"""Consolidated skinning analysis for remix-comp-proxy configuration.

Combines vertex declaration scanning, bone palette detection from
SetVertexShaderConstantF patterns, and FFP vertex blending state
detection into a single report with suggested proxy INI values.

Analyzes:
  - Skinned vertex declarations (BLENDWEIGHT + BLENDINDICES elements)
  - Bone palette candidates from VS constant upload patterns
  - FFP indexed vertex blending render states (D3DRS_VERTEXBLEND,
    D3DRS_INDEXEDVERTEXBLENDENABLE)
  - SetTransform(WORLDMATRIX(n)) calls for FFP bone upload
  - Expanded vertex size (SKIN_VTX_SIZE) validation

Usage:
    python find_skinning.py <game.exe>
"""
import argparse
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header, va_to_offset,
    scan_vtable_calls, scan_vtable_mov, method_immediates,
    D3DRS, decode_transform_type,
)


# ── Vertex declaration types ────────────────────────────────────────

D3DDECLTYPE = {
    0: "FLOAT1", 1: "FLOAT2", 2: "FLOAT3", 3: "FLOAT4",
    4: "D3DCOLOR", 5: "UBYTE4", 6: "SHORT2", 7: "SHORT4",
    8: "UBYTE4N", 9: "SHORT2N", 10: "SHORT4N", 11: "USHORT2N",
    12: "USHORT4N", 13: "UDEC3", 14: "DEC3N", 15: "FLOAT16_2",
    16: "FLOAT16_4", 17: "UNUSED",
}

D3DDECLUSAGE = {
    0: "POSITION", 1: "BLENDWEIGHT", 2: "BLENDINDICES", 3: "NORMAL",
    4: "PSIZE", 5: "TEXCOORD", 6: "TANGENT", 7: "BINORMAL",
    8: "TESSFACTOR", 9: "POSITIONT", 10: "COLOR", 11: "FOG",
    12: "DEPTH", 13: "SAMPLE",
}

TYPE_SIZES = {
    0: 4, 1: 8, 2: 12, 3: 16, 4: 4, 5: 4, 6: 4, 7: 8,
    8: 4, 9: 4, 10: 8, 11: 4, 12: 8, 15: 4, 16: 8,
}

# Number of blend weights by BLENDWEIGHT type
BLEND_WEIGHT_COUNTS = {
    0: 1,   # FLOAT1
    1: 2,   # FLOAT2
    2: 3,   # FLOAT3
    3: 3,   # FLOAT4 (4th weight is derived: 1 - sum)
    8: 3,   # UBYTE4N (4th weight is derived)
}

# FVF blend weight bits (D3DFVF position type field, bits 1-3)
FVF_BLEND_COUNTS = {
    0x002: 0, 0x004: 0,  # XYZ, XYZRHW — no blending
    0x006: 1, 0x008: 2, 0x00A: 3, 0x00C: 4, 0x00E: 5,
}

MAX_ELEMENTS = 64


# ── Vertex declaration parsing ──────────────────────────────────────

def parse_decl(data, sections, image_base, va):
    """Parse a D3DVERTEXELEMENT9 array at VA. Returns element list or None."""
    off = va_to_offset(sections, image_base, va)
    if off is None:
        return None

    elements = []
    for i in range(MAX_ELEMENTS + 1):
        elem = data[off:off + 8]
        if len(elem) < 8:
            break
        stream, offset, typ, method, usage, usage_idx = struct.unpack_from("<HHBBBB", elem)
        if stream == 0xFF or stream == 0xFFFF:
            break
        if i == MAX_ELEMENTS:
            return None  # no D3DDECL_END — false positive
        elements.append({
            'stream': stream, 'offset': offset, 'type': typ,
            'method': method, 'usage': usage, 'usage_idx': usage_idx,
        })
        off += 8

    return elements if elements else None


def is_skinned(elements):
    """Check if declaration contains both BLENDWEIGHT and BLENDINDICES."""
    usages = {e['usage'] for e in elements}
    return 1 in usages and 2 in usages


def analyze_decl(elements):
    """Extract skinning-relevant info from a parsed declaration."""
    info = {
        'stride': 0,
        'bw_type': None, 'bw_type_name': None, 'bw_offset': None, 'num_weights': 0,
        'bi_type': None, 'bi_type_name': None, 'bi_offset': None,
        'pos_offset': None, 'normal_offset': None, 'normal_type': None,
        'texcoord_offset': None, 'texcoord_type': None,
        'has_tangent': False, 'has_color': False,
        'elements': elements,
    }

    for e in elements:
        sz = TYPE_SIZES.get(e['type'], 0)
        end = e['offset'] + sz
        if end > info['stride']:
            info['stride'] = end

        if e['usage'] == 0:  # POSITION
            info['pos_offset'] = e['offset']
        elif e['usage'] == 1:  # BLENDWEIGHT
            info['bw_type'] = e['type']
            info['bw_type_name'] = D3DDECLTYPE.get(e['type'], f"TYPE_{e['type']}")
            info['bw_offset'] = e['offset']
            info['num_weights'] = BLEND_WEIGHT_COUNTS.get(e['type'], 0)
        elif e['usage'] == 2:  # BLENDINDICES
            info['bi_type'] = e['type']
            info['bi_type_name'] = D3DDECLTYPE.get(e['type'], f"TYPE_{e['type']}")
            info['bi_offset'] = e['offset']
        elif e['usage'] == 3:  # NORMAL
            info['normal_offset'] = e['offset']
            info['normal_type'] = D3DDECLTYPE.get(e['type'], f"TYPE_{e['type']}")
        elif e['usage'] == 5:  # TEXCOORD
            if info['texcoord_offset'] is None:
                info['texcoord_offset'] = e['offset']
                info['texcoord_type'] = D3DDECLTYPE.get(e['type'], f"TYPE_{e['type']}")
        elif e['usage'] == 6:  # TANGENT
            info['has_tangent'] = True
        elif e['usage'] == 10:  # COLOR
            info['has_color'] = True

    return info


def scan_for_skinned_decls(data, sections, image_base, text_data, text_va):
    """Find all CreateVertexDeclaration call sites, return skinned ones."""
    call_vas = [va for va, _ in scan_vtable_calls(text_data, text_va, 0x158)]
    call_vas += [va for va, _ in scan_vtable_mov(text_data, text_va, 0x158)]

    skinned = []
    all_addrs = set()

    for call_va in sorted(call_vas):
        pushed = method_immediates(text_data, text_va, call_va, "CreateVertexDeclaration")
        addr = pushed["pVertexElements"]
        if addr is None or addr in all_addrs:
            continue
        all_addrs.add(addr)

        off_check = va_to_offset(sections, image_base, addr)
        if off_check is None:
            continue
        elem = data[off_check:off_check + 8]
        if len(elem) < 8:
            continue
        stream, offset, typ, method, usage, usage_idx = \
            struct.unpack_from("<HHBBBB", elem)
        if not (stream <= 4 and typ <= 17 and usage <= 13):
            continue

        elements = parse_decl(data, sections, image_base, addr)
        if elements and is_skinned(elements):
            skinned.append((addr, analyze_decl(elements)))

    return skinned


# ── FVF scanning ────────────────────────────────────────────────────

def scan_fvf_skinning(text_data, text_va):
    """Find SetFVF calls with skinning bits set."""
    sites = scan_vtable_calls(text_data, text_va, 0x164)  # SetFVF
    sites += scan_vtable_mov(text_data, text_va, 0x164)

    skinned_fvfs = []
    for va, _ in sites:
        val = method_immediates(text_data, text_va, va, "SetFVF")["FVF"]
        # FVF codes are bitfields; anything > 0xFFFFF is likely an address
        if val is None or val > 0xFFFFF:
            continue
        pos_type = val & 0x00E
        if pos_type in (0x006, 0x008, 0x00A, 0x00C, 0x00E):
            blend_count = FVF_BLEND_COUNTS.get(pos_type, 0)
            if blend_count > 0:
                indexed = bool(val & 0x1000)  # D3DFVF_LASTBETA_UBYTE4
                skinned_fvfs.append((va, val, blend_count, indexed))
    return skinned_fvfs


# ── Bone palette detection ──────────────────────────────────────────

def find_bone_palettes(text_data, text_va):
    """Detect bone palette uploads from SetVertexShaderConstantF patterns.

    Heuristic: start_reg >= 20, count >= 9, count divisible by 3 or 4.
    The proxy applies its own thresholds, the [Skinning] keys of remix-comp-proxy.ini.
    """
    sites = scan_vtable_calls(text_data, text_va, 0x178)
    sites += [(va, 'indirect') for va, _ in scan_vtable_mov(text_data, text_va, 0x178)]

    candidates = []
    for va, _ in sites:
        pushed = method_immediates(text_data, text_va, va, "SetVertexShaderConstantF")
        start_reg, count = pushed["StartRegister"], pushed["Vector4fCount"]
        if start_reg is None or count is None:
            continue
        if start_reg < 20 or count < 9 or start_reg > 255 or count > 768:
            continue

        # Check divisibility by common regs-per-bone values
        for rpb in (3, 4):
            if count % rpb == 0:
                num_bones = count // rpb
                candidates.append({
                    'va': va,
                    'start_reg': start_reg,
                    'count': count,
                    'regs_per_bone': rpb,
                    'num_bones': num_bones,
                })

    # Deduplicate by (start_reg, count, regs_per_bone)
    seen = set()
    unique = []
    for c in candidates:
        key = (c['start_reg'], c['count'], c['regs_per_bone'])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return unique


# ── FFP blend state detection ───────────────────────────────────────

def find_vertex_blend_states(text_data, text_va):
    """Find SetRenderState calls for D3DRS_VERTEXBLEND (151) and
    D3DRS_INDEXEDVERTEXBLENDENABLE (167)."""
    sites = scan_vtable_calls(text_data, text_va, 0xE4)  # SetRenderState
    sites += [(va, 'indirect') for va, _ in scan_vtable_mov(text_data, text_va, 0xE4)]

    vb_states = defaultdict(list)
    for va, _ in sites:
        pushed = method_immediates(text_data, text_va, va, "SetRenderState")
        state_id, value = pushed["State"], pushed["Value"]
        if state_id in (151, 167) and value is not None:
            vb_states[state_id].append((va, value))

    return vb_states


# ── SetTransform(WORLDMATRIX(n)) detection ──────────────────────────

def find_worldmatrix_transforms(text_data, text_va):
    """Find SetTransform calls with WORLDMATRIX(n) arguments (>= 256).

    WORLDMATRIX(n) = 256 + n. Realistic bone indices are 0..255, so
    valid transform type values are 256..511.
    """
    sites = scan_vtable_calls(text_data, text_va, 0xB0)  # SetTransform
    sites += [(va, 'indirect') for va, _ in scan_vtable_mov(text_data, text_va, 0xB0)]

    wm_calls = []
    for va, _ in sites:
        state = method_immediates(text_data, text_va, va, "SetTransform")["State"]
        if state is not None and 256 <= state <= 511:
            wm_calls.append((va, state))
    return wm_calls


# ── Expanded vertex size calculation ────────────────────────────────

# Proxy expanded layout: FLOAT3 pos(12) + FLOAT3 weights(12) + UBYTE4 idx(4) +
#                        FLOAT3 normal(12) + FLOAT2 texcoord(8) = 48
PROXY_SKIN_VTX_SIZE = 48

def compute_min_expanded_stride(decl_info):
    """Compute the minimum expanded stride needed for a skinned declaration.

    The proxy always expands to a fixed 48-byte layout. This checks if the
    source declaration has elements that would be lost in expansion.
    """
    covered = {'POSITION', 'BLENDWEIGHT', 'BLENDINDICES', 'NORMAL', 'TEXCOORD'}
    extra = []
    for e in decl_info['elements']:
        usage_name = D3DDECLUSAGE.get(e['usage'], f"USAGE_{e['usage']}")
        if usage_name not in covered:
            sz = TYPE_SIZES.get(e['type'], 0)
            extra.append((usage_name, e['usage_idx'], sz))
    return PROXY_SKIN_VTX_SIZE, extra


# ── Main ────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--all", action="store_true",
                   help="Show full element lists for each declaration")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    # ── 1. Skinned vertex declarations ──────────────────────────────

    print(f"\n{'='*60}")
    print("  Skinned Vertex Declarations")
    print(f"{'='*60}")

    skinned_decls = scan_for_skinned_decls(data, sections, image_base, text_data, text_va)
    fvf_skinned = scan_fvf_skinning(text_data, text_va)

    if skinned_decls:
        print(f"\n  {len(skinned_decls)} skinned declaration(s) found:\n")
        bw_types_seen = set()
        max_weights = 0
        for addr, info in skinned_decls:
            print(f"  0x{addr:08X}: stride={info['stride']}")
            print(f"    BLENDWEIGHT:  {info['bw_type_name']} @{info['bw_offset']} "
                  f"({info['num_weights']} weights)")
            print(f"    BLENDINDICES: {info['bi_type_name']} @{info['bi_offset']}")
            if info['pos_offset'] is not None:
                print(f"    POSITION:     @{info['pos_offset']}")
            if info['normal_offset'] is not None:
                print(f"    NORMAL:       {info['normal_type']} @{info['normal_offset']}")
            if info['texcoord_offset'] is not None:
                print(f"    TEXCOORD:     {info['texcoord_type']} @{info['texcoord_offset']}")
            if info['has_tangent']:
                print(f"    TANGENT:      present")
            if info['has_color']:
                print(f"    COLOR:        present")

            _, extra = compute_min_expanded_stride(info)
            if extra:
                lost = ", ".join(f"{n}[{i}]({s}B)" for n, i, s in extra)
                print(f"    WARNING: elements lost in proxy expansion: {lost}")

            if args.all:
                print(f"    Full elements:")
                for e in info['elements']:
                    tn = D3DDECLTYPE.get(e['type'], f"TYPE_{e['type']}")
                    un = D3DDECLUSAGE.get(e['usage'], f"USAGE_{e['usage']}")
                    print(f"      Stream={e['stream']} Off={e['offset']:3d} "
                          f"{tn:12s} {un}[{e['usage_idx']}]")

            bw_types_seen.add(info['bw_type_name'])
            if info['num_weights'] > max_weights:
                max_weights = info['num_weights']
            print()
    else:
        print("\n  No skinned vertex declarations found.")

    if fvf_skinned:
        print(f"  {len(fvf_skinned)} FVF skinning pattern(s) found:\n")
        for va, fvf, blend_count, indexed in fvf_skinned:
            idx_str = " (indexed)" if indexed else ""
            print(f"    0x{va:08X}: FVF=0x{fvf:08X}, {blend_count} blend weight(s){idx_str}")
        print()
    elif not skinned_decls:
        print("  No FVF skinning patterns found.\n")

    # ── 2. Bone palette candidates ──────────────────────────────────

    print(f"{'='*60}")
    print("  Bone Palette Candidates (SetVertexShaderConstantF)")
    print(f"{'='*60}")

    palettes = find_bone_palettes(text_data, text_va)

    if palettes:
        print(f"\n  {len(palettes)} candidate(s) found:\n")

        # Group by (start_reg, regs_per_bone) for cleaner output
        by_config = defaultdict(list)
        for c in palettes:
            by_config[(c['start_reg'], c['regs_per_bone'])].append(c)

        best_start = None
        best_rpb = None
        best_count = 0

        for (sreg, rpb), group in sorted(by_config.items()):
            bone_counts = sorted(set(c['num_bones'] for c in group))
            sites = [c['va'] for c in group]
            print(f"  start_reg={sreg}, regs_per_bone={rpb}: "
                  f"{len(sites)} site(s), bone counts: {bone_counts}")
            for c in group:
                print(f"    0x{c['va']:08X}: count={c['count']} -> "
                      f"{c['num_bones']} bones x {rpb} regs")

            total = len(sites)
            if total > best_count:
                best_count = total
                best_start = sreg
                best_rpb = rpb
            print()
    else:
        print("\n  No bone palette patterns detected.\n")
        best_start = None
        best_rpb = None

    # ── 3. FFP vertex blending ──────────────────────────────────────

    print(f"{'='*60}")
    print("  FFP Vertex Blending (Render States)")
    print(f"{'='*60}")

    vb_states = find_vertex_blend_states(text_data, text_va)

    D3DVERTEXBLENDFLAGS = {0: "DISABLE", 1: "1WEIGHTS", 2: "2WEIGHTS", 3: "3WEIGHTS", 255: "TWEENING"}

    if 151 in vb_states:
        entries = vb_states[151]
        vals = defaultdict(int)
        for _, v in entries:
            vals[v] += 1
        val_strs = []
        for v, cnt in sorted(vals.items()):
            name = D3DVERTEXBLENDFLAGS.get(v, f"0x{v:X}")
            suffix = f" x{cnt}" if cnt > 1 else ""
            val_strs.append(f"{name}{suffix}")
        print(f"\n  D3DRS_VERTEXBLEND: {len(entries)} site(s), values: {', '.join(val_strs)}")
    else:
        print(f"\n  D3DRS_VERTEXBLEND: not found")

    if 167 in vb_states:
        entries = vb_states[167]
        vals = defaultdict(int)
        for _, v in entries:
            vals[v] += 1
        val_strs = []
        for v, cnt in sorted(vals.items()):
            name = "TRUE" if v else "FALSE"
            suffix = f" x{cnt}" if cnt > 1 else ""
            val_strs.append(f"{name}{suffix}")
        print(f"  D3DRS_INDEXEDVERTEXBLENDENABLE: {len(entries)} site(s), values: {', '.join(val_strs)}")
    else:
        print(f"  D3DRS_INDEXEDVERTEXBLENDENABLE: not found")

    # WORLDMATRIX transforms
    wm_calls = find_worldmatrix_transforms(text_data, text_va)
    if wm_calls:
        indices = sorted(set(v - 256 for _, v in wm_calls))
        max_idx = max(indices)
        print(f"  SetTransform(WORLDMATRIX(n)): {len(wm_calls)} call(s), "
              f"indices 0..{max_idx} ({max_idx + 1} bones)")
    else:
        print(f"  SetTransform(WORLDMATRIX(n)): not found")

    has_ffp_blend = bool(vb_states) or bool(wm_calls)
    has_fvf_blend = bool(fvf_skinned)
    if not has_ffp_blend and not skinned_decls and not has_fvf_blend and not palettes:
        blend_method = "none detected"
    elif palettes and not has_ffp_blend and not has_fvf_blend:
        blend_method = "VS-based skinning (bone palette via VS constants)"
    elif has_ffp_blend and not palettes:
        blend_method = "FFP indexed vertex blending (SetTransform WORLDMATRIX)"
    elif has_ffp_blend and palettes:
        blend_method = "hybrid (both VS constants and FFP WORLDMATRIX)"
    elif has_fvf_blend:
        blend_method = "FFP vertex blending via FVF (blend states may be set dynamically)"
    elif skinned_decls and palettes:
        blend_method = "VS-based skinning (bone palette via VS constants)"
    else:
        blend_method = "skinned declarations found, method unclear"

    print(f"\n  -> Skinning method: {blend_method}")

    # ── 4. Suggested proxy INI ──────────────────────────────────────

    has_skinning = bool(skinned_decls) or bool(fvf_skinned)
    print(f"\n{'='*60}")
    print("  Suggested Proxy Configuration")
    print(f"{'='*60}\n")

    if has_skinning:
        print("  [Skinning]")
        print("  Enabled=1")
        if best_start is not None:
            print(f"  BoneThreshold={best_start}")
        if best_rpb is not None:
            print(f"  RegsPerBone={best_rpb}")
        print(f"  ; SKIN_VTX_SIZE={PROXY_SKIN_VTX_SIZE} (fixed proxy layout)")
        if skinned_decls:
            bw_summary = ", ".join(sorted(
                {info['bw_type_name'] for _, info in skinned_decls}))
            print(f"  ; blend weight formats: {bw_summary}")
            strides = sorted(set(info['stride'] for _, info in skinned_decls))
            print(f"  ; source vertex strides: {strides}")
    else:
        print("  [Skinning]")
        print("  Enabled=0")
        print("  ; No skinned meshes detected in this binary.")

    print(f"\n{'='*60}")
    print("--- DONE ---")


if __name__ == "__main__":
    main()
