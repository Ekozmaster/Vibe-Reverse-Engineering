"""Identify likely View, Projection, and World matrix VS constant registers.

Cross-references multiple signals to pinpoint which VS constant registers
hold transformation matrices:

1. SetVertexShaderConstantF sites with count=4 (matrix-sized uploads)
2. Calling-function grouping (same function uploading multiple matrices)
3. Frequency analysis (per-frame vs per-object upload patterns)
4. D3DX SetMatrix/SetMatrixArray vtable calls
5. Embedded shader CTAB parsing (extracts named constants like "WorldViewProj")
6. SetTransform cross-reference (FFP transform usage reveals matrix roles)

Outputs a suggested remix-comp-proxy.ini register layout.

Usage:
    python find_matrix_registers.py <game.exe>
"""
import argparse
import struct
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov, method_immediates,
    va_to_offset, validate_shader_token, find_shader_end,
)

# Vtable offsets
SVSCF = 0x178    # SetVertexShaderConstantF
SET_TRANSFORM = 0xB0
CREATE_VS = 0x16C

# Common matrix name patterns in CTAB
MATRIX_NAME_HINTS = {
    'view': 'View',
    'proj': 'Projection',
    'world': 'World',
    'wvp': 'WorldViewProj',
    'worldviewproj': 'WorldViewProj',
    'viewproj': 'ViewProj',
    'worldview': 'WorldView',
    'mvp': 'WorldViewProj',
    'modelview': 'WorldView',
    'model': 'World',
    'bone': 'Bones',
    'skin': 'Bones',
}


def classify_matrix_name(name):
    """Classify a CTAB constant name into a matrix role."""
    lower = name.lower().replace('_', '').replace(' ', '')
    # Order matters: check compound names first
    if 'worldviewproj' in lower or lower in ('wvp', 'mvp'):
        return 'WorldViewProj'
    if 'viewproj' in lower or lower == 'vp':
        return 'ViewProj'
    if 'worldview' in lower or lower == 'mv' or 'modelview' in lower:
        return 'WorldView'
    if 'bone' in lower or 'skin' in lower or 'palette' in lower:
        return 'Bones'
    if 'proj' in lower:
        return 'Projection'
    if 'view' in lower or 'camera' in lower:
        return 'View'
    if 'world' in lower or 'model' in lower or 'object' in lower:
        return 'World'
    if 'texmat' in lower or 'textransform' in lower or 'texturematrix' in lower:
        return 'TexTransform'
    return None


def parse_ctab(data, offset, bytecode_len):
    """Parse D3DX shader CTAB from bytecode. Returns list of (name, register, count, rows, columns)."""
    constants = []
    end = offset + bytecode_len
    pos = offset + 4  # skip version token

    while pos < end - 4:
        token = struct.unpack_from('<I', data, pos)[0]
        # End token
        if token == 0x0000FFFF:
            break
        # Comment token: opcode 0xFFFE, length in upper 16 bits
        opcode = token & 0xFFFF
        if opcode == 0xFFFE:
            dword_count = (token >> 16) & 0xFFFF
            comment_start = pos + 4
            comment_end = comment_start + dword_count * 4
            if comment_end <= end and dword_count >= 2:
                # Check for CTAB signature
                if data[comment_start:comment_start + 4] == b'CTAB':
                    try:
                        constants = _decode_ctab_block(data, comment_start, comment_end)
                    except Exception:
                        pass
            pos = comment_end
        else:
            pos += 4
    return constants


def _decode_ctab_block(data, start, end):
    """Decode a CTAB comment block."""
    constants = []
    # CTAB header: 'CTAB' + size + creator + version + constants_count + constant_info_offset + ...
    if end - start < 28:
        return constants

    size = struct.unpack_from('<I', data, start + 4)[0]
    # Creator string offset (from start of CTAB)
    creator_off = struct.unpack_from('<I', data, start + 8)[0]
    # Version
    version = struct.unpack_from('<I', data, start + 12)[0]
    # Constants count and offset
    num_constants = struct.unpack_from('<I', data, start + 16)[0]
    const_info_off = struct.unpack_from('<I', data, start + 20)[0]

    if num_constants > 256 or num_constants == 0:
        return constants

    # Each constant info: name_offset(4) + register_set(2) + register_index(2) +
    #                     register_count(2) + reserved(2) + type_info_offset(4) +
    #                     default_value_offset(4) + default_value_size(4)
    info_base = start + const_info_off
    for i in range(num_constants):
        entry = info_base + i * 20
        if entry + 20 > end:
            break

        name_off = struct.unpack_from('<I', data, entry)[0]
        register_set = struct.unpack_from('<H', data, entry + 4)[0]
        register_idx = struct.unpack_from('<H', data, entry + 6)[0]
        register_count = struct.unpack_from('<H', data, entry + 8)[0]

        # Read name (null-terminated string)
        name_addr = start + name_off
        if name_addr < end:
            name_end = data.find(b'\x00', name_addr, min(name_addr + 128, end))
            if name_end == -1:
                name_end = min(name_addr + 64, end)
            name = data[name_addr:name_end].decode('ascii', errors='replace')
        else:
            name = f"const_{i}"

        # Type info for rows/columns
        type_off = struct.unpack_from('<I', data, entry + 12)[0]
        rows = cols = 0
        type_addr = start + type_off
        if type_addr + 12 <= end:
            # D3DXSHADER_TYPEINFO: class(2) + type(2) + rows(2) + columns(2) + elements(2) + ...
            rows = struct.unpack_from('<H', data, type_addr + 4)[0]
            cols = struct.unpack_from('<H', data, type_addr + 6)[0]

        # register_set: 0=bool, 1=int, 2=float, 3=sampler
        if register_set == 2:  # float constants
            constants.append((name, register_idx, register_count, rows, cols))

    return constants


def find_containing_function(data, sections, image_base, va, search_back=256):
    """Heuristic: find likely function start by scanning backwards for common prologues."""
    file_off = va_to_offset(sections, image_base, va)
    if file_off is None:
        return None
    start = max(0, file_off - search_back)
    region = data[start:file_off]

    # Look for push ebp; mov ebp, esp (55 8B EC) or sub esp (83 EC)
    best = None
    for i in range(len(region) - 2):
        if region[i] == 0x55 and region[i + 1] == 0x8B and region[i + 2] == 0xEC:
            candidate = image_base + (start + i - sections[0]['raw'] + sections[0]['va'])
            # Prefer the one closest to our VA
            if best is None or candidate > best:
                best = candidate
        # Also check for naked functions with just sub esp
        if region[i] == 0x83 and region[i + 1] == 0xEC and i > 0 and region[i - 1] in (0xCC, 0x90, 0xC3):
            candidate = image_base + (start + i - sections[0]['raw'] + sections[0]['va'])
            if best is None or candidate > best:
                best = candidate

    return best


def _phase1_svscf_uploads(data, image_base, sections, text_data, text_va):
    """Phase 1: Find SetVertexShaderConstantF sites with count=4 (matrix uploads)."""
    print("\n=== Phase 1: SetVertexShaderConstantF matrix uploads ===")

    direct = scan_vtable_calls(text_data, text_va, SVSCF)
    indirect = scan_vtable_mov(text_data, text_va, SVSCF)
    all_svscf = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]
    print(f"  Total SVSCF call sites: {len(all_svscf)}")

    reg_uploads = defaultdict(list)  # (start, count) -> [call_va, ...]
    unknown_sites = 0

    for va, reg in all_svscf:
        pushed = method_immediates(text_data, text_va, va, "SetVertexShaderConstantF")
        start_reg, count = pushed["StartRegister"], pushed["Vector4fCount"]
        if start_reg is None or count is None or start_reg > 255 or count > 256:
            unknown_sites += 1
        else:
            reg_uploads[(start_reg, count)].append(va)

    # Focus on count=4 (matrix) uploads
    matrix_regs = {}  # start_reg -> [call_va, ...]
    other_regs = {}

    for (start, count), sites in sorted(reg_uploads.items()):
        if count == 4:
            matrix_regs[start] = sites
        else:
            other_regs[(start, count)] = sites

    if matrix_regs:
        print(f"\n  Matrix-sized uploads (count=4): {len(matrix_regs)} register ranges\n")
        print(f"  {'Registers':<15s} {'Sites':>5s}  {'Functions':>9s}  Notes")
        print(f"  {'-'*15} {'-'*5}  {'-'*9}  {'-'*30}")

        for start in sorted(matrix_regs):
            sites = matrix_regs[start]
            # Group by containing function
            funcs = set()
            for va in sites:
                fn = find_containing_function(data, sections, image_base, va)
                if fn:
                    funcs.add(fn)
            fn_count = len(funcs) if funcs else '?'

            # Heuristics
            notes = []
            if len(sites) <= 5 and (isinstance(fn_count, int) and fn_count <= 2):
                notes.append("per-frame (few sites, few functions)")
            elif len(sites) > 20 or (isinstance(fn_count, int) and fn_count > 5):
                notes.append("per-object (many sites/functions)")
            if start >= 20 and len(sites) > 30:
                notes.append("possible bones")

            note_str = "; ".join(notes) if notes else ""
            print(f"  c{start}-c{start+3:<10d} {len(sites):>5d}  {str(fn_count):>9s}  {note_str}")
    else:
        print(f"\n  No count=4 uploads decoded (arguments likely register-loaded)")

    # Other notable uploads
    bone_candidates = [(s, c, sites) for (s, c), sites in other_regs.items()
                       if c > 8 and s >= 16]
    if bone_candidates:
        print(f"\n  Potential bone/array uploads (count > 8):")
        for start, count, sites in sorted(bone_candidates):
            print(f"    c{start}-c{start+count-1} (count={count}): {len(sites)} sites")

    if unknown_sites > 0:
        print(f"\n  ({unknown_sites} sites with register-loaded arguments -- not decoded)")

    return matrix_regs


def _phase2_function_grouping(data, sections, image_base, matrix_regs):
    """Phase 2: Group matrix uploads by containing function."""
    print(f"\n\n=== Phase 2: Matrix upload function analysis ===")

    # Group all matrix uploads by containing function
    func_matrices = defaultdict(list)  # func_va -> [(start_reg, call_va), ...]
    for start, sites in matrix_regs.items():
        for va in sites:
            fn = find_containing_function(data, sections, image_base, va)
            if fn:
                func_matrices[fn].append((start, va))

    # Find functions that upload multiple distinct matrices
    multi_matrix_funcs = {fn: regs for fn, regs in func_matrices.items()
                          if len(set(r for r, _ in regs)) >= 2}

    if multi_matrix_funcs:
        print(f"\n  Functions uploading 2+ distinct matrix registers:")
        for fn_va in sorted(multi_matrix_funcs):
            regs = multi_matrix_funcs[fn_va]
            unique_starts = sorted(set(r for r, _ in regs))
            reg_strs = [f"c{s}-c{s+3}" for s in unique_starts]
            print(f"\n    0x{fn_va:08X}: uploads {len(unique_starts)} matrices")
            print(f"      Registers: {', '.join(reg_strs)}")

            if len(unique_starts) >= 2:
                # Try to identify roles by position and frequency
                assessment = []
                for s in unique_starts:
                    total_sites = len(matrix_regs.get(s, []))
                    total_funcs = len(set(
                        find_containing_function(data, sections, image_base, va)
                        for va in matrix_regs.get(s, [])
                        if find_containing_function(data, sections, image_base, va)
                    ))
                    if total_sites <= 5 and total_funcs <= 2:
                        assessment.append(f"c{s}-c{s+3}: low-frequency (View or Proj candidate)")
                    elif total_sites > 15:
                        assessment.append(f"c{s}-c{s+3}: high-frequency (World candidate)")
                    else:
                        assessment.append(f"c{s}-c{s+3}: medium-frequency")

                if assessment:
                    print(f"      Frequency analysis:")
                    for a in assessment:
                        print(f"        {a}")
    else:
        print(f"\n  No functions found uploading 2+ distinct matrices.")
        print(f"  Game may use a single upload function called with different arguments,")
        print(f"  or matrices are uploaded via D3DX constant tables.")


def _phase3_ctab_extraction(data, sections, image_base, text_data, text_va):
    """Phase 3: Extract matrix constants from embedded shader CTABs."""
    print(f"\n\n=== Phase 3: Shader CTAB constant names ===")

    # Find CreateVertexShader sites and extract bytecode
    vs_direct = scan_vtable_calls(text_data, text_va, CREATE_VS)
    vs_indirect = scan_vtable_mov(text_data, text_va, CREATE_VS)
    all_vs = [(va, r) for va, r in vs_direct] + [(va, 'indirect') for va, _ in vs_indirect]

    ctab_matrices = []  # (name, register, count, rows, cols, shader_va)
    seen_shaders = set()

    for va, reg in all_vs:
        target_va = method_immediates(text_data, text_va, va, "CreateVertexShader")["pFunction"]
        if target_va is None or target_va in seen_shaders:
            continue
        file_off = va_to_offset(sections, image_base, target_va)
        if file_off is None:
            continue
        info = validate_shader_token(data, file_off)
        if info is None:
            continue
        seen_shaders.add(target_va)
        byte_len = find_shader_end(data, file_off)
        if byte_len is None:
            continue

        constants = parse_ctab(data, file_off, byte_len)
        for name, reg_idx, reg_count, rows, cols in constants:
            if rows >= 3 and cols >= 3:  # matrix (3x3 or 4x4)
                role = classify_matrix_name(name)
                ctab_matrices.append((name, reg_idx, reg_count, rows, cols, target_va, role))

    if ctab_matrices:
        print(f"\n  Found {len(ctab_matrices)} matrix constants in shader CTABs:\n")
        print(f"  {'Name':<30s} {'Register':<12s} {'Size':<8s} {'Role':<20s} Shader")
        print(f"  {'-'*30} {'-'*12} {'-'*8} {'-'*20} {'-'*10}")

        for name, reg_idx, reg_count, rows, cols, shader_va, role in sorted(ctab_matrices, key=lambda x: x[1]):
            role_str = role or "(unknown)"
            print(f"  {name:<30s} c{reg_idx}-c{reg_idx+reg_count-1:<6d} {rows}x{cols:<5d} {role_str:<20s} 0x{shader_va:08X}")

        # Group by role
        role_regs = defaultdict(set)
        for name, reg_idx, reg_count, rows, cols, shader_va, role in ctab_matrices:
            if role:
                role_regs[role].add(reg_idx)

        if role_regs:
            print(f"\n  CTAB role summary:")
            for role in ['View', 'Projection', 'World', 'WorldViewProj', 'ViewProj',
                         'WorldView', 'Bones', 'TexTransform']:
                if role in role_regs:
                    regs = sorted(role_regs[role])
                    reg_strs = [f"c{r}" for r in regs]
                    print(f"    {role:20s} -> {', '.join(reg_strs)}")
    else:
        print(f"\n  No CTAB data found in embedded shaders.")
        print(f"  Game may load shaders from files or compile at runtime.")
        print(f"  Use dx9tracer --shader-map for runtime CTAB extraction.")

    return ctab_matrices


def _phase4_set_transform(text_data, text_va):
    """Phase 4: Cross-reference SetTransform calls."""
    print(f"\n\n=== Phase 4: SetTransform cross-reference ===")

    st_direct = scan_vtable_calls(text_data, text_va, SET_TRANSFORM)
    st_indirect = scan_vtable_mov(text_data, text_va, SET_TRANSFORM)
    st_total = len(st_direct) + len(st_indirect)

    if st_total > 0:
        print(f"\n  SetTransform: {st_total} call sites")
        print(f"  Game uses FFP transforms -- the proxy may be able to read")
        print(f"  View/Projection from SetTransform and only need the World")
        print(f"  register mapping from VS constants.")
    else:
        print(f"\n  SetTransform: 0 call sites")
        print(f"  Game is fully shader-based -- all matrices come from VS constants.")


def _phase5_suggested_layout(matrix_regs, ctab_matrices):
    """Phase 5: Suggest remix-comp-proxy.ini register layout."""
    print(f"\n\n{'='*60}")
    print(f"=== Suggested remix-comp-proxy.ini Register Layout ===")
    print(f"{'='*60}")

    # Priority: CTAB names > frequency heuristics > position heuristics
    view_reg = None
    proj_reg = None
    world_reg = None
    has_wvp = False

    # Try CTAB first
    ctab_roles = {}
    for name, reg_idx, reg_count, rows, cols, shader_va, role in ctab_matrices:
        if role and role not in ctab_roles:
            ctab_roles[role] = reg_idx

    if 'View' in ctab_roles:
        view_reg = ctab_roles['View']
    if 'Projection' in ctab_roles:
        proj_reg = ctab_roles['Projection']
    if 'World' in ctab_roles:
        world_reg = ctab_roles['World']
    if 'WorldViewProj' in ctab_roles:
        has_wvp = True

    # Fall back to frequency heuristics
    if matrix_regs and (view_reg is None or proj_reg is None or world_reg is None):
        sorted_by_freq = sorted(matrix_regs.items(), key=lambda x: len(x[1]))
        # Lowest frequency = View or Proj, highest = World
        unassigned = sorted([s for s in matrix_regs if s not in (view_reg, proj_reg, world_reg)])

        if world_reg is None and sorted_by_freq:
            # Highest frequency unassigned
            candidates = [(s, sites) for s, sites in sorted_by_freq
                          if s not in (view_reg, proj_reg)]
            if candidates:
                world_reg = candidates[-1][0]

        if view_reg is None and proj_reg is None:
            # Two lowest-frequency unassigned
            candidates = [(s, sites) for s, sites in sorted_by_freq
                          if s != world_reg]
            if len(candidates) >= 2:
                view_reg = candidates[0][0]
                proj_reg = candidates[1][0]
            elif len(candidates) == 1:
                view_reg = candidates[0][0]

    if has_wvp and view_reg is None and proj_reg is None and world_reg is None:
        wvp_reg = ctab_roles.get('WorldViewProj')
        print(f"\n  WARNING: Game uses a concatenated WorldViewProj matrix at c{wvp_reg}.")
        print(f"  Remix REQUIRES separate World, View, and Projection matrices.")
        print(f"  The proxy must intercept the WVP computation and extract the")
        print(f"  individual matrices before they are concatenated.")
        print(f"  Look for the function that multiplies W*V*P and uploads to c{wvp_reg}.")
        vp_reg = ctab_roles.get('ViewProj')
        if vp_reg:
            print(f"\n  Also found ViewProj at c{vp_reg} -- same issue, needs separation.")
    elif view_reg is not None or proj_reg is not None or world_reg is not None:
        print(f"\n  [FFP.Registers]")
        if view_reg is not None:
            source = "CTAB" if 'View' in ctab_roles else "frequency"
            print(f"  ViewStart={view_reg}          ; c{view_reg}-c{view_reg+3} ({source})")
            print(f"  ViewEnd={view_reg + 4}")
        else:
            print(f"  ViewStart=???         ; could not determine -- check with livetools trace")
            print(f"  ViewEnd=???")

        if proj_reg is not None:
            source = "CTAB" if 'Projection' in ctab_roles else "frequency"
            print(f"  ProjStart={proj_reg}          ; c{proj_reg}-c{proj_reg+3} ({source})")
            print(f"  ProjEnd={proj_reg + 4}")
        else:
            print(f"  ProjStart=???         ; could not determine -- check with livetools trace")
            print(f"  ProjEnd=???")

        if world_reg is not None:
            source = "CTAB" if 'World' in ctab_roles else "frequency"
            print(f"  WorldStart={world_reg}        ; c{world_reg}-c{world_reg+3} ({source})")
            print(f"  WorldEnd={world_reg + 4}")
        else:
            print(f"  WorldStart=???        ; could not determine -- check with livetools trace")
            print(f"  WorldEnd=???")

        print(f"\n  IMPORTANT: Verify with livetools trace or dx9tracer --const-provenance.")
        print(f"  Remix requires SEPARATE World, View, and Projection matrices.")
        print(f"  If the game uploads a concatenated WVP or VP, the proxy must")
        print(f"  intercept before concatenation to extract individual matrices.")
    else:
        print(f"\n  Could not determine register layout from static analysis alone.")
        print(f"\n  Recommended next steps:")
        print(f"    1. livetools trace --probe on SVSCF call sites with --read to see actual values")
        print(f"    2. dx9tracer capture + --const-provenance + --shader-map")
        print(f"    3. Decompile the matrix upload functions found above")
        print(f"\n  Remember: Remix requires SEPARATE World, View, and Projection.")
        print(f"  A concatenated WorldViewProj will NOT work -- the proxy must")
        print(f"  capture W, V, P individually before any concatenation.")

    print("\n--- DONE ---")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    matrix_regs = _phase1_svscf_uploads(data, image_base, sections, text_data, text_va)
    _phase2_function_grouping(data, sections, image_base, matrix_regs)
    ctab_matrices = _phase3_ctab_extraction(data, sections, image_base, text_data, text_va)
    _phase4_set_transform(text_data, text_va)
    _phase5_suggested_layout(matrix_regs, ctab_matrices)


if __name__ == "__main__":
    main()
