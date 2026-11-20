"""Find D3DRS_VERTEXBLEND and D3DRS_INDEXEDVERTEXBLENDENABLE render states.

Quick check for whether a game uses hardware FFP vertex blending.
Also scans for SetTransform(WORLDMATRIX(n)) calls that upload bone
matrices to the FFP pipeline.

This is the lightweight companion to find_skinning.py — use this
when you only need to know if FFP vertex blending is present.

Usage:
    python find_blend_states.py <game.exe>
"""
import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_pe import load_binary, load_text_section, print_header
from dx9_calls import scan_vtable_calls, scan_vtable_mov, method_immediates
from dx9_enums import decode_transform_type


D3DVERTEXBLENDFLAGS = {
    0: "DISABLE", 1: "1WEIGHTS", 2: "2WEIGHTS", 3: "3WEIGHTS", 255: "TWEENING",
}

# Render states of interest
BLEND_STATES = {
    151: "D3DRS_VERTEXBLEND",
    167: "D3DRS_INDEXEDVERTEXBLENDENABLE",
}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--all", action="store_true",
                   help="Show every call site, not just the summary")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    # ── SetRenderState scan ─────────────────────────────────────────

    sites = scan_vtable_calls(text_data, text_va, 0xE4)  # SetRenderState
    sites += [(va, 'indirect') for va, _ in scan_vtable_mov(text_data, text_va, 0xE4)]

    state_usage = defaultdict(list)
    for va, _ in sites:
        pushed = method_immediates(text_data, text_va, va, "SetRenderState")
        state_id, value = pushed["State"], pushed["Value"]
        if state_id in BLEND_STATES and value is not None:
            state_usage[state_id].append((va, value))

    print(f"\n=== Vertex Blend Render States ===\n")

    for state_id in sorted(BLEND_STATES):
        state_name = BLEND_STATES[state_id]
        entries = state_usage.get(state_id, [])

        if not entries:
            print(f"  {state_name}: not found")
            continue

        vals = defaultdict(int)
        for _, v in entries:
            vals[v] += 1

        val_strs = []
        for v, cnt in sorted(vals.items()):
            if state_id == 151:
                name = D3DVERTEXBLENDFLAGS.get(v, f"0x{v:X}")
            else:
                name = "TRUE" if v else "FALSE"
            suffix = f" x{cnt}" if cnt > 1 else ""
            val_strs.append(f"{name}{suffix}")

        print(f"  {state_name}: {len(entries)} site(s), values: {', '.join(val_strs)}")

        if args.all:
            for va, v in entries:
                if state_id == 151:
                    decoded = D3DVERTEXBLENDFLAGS.get(v, f"0x{v:X}")
                else:
                    decoded = "TRUE" if v else "FALSE"
                print(f"    0x{va:08X}: {decoded} (0x{v:X})")

    # ── SetTransform(WORLDMATRIX(n)) scan ───────────────────────────

    print(f"\n=== SetTransform — WORLDMATRIX(n) ===\n")

    xform_sites = scan_vtable_calls(text_data, text_va, 0xB0)  # SetTransform
    xform_sites += [(va, 'indirect') for va, _ in scan_vtable_mov(text_data, text_va, 0xB0)]

    wm_calls = []
    for va, _ in xform_sites:
        state = method_immediates(text_data, text_va, va, "SetTransform")["State"]
        if state is not None and 256 <= state <= 511:
            wm_calls.append((va, state))

    if wm_calls:
        indices = sorted(set(v - 256 for _, v in wm_calls))
        max_idx = max(indices)
        print(f"  {len(wm_calls)} call(s) with WORLDMATRIX indices")
        print(f"  Index range: 0..{max_idx} ({max_idx + 1} bone slots)")

        if args.all:
            for va, v in sorted(wm_calls):
                print(f"    0x{va:08X}: {decode_transform_type(v)}")
    else:
        print("  No WORLDMATRIX transform calls found.")

    # ── Summary ─────────────────────────────────────────────────────

    has_vb = bool(state_usage.get(151))
    has_ivb = bool(state_usage.get(167))
    has_wm = bool(wm_calls)

    print(f"\n=== Summary ===\n")

    if has_vb or has_ivb or has_wm:
        print("  Game uses FFP vertex blending:")
        if has_vb:
            print("    - D3DRS_VERTEXBLEND is set (hardware blend weight count)")
        if has_ivb:
            print("    - D3DRS_INDEXEDVERTEXBLENDENABLE is set (matrix palette indexing)")
        if has_wm:
            print("    - WORLDMATRIX(n) transforms uploaded (bone matrices)")
        print("\n  This indicates the game uses D3D9 fixed-function skinning.")
        print("  The proxy's skinning module handles this via SetTransform.")
    else:
        print("  No FFP vertex blending detected.")
        print("  If the game has skinned meshes, it likely uses vertex shaders")
        print("  with bone palettes via SetVertexShaderConstantF.")
        print("  Run find_skinning.py for full analysis.")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
