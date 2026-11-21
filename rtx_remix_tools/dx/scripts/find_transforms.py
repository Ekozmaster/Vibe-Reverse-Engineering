"""Find SetTransform and MultiplyTransform call sites and decode arguments.

Scans for:
  - SetTransform (0xB0)       — which transform types are used
  - MultiplyTransform (0xB8)  — concatenated transforms

Decodes the D3DTRANSFORMSTATETYPE argument to show World, View,
Projection, Texture0-7, and WorldMatrix(n) usage. Cross-reference
with find_vs_constants.py output to understand the matrix pipeline.

Usage:
    python find_transforms.py <game.exe>
"""
import argparse
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_pe import load_binary, load_text_section, print_header
from dx9_calls import scan_vtable_calls, scan_vtable_mov, method_args, arg_text
from dx9_enums import decode_transform_type

METHODS = {
    0xB0: "SetTransform",
    0xB4: "GetTransform",
    0xB8: "MultiplyTransform",
}


def analyze_transform_sites(text_data, text_va, vtable_offset, method_name, show_all=False):
    """Analyze call sites for a transform method."""
    direct = scan_vtable_calls(text_data, text_va, vtable_offset)
    indirect = scan_vtable_mov(text_data, text_va, vtable_offset)

    print(f"\n=== {method_name} (vtable+0x{vtable_offset:03X}) ===")
    print(f"  Direct: {len(direct)}, Indirect: {len(indirect)}")

    all_sites = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]
    if not all_sites:
        return {}

    type_usage = defaultdict(list)  # transform_type -> [call_va, ...]

    for va, reg in all_sites:
        state = method_args(text_data, text_va, va, method_name)["State"]
        # D3DTRANSFORMSTATETYPE runs from VIEW (2) to WORLDMATRIX(255) (511)
        if state is not None and state.value is not None and 2 <= state.value <= 511:
            type_usage[state.value].append(va)
            if show_all:
                print(f"    0x{va:08X}: {decode_transform_type(state.value)}")
        elif show_all:
            print(f"    0x{va:08X}: State={arg_text(state)} (not decoded)")

    return type_usage


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

    all_usage = {}

    for offset, name in sorted(METHODS.items()):
        usage = analyze_transform_sites(text_data, text_va, offset, name, show_all=args.all)
        for ttype, sites in usage.items():
            all_usage.setdefault(ttype, []).extend(sites)

    # Summary
    print(f"\n=== Transform Type Summary ===\n")

    # Group by category
    categories = [
        ("View/Projection", [2, 3]),
        ("World Matrices", list(range(256, 270))),
        ("Texture Transforms", list(range(16, 24))),
    ]

    for cat_name, type_ids in categories:
        found = [(tid, all_usage[tid]) for tid in type_ids if tid in all_usage]
        if not found:
            continue
        print(f"  -- {cat_name} --")
        for tid, sites in found:
            tname = decode_transform_type(tid)
            print(f"    {tname:25s} {len(sites):3d} sites")
        print()

    # Anything else (unusual transform types)
    known = set()
    for _, ids in categories:
        known.update(ids)
    other = {tid: sites for tid, sites in all_usage.items() if tid not in known}
    if other:
        print(f"  -- Other --")
        for tid in sorted(other):
            tname = decode_transform_type(tid)
            print(f"    {tname:25s} {len(other[tid]):3d} sites")
        print()

    # Analysis hints
    if not all_usage:
        print("  No transform type arguments decoded (likely register-loaded)")
    else:
        world_count = sum(1 for tid in all_usage if 256 <= tid < 512)
        tex_count = sum(1 for tid in all_usage if 16 <= tid <= 23)
        has_view = 2 in all_usage
        has_proj = 3 in all_usage

        print(f"  -- Analysis --")
        if has_view:
            print(f"    View matrix:       set at {len(all_usage[2])} sites")
        if has_proj:
            print(f"    Projection matrix: set at {len(all_usage[3])} sites")
        if world_count > 1:
            print(f"    World matrices:    {world_count} distinct indices "
                  f"(hardware skinning with indexed vertex blending)")
        elif world_count == 1:
            print(f"    World matrix:      single (no indexed blending)")
        if tex_count > 0:
            print(f"    Texture transforms: {tex_count} stages "
                  f"(scrolling UVs, projected textures, or cubemap gen)")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
