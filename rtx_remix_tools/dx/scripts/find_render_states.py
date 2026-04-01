"""Find SetRenderState call sites and decode state/value arguments.

Scans for call [reg+0xE4] (D3D9 device vtable slot 57) and inspects
push instructions before each call to determine which render state
is being set and to what value.

Produces a per-state summary showing all hardcoded values found,
making it easy to see the game's alpha blending, culling, depth,
fog, and stencil configuration at a glance.

Usage:
    python find_render_states.py <game.exe>
"""
import argparse
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov, analyze_pushes,
    D3DRS, decode_rs_value,
)

VTABLE_OFFSET = 0xE4  # SetRenderState


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

    # Find call sites
    direct = scan_vtable_calls(text_data, text_va, VTABLE_OFFSET)
    indirect = scan_vtable_mov(text_data, text_va, VTABLE_OFFSET)

    print(f"\n=== SetRenderState (vtable+0x{VTABLE_OFFSET:03X}) ===")
    print(f"  Direct calls:   {len(direct)}")
    print(f"  Indirect (mov): {len(indirect)}")

    # Analyze push arguments for all call sites
    all_sites = [(va, reg) for va, reg in direct]
    all_sites += [(va, 'indirect') for va, _ in indirect]

    # Track per-state: {state_id: [(call_va, value), ...]}
    state_usage = defaultdict(list)
    unknown_sites = []

    for va, reg in all_sites:
        pushes = analyze_pushes(data, sections, image_base, va, window=40)
        # SetRenderState(device, State, Value) — last two pushes are Value, State
        # In cdecl/thiscall, pushed right-to-left: push Value; push State; call
        if len(pushes) >= 2:
            state_id = pushes[-2][1]
            value = pushes[-1][1]
            # Swap if state_id looks like a value and value looks like a state
            if state_id not in D3DRS and value in D3DRS:
                state_id, value = value, state_id
            state_usage[state_id].append((va, value))
        elif len(pushes) == 1:
            # Only got one push — might be register-loaded
            unknown_sites.append((va, pushes))
        else:
            unknown_sites.append((va, []))

    # -- Per-state summary --
    print(f"\n=== Render State Summary ({len(state_usage)} states found) ===\n")

    # Group by category for readability
    categories = {
        "Depth/Stencil": [7, 14, 23, 128, 129, 130, 131, 132, 133, 134, 135,
                          205, 206, 207, 208, 209],
        "Alpha Blending": [15, 24, 25, 27, 20, 21, 190, 230, 231, 232, 233],
        "Culling/Fill": [8, 9, 22],
        "Fog": [28, 34, 35, 36, 37, 38, 48, 158],
        "Lighting/Material": [29, 155, 157, 159, 160, 161, 162, 163, 164, 165],
        "Vertex Processing": [154, 168, 169, 186, 189],
        "Texture Factor": [136],
        "Points": [174, 175, 176, 177, 178, 179, 180, 181, 182, 185],
        "Color Write": [187, 210, 211, 212],
        "Misc": [19, 26, 183, 184, 191, 192, 194, 195, 196, 214, 215],
    }

    categorized = set()
    for cat_name, state_ids in categories.items():
        found = [(sid, state_usage[sid]) for sid in state_ids if sid in state_usage]
        if not found:
            continue
        print(f"  -- {cat_name} --")
        for state_id, entries in found:
            state_name = D3DRS.get(state_id, f"STATE_{state_id}")
            # Collect unique values
            values = defaultdict(int)
            for _, val in entries:
                values[val] += 1
            val_strs = []
            for val, count in sorted(values.items()):
                decoded = decode_rs_value(state_id, val)
                suffix = f" x{count}" if count > 1 else ""
                val_strs.append(f"{decoded}{suffix}")
            print(f"  {state_name:35s} [{len(entries):3d} sites]  "
                  f"values: {', '.join(val_strs)}")
            categorized.add(state_id)
        print()

    # Uncategorized states
    uncategorized = {sid: entries for sid, entries in state_usage.items()
                     if sid not in categorized}
    if uncategorized:
        print(f"  -- Other --")
        for state_id in sorted(uncategorized):
            entries = uncategorized[state_id]
            state_name = D3DRS.get(state_id, f"STATE_{state_id}")
            values = defaultdict(int)
            for _, val in entries:
                values[val] += 1
            val_strs = []
            for val, count in sorted(values.items()):
                decoded = decode_rs_value(state_id, val)
                suffix = f" x{count}" if count > 1 else ""
                val_strs.append(f"{decoded}{suffix}")
            print(f"  {state_name:35s} [{len(entries):3d} sites]  "
                  f"values: {', '.join(val_strs)}")
        print()

    if unknown_sites:
        print(f"  ({len(unknown_sites)} call sites with register-loaded arguments -- "
              f"not decoded statically)")

    # -- Detailed per-site output --
    if args.all:
        print(f"\n=== All SetRenderState call sites ===\n")
        for state_id in sorted(state_usage):
            state_name = D3DRS.get(state_id, f"STATE_{state_id}")
            entries = state_usage[state_id]
            print(f"  {state_name} ({state_id}):")
            for va, val in entries:
                decoded = decode_rs_value(state_id, val)
                print(f"    0x{va:08X}: value = {decoded} (0x{val:X})")
            print()

    print("--- DONE ---")


if __name__ == "__main__":
    main()
