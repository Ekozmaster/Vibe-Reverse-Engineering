"""Find state block creation, recording, and application patterns.

Some engines batch D3D state changes into state blocks that get
applied atomically. This script finds:
  - CreateStateBlock (0xEC)   — captures current device state
  - BeginStateBlock (0xF0)    — starts recording state changes
  - EndStateBlock (0xF4)      — stops recording, returns state block

Also scans for IDirect3DStateBlock9 vtable calls:
  - Apply   (vtable+0x14)    — applies captured state
  - Capture (vtable+0x10)    — re-captures current state into block

Understanding state block usage is important because state set
inside a BeginStateBlock/EndStateBlock pair is recorded, not
applied — and Apply replays it later, making state flow non-local.

Usage:
    python find_stateblocks.py <game.exe>
"""
import argparse
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov, scan_all_patterns,
    analyze_pushes, D3DSTATEBLOCKTYPE,
)

# Device methods
DEVICE_METHODS = {
    0xEC: "CreateStateBlock",
    0xF0: "BeginStateBlock",
    0xF4: "EndStateBlock",
}

# IDirect3DStateBlock9 vtable (inherits from IUnknown)
STATEBLOCK_VTABLE = {
    0x00: "QueryInterface",
    0x04: "AddRef",
    0x08: "Release",
    0x0C: "GetDevice",
    0x10: "Capture",
    0x14: "Apply",
}

STATEBLOCK_KEY_METHODS = {0x10: "Capture", 0x14: "Apply"}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    # -- Device state block methods --
    print(f"\n=== Device state block methods ===")

    for offset, name in sorted(DEVICE_METHODS.items()):
        direct = scan_vtable_calls(text_data, text_va, offset)
        indirect = scan_vtable_mov(text_data, text_va, offset)
        total = len(direct) + len(indirect)
        print(f"\n  {name} (vtable+0x{offset:03X}): {total} sites "
              f"({len(direct)} direct, {len(indirect)} indirect)")

        all_sites = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]

        if offset == 0xEC and all_sites:
            # CreateStateBlock(device, Type, ppSB)
            # Type is D3DSTATEBLOCKTYPE pushed as imm8 (1-3)
            type_counts = defaultdict(int)
            for va, reg in all_sites:
                pushes = analyze_pushes(data, sections, image_base, va, window=30)
                for _, pval, ptype in pushes:
                    if pval in D3DSTATEBLOCKTYPE:
                        type_counts[pval] += 1
                        print(f"    0x{va:08X}: type={D3DSTATEBLOCKTYPE[pval]}")
                        break
                else:
                    print(f"    0x{va:08X}: type=<register-loaded>")

            if type_counts:
                print(f"\n    State block types:")
                for t, count in sorted(type_counts.items()):
                    print(f"      {D3DSTATEBLOCKTYPE[t]:15s} {count} creation sites")
        else:
            for va, reg in direct:
                print(f"    0x{va:08X}: call [{reg}+0x{offset:03X}]")
            for va, desc in indirect:
                print(f"    0x{va:08X}: {desc}")

    # -- IDirect3DStateBlock9 Apply/Capture --
    # These use small vtable offsets so we need disp8 scanning too
    print(f"\n\n=== IDirect3DStateBlock9 vtable calls ===")
    print(f"  (Note: small offsets may produce false positives from non-D3D vtables)\n")

    for offset, name in sorted(STATEBLOCK_KEY_METHODS.items()):
        results = scan_all_patterns(text_data, text_va, offset)
        print(f"  {name} (vtable+0x{offset:02X}): {len(results)} candidate sites")
        # Show first 20
        for va, desc in results[:20]:
            print(f"    0x{va:08X}: {desc}")
        if len(results) > 20:
            print(f"    ... and {len(results) - 20} more")

    # -- Analysis --
    begin_count = (len(scan_vtable_calls(text_data, text_va, 0xF0)) +
                   len(scan_vtable_mov(text_data, text_va, 0xF0)))
    end_count = (len(scan_vtable_calls(text_data, text_va, 0xF4)) +
                 len(scan_vtable_mov(text_data, text_va, 0xF4)))
    create_count = (len(scan_vtable_calls(text_data, text_va, 0xEC)) +
                    len(scan_vtable_mov(text_data, text_va, 0xEC)))

    print(f"\n=== Analysis ===")
    if create_count == 0 and begin_count == 0:
        print(f"  No state block usage detected -- game sets state directly.")
    else:
        if create_count > 0:
            print(f"  Uses CreateStateBlock: state snapshots are taken at runtime.")
            print(f"  State set between BeginScene/EndScene may be replayed via Apply().")
        if begin_count > 0:
            print(f"  Uses BeginStateBlock/EndStateBlock: state is RECORDED, not applied.")
            print(f"  D3D calls between Begin/End are captured into a block for later replay.")
            if begin_count != end_count:
                print(f"  WARNING: {begin_count} Begin vs {end_count} End -- "
                      f"possible conditional recording paths.")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
