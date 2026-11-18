"""Scan a code region for all D3D9 device vtable call sites.

Useful when you've identified the engine's D3D wrapper code region and
want a complete map of every device method called and from where.

Scans for:
  - mov reg, [reg+OFFSET] where OFFSET is a D3D9 vtable slot
  - call [reg+OFFSET] patterns

Usage:
    python scan_d3d_region.py <game.exe> <start_va> <end_va>

Example:
    python scan_d3d_region.py game.exe 0xF96000 0xFAA000
"""
import argparse
import sys
import struct

from dx9_common import load_binary, va_to_offset, D3D9_DEVICE_VTABLE

# Derive slot-indexed method dict from offset-keyed vtable
D3D9_DEVICE_METHODS = {offset // 4: name for offset, name in D3D9_DEVICE_VTABLE.items()}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("start_va", type=lambda x: int(x, 0), metavar="START_VA",
                   help="Start of scan range (hex, e.g. 0xF96000)")
    p.add_argument("end_va", type=lambda x: int(x, 0), metavar="END_VA",
                   help="End of scan range exclusive (hex, e.g. 0xFAA000)")
    args = p.parse_args()

    scan_start = args.start_va
    scan_end = args.end_va

    if scan_start >= scan_end:
        print(f"ERROR: start_va 0x{scan_start:X} >= end_va 0x{scan_end:X} — nothing to scan")
        sys.exit(1)

    data, image_base, sections = load_binary(args.binary)

    raw_start = va_to_offset(sections, image_base, scan_start)
    raw_end = va_to_offset(sections, image_base, scan_end)

    if raw_start is None or raw_end is None:
        print(f"ERROR: scan range 0x{scan_start:X}-0x{scan_end:X} not in any section")
        sys.exit(1)

    print(f"Scanning 0x{scan_start:X}-0x{scan_end:X} ({scan_end - scan_start} bytes)")
    print(f"ImageBase: 0x{image_base:08X}")

    vtable_calls = []

    for i in range(raw_start, raw_end - 6):
        # mov reg, [reg+disp32]: opcode 0x8B, ModRM with mod=10
        if data[i] == 0x8B:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            dst = (modrm >> 3) & 7
            rm = modrm & 7

            if mod == 2 and rm != 4:  # mod=10 (disp32), no SIB
                disp = struct.unpack_from("<i", data, i + 2)[0]
                if 0 < disp < 0x200 and disp % 4 == 0:
                    slot = disp // 4
                    if slot in D3D9_DEVICE_METHODS:
                        va = None
                        for s in sections:
                            if s['raw'] <= i < s['raw'] + s['rawsz']:
                                va = image_base + s['va'] + (i - s['raw'])
                                break
                        if va:
                            vtable_calls.append((va, disp, D3D9_DEVICE_METHODS[slot], 'mov'))

        # call [reg+disp32]: opcode 0xFF, ModRM with mod=10, reg=010 (call)
        if data[i] == 0xFF:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            reg_opc = (modrm >> 3) & 7
            rm = modrm & 7

            if mod == 2 and reg_opc == 2 and rm != 4:
                disp = struct.unpack_from("<i", data, i + 2)[0]
                if 0 < disp < 0x200 and disp % 4 == 0:
                    slot = disp // 4
                    if slot in D3D9_DEVICE_METHODS:
                        va = None
                        for s in sections:
                            if s['raw'] <= i < s['raw'] + s['rawsz']:
                                va = image_base + s['va'] + (i - s['raw'])
                                break
                        if va:
                            vtable_calls.append((va, disp, D3D9_DEVICE_METHODS[slot], 'call'))

    # Deduplicate
    seen = set()
    unique = []
    for entry in vtable_calls:
        if entry[0] not in seen:
            seen.add(entry[0])
            unique.append(entry)
    unique.sort()

    # Group by method
    by_method = {}
    for va, disp, name, kind in unique:
        by_method.setdefault(name, []).append((va, kind))

    print(f"\n=== D3D9 Device vtable references in 0x{scan_start:X}-0x{scan_end:X} ===\n")

    for slot_idx in sorted(D3D9_DEVICE_METHODS.keys()):
        name = D3D9_DEVICE_METHODS[slot_idx]
        if name not in by_method:
            continue
        addrs = by_method[name]
        offset = slot_idx * 4
        print(f"[{slot_idx:3d}] {name} (offset 0x{offset:X}): {len(addrs)} refs")
        for va, kind in addrs:
            print(f"        0x{va:08X}  ({kind})")

    print(f"\nTotal: {len(unique)} vtable reference sites")
    print(f"Unique methods referenced: {len(by_method)}")

    # Summary of key methods
    print(f"\n=== Key method summary ===")
    key_names = ["SetVertexShader", "SetPixelShader", "SetVertexShaderConstantF",
                 "SetPixelShaderConstantF", "DrawPrimitive", "DrawIndexedPrimitive",
                 "SetVertexDeclaration", "SetStreamSource", "SetTexture",
                 "SetRenderState", "SetTransform", "BeginScene", "EndScene", "Present"]
    for name in key_names:
        count = len(by_method.get(name, []))
        status = f"{count} refs" if count > 0 else "NOT FOUND"
        print(f"  {name:30s} {status}")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
