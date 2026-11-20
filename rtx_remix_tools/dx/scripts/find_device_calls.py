"""Find D3D9 device vtable call sites and device pointer references.

Scans for:
  - References to a known device pointer global (if provided)
  - call [reg+offset] patterns for key D3D9 device methods
  - mov reg, [reg+offset] patterns (indirect vtable dispatch)

Usage:
    python find_device_calls.py <game.exe> [--device-addr 0xADDRESS]

If --device-addr is provided, also searches for mov reg, [device_addr] patterns
to find all code that reads the device pointer global.
"""
import argparse
import sys
import struct

from dx9_common import (
    load_binary, find_text_section,
    scan_vtable_calls, scan_vtable_mov, split_device_hits, device_origin_summary,
)

# Key methods for FFP conversion (the ones you'll most likely intercept)
KEY_METHODS = {
    0xA4: "BeginScene", 0xA8: "EndScene", 0x44: "Present",
    0x40: "Reset",
    0xB0: "SetTransform", 0xC4: "SetMaterial", 0xCC: "SetLight",
    0xD4: "LightEnable", 0xE4: "SetRenderState",
    0x104: "SetTexture", 0x10C: "SetTextureStageState",
    0x144: "DrawPrimitive", 0x148: "DrawIndexedPrimitive",
    0x158: "CreateVertexDeclaration", 0x15C: "SetVertexDeclaration",
    0x164: "SetFVF",
    0x16C: "CreateVertexShader", 0x170: "SetVertexShader",
    0x178: "SetVertexShaderConstantF",
    0x190: "SetStreamSource",
    0x1A8: "CreatePixelShader", 0x1AC: "SetPixelShader",
    0x1B4: "SetPixelShaderConstantF",
}


def print_sites(method_name, vtable_off, hits, show_unconfirmed, limit):
    """Print the confirmed sites of one method, up to *limit* (None: all), then the unconfirmed ones' count."""
    confirmed = hits.confirmed
    print(f"\n  {method_name} (vtable+0x{vtable_off:03X}): {len(confirmed)} sites")
    for va, desc in confirmed[:limit]:
        print(f"    0x{va:08X}: {desc}")
    if limit is not None and len(confirmed) > limit:
        print(f"    ... and {len(confirmed) - limit} more")
    if hits.unconfirmed:
        print(f"    + {len(hits.unconfirmed)} unconfirmed (object not shown to be the device)")
        if show_unconfirmed:
            for va, desc in hits.unconfirmed:
                print(f"      0x{va:08X}: {desc}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--device-addr", type=lambda x: int(x, 0), metavar="ADDR",
                   help="VA of the device pointer global (hex, e.g. 0x7C5548)")
    p.add_argument("--unconfirmed", action="store_true",
                   help="List the calls below vtable+0x80 on objects not shown to be the device")
    args = p.parse_args()

    device_addr = args.device_addr
    data, image_base, sections = load_binary(args.binary)
    raw_start, raw_size, text_va = find_text_section(data, image_base, sections)

    if raw_start is None:
        print("ERROR: no executable section found")
        sys.exit(1)

    text_data = data[raw_start:raw_start + raw_size]
    print(f"ImageBase: 0x{image_base:08X}")
    print(f"Executable section: VA 0x{text_va:08X}, size 0x{raw_size:X}")
    print(device_origin_summary(text_data, text_va))

    # --- Key D3D9 vtable offsets ---
    print("\n=== Key D3D9 Device vtable offsets ===")
    for off, name in sorted(KEY_METHODS.items()):
        slot = off // 4
        print(f"  vtable+0x{off:03X} (slot {slot:3d}) = {name}")

    # --- Device pointer references ---
    if device_addr:
        addr_bytes = struct.pack('<I', device_addr)
        print(f"\n=== References to device pointer 0x{device_addr:08X} ===")
        count = 0
        for prefix, reg in [(b'\xA1', 'eax'), (b'\x8B\x0D', 'ecx'),
                            (b'\x8B\x15', 'edx'), (b'\x8B\x1D', 'ebx'),
                            (b'\x8B\x35', 'esi'), (b'\x8B\x3D', 'edi')]:
            pattern = prefix + addr_bytes
            pos = 0
            while True:
                idx = text_data.find(pattern, pos)
                if idx == -1:
                    break
                ref_va = text_va + idx
                print(f"  0x{ref_va:08X}: mov {reg}, [0x{device_addr:08X}]")
                count += 1
                pos = idx + 1
        print(f"  Total: {count} references")

    # --- call [reg+offset] direct vtable calls ---
    print("\n=== Direct vtable calls: call [reg+offset] ===")

    for vtable_off, method_name in sorted(KEY_METHODS.items()):
        calls = [(va, f"call [{reg}+0x{vtable_off:03X}]")
                 for va, reg in scan_vtable_calls(text_data, text_va, vtable_off)]
        print_sites(method_name, vtable_off, split_device_hits(text_data, text_va, vtable_off, calls),
                    args.unconfirmed, limit=None)

    # --- mov reg, [reg+offset] indirect dispatch ---
    print("\n\n=== Indirect vtable dispatch: mov reg, [reg+offset] ===")

    for vtable_off, method_name in sorted(KEY_METHODS.items()):
        loads = scan_vtable_mov(text_data, text_va, vtable_off)
        print_sites(method_name, vtable_off, split_device_hits(text_data, text_va, vtable_off, loads),
                    args.unconfirmed, limit=30)

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
