"""Decode D3D9 vertex declarations from static binary data.

Reads D3DVERTEXELEMENT9 arrays from specified addresses in the binary,
or auto-discovers them by scanning for CreateVertexDeclaration call sites
and extracting the element array pointers.

Usage:
    python decode_vtx_decls.py <game.exe> [addr1 addr2 ...]
    python decode_vtx_decls.py <game.exe> --scan

Examples:
    python decode_vtx_decls.py game.exe 0x16EBF50 0x16EBF70
    python decode_vtx_decls.py game.exe --scan
"""
import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_pe import load_binary, find_text_section, va_to_offset
from dx9_calls import scan_vtable_calls, scan_vtable_mov, method_immediates

D3DDECLTYPE = {
    0: "FLOAT1", 1: "FLOAT2", 2: "FLOAT3", 3: "FLOAT4",
    4: "D3DCOLOR", 5: "UBYTE4", 6: "SHORT2", 7: "SHORT4",
    8: "UBYTE4N", 9: "SHORT2N", 10: "SHORT4N", 11: "USHORT2N",
    12: "USHORT4N", 13: "UDEC3", 14: "DEC3N", 15: "FLOAT16_2",
    16: "FLOAT16_4", 17: "UNUSED"
}

D3DDECLUSAGE = {
    0: "POSITION", 1: "BLENDWEIGHT", 2: "BLENDINDICES", 3: "NORMAL",
    4: "PSIZE", 5: "TEXCOORD", 6: "TANGENT", 7: "BINORMAL",
    8: "TESSFACTOR", 9: "POSITIONT", 10: "COLOR", 11: "FOG",
    12: "DEPTH", 13: "SAMPLE"
}

TYPE_SIZES = {
    0: 4, 1: 8, 2: 12, 3: 16, 4: 4, 5: 4, 6: 4, 7: 8,
    8: 4, 9: 4, 10: 8, 11: 4, 12: 8, 15: 4, 16: 8
}


MAX_ELEMENTS = 64  # D3D9 max is 64 elements per declaration


def decode_decl(data, sections, image_base, va):
    """Decode a D3DVERTEXELEMENT9 array at the given VA."""
    print(f"\n=== Vertex Declaration at 0x{va:08X} ===")
    off = va_to_offset(sections, image_base, va)
    if off is None:
        print("  ERROR: address not in any section")
        return

    total_stride = 0
    has_float16_tc = False
    has_skinning = False
    elem_idx = 0

    while elem_idx <= MAX_ELEMENTS:
        elem = data[off:off + 8]
        if len(elem) < 8:
            break
        stream, offset, typ, method, usage, usage_idx = struct.unpack_from("<HHBBBB", elem)

        if stream == 0xFF or stream == 0xFFFF:
            print(f"  [{elem_idx}] D3DDECL_END")
            break

        if elem_idx == MAX_ELEMENTS:
            print(f"  [{elem_idx}] ... (truncated — no D3DDECL_END found, likely a false positive)")
            return

        type_name = D3DDECLTYPE.get(typ, f"UNKNOWN({typ})")
        usage_name = D3DDECLUSAGE.get(usage, f"UNKNOWN({usage})")
        sz = TYPE_SIZES.get(typ, 0)

        flags = []
        if usage == 5 and typ == 15:  # TEXCOORD + FLOAT16_2
            flags.append("NEEDS EXPANSION")
            has_float16_tc = True
        if usage == 1:  # BLENDWEIGHT
            has_skinning = True
        if usage == 2:  # BLENDINDICES
            has_skinning = True

        flag_str = f"  <{'  '.join(flags)}>" if flags else ""

        print(f"  [{elem_idx}] Stream={stream} Offset={offset:3d} "
              f"Type={type_name:12s} Usage={usage_name}[{usage_idx}] "
              f"Method={method} ({sz} bytes){flag_str}")

        end = offset + sz
        if end > total_stride:
            total_stride = end

        off += 8
        elem_idx += 1

    print(f"  Total stride: {total_stride} bytes")
    if has_float16_tc:
        print("  ** Has FLOAT16_2 texcoords — proxy will expand to FLOAT2 **")
    if has_skinning:
        print("  ** Has blend weight/indices — SKINNED mesh **")


def scan_for_decls(data, sections, image_base):
    """Auto-discover vertex declarations by finding CreateVertexDeclaration calls."""
    found = set()

    raw_start, raw_size, text_va = find_text_section(data, image_base, sections)
    if raw_start is None:
        return []

    text_data = data[raw_start:raw_start + raw_size]

    # Find CreateVertexDeclaration (vtable+0x158) call sites
    call_vas = [va for va, _ in scan_vtable_calls(text_data, text_va, 0x158)]
    # Also check mov reg,[reg+0x158] indirect pattern
    call_vas += [va for va, _ in scan_vtable_mov(text_data, text_va, 0x158)]

    print(f"Found {len(call_vas)} CreateVertexDeclaration call sites")

    # Keep the pVertexElements arguments that point at a valid D3DVERTEXELEMENT9
    for call_va in sorted(call_vas):
        pushed = method_immediates(text_data, text_va, call_va, "CreateVertexDeclaration")
        addr = pushed["pVertexElements"]
        off_check = None if addr is None else va_to_offset(sections, image_base, addr)
        if off_check is None:
            continue
        elem = data[off_check:off_check + 8]
        if len(elem) < 8:
            continue
        stream, offset, typ, method, usage, usage_idx = \
            struct.unpack_from("<HHBBBB", elem)
        if stream <= 4 and typ <= 17 and usage <= 13:
            found.add(addr)

    return sorted(found)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("addresses", nargs="*", type=lambda x: int(x, 0), metavar="ADDR",
                   help="VA(s) of D3DVERTEXELEMENT9 array(s) (hex, e.g. 0x16EBF50)")
    p.add_argument("--scan", action="store_true",
                   help="Auto-scan for CreateVertexDeclaration call sites")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    print(f"ImageBase: 0x{image_base:08X}")

    addresses = list(args.addresses)
    do_scan = args.scan

    if do_scan:
        print("\nAuto-scanning for vertex declarations...")
        found = scan_for_decls(data, sections, image_base)
        if found:
            print(f"Discovered {len(found)} potential vertex declaration addresses:")
            for addr in found:
                print(f"  0x{addr:08X}")
            addresses.extend(found)
        else:
            print("No declarations found via auto-scan. Try providing addresses manually.")

    if not addresses:
        print("\nNo addresses to decode. Use --scan or provide addresses.")
        return

    # Deduplicate
    addresses = sorted(set(addresses))
    for addr in addresses:
        decode_decl(data, sections, image_base, addr)

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
