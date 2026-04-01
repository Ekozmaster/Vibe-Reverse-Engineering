"""Decode D3D FVF (Flexible Vertex Format) codes from SetFVF call sites.

Scans for SetFVF (vtable+0x164) call sites, extracts the pushed FVF
DWORD, and decodes the bitfield into human-readable vertex components
with stride calculation.

Also accepts FVF values directly on the command line for manual decoding.

FVF is the legacy alternative to vertex declarations — some older games
use it exclusively, others mix FVF and declarations.

Usage:
    python decode_fvf.py <game.exe>             # scan binary
    python decode_fvf.py --decode 0x112         # decode specific value
    python decode_fvf.py <game.exe> --decode 0x112 0x1C2  # both
"""
import argparse
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov, analyze_pushes,
    decode_fvf, D3DFVF_POSITIONS, D3DFVF_FLAGS,
)

SETFVF_OFFSET = 0x164
GETFVF_OFFSET = 0x168


def print_fvf_decode(fvf_val):
    """Pretty-print a decoded FVF value."""
    components, stride, tex_count = decode_fvf(fvf_val)
    print(f"\n  FVF 0x{fvf_val:08X}:")
    print(f"    Components: {' | '.join(components)}")
    print(f"    Stride:     {stride} bytes")
    print(f"    TexCoords:  {tex_count}")

    # Remix-relevant flags
    flags = []
    pos = fvf_val & 0x400E
    if pos == 0x004:
        flags.append("PRETRANSFORMED (XYZRHW) — screen-space, no vertex shader")
    if pos in (0x006, 0x008, 0x00A, 0x00C, 0x00E):
        blend_count = (pos - 4) // 2
        flags.append(f"SKINNED ({blend_count} blend weights)")
    if fvf_val & 0x1000:
        flags.append("LASTBETA_UBYTE4 — indexed skinning")
    if not (fvf_val & 0x010):
        flags.append("NO NORMAL — flat shading or screen-space")
    if not (fvf_val & 0x040):
        flags.append("NO DIFFUSE COLOR")

    if flags:
        print(f"    Notes:")
        for f in flags:
            print(f"      - {f}")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", nargs="?", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--decode", nargs="+", type=lambda x: int(x, 0), metavar="FVF",
                   help="Decode specific FVF value(s) (hex, e.g. 0x112)")
    args = p.parse_args()

    if not args.binary and not args.decode:
        p.error("provide a binary to scan, --decode values, or both")

    # Manual decode
    if args.decode:
        print("=== Manual FVF decode ===")
        for fvf_val in args.decode:
            print_fvf_decode(fvf_val)
        if not args.binary:
            print("\n--- DONE ---")
            return

    # Binary scan
    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    # SetFVF
    print(f"\n=== SetFVF (vtable+0x{SETFVF_OFFSET:03X}) ===")
    direct = scan_vtable_calls(text_data, text_va, SETFVF_OFFSET)
    indirect = scan_vtable_mov(text_data, text_va, SETFVF_OFFSET)
    print(f"  Direct: {len(direct)}, Indirect: {len(indirect)}")

    # GetFVF (context: how many queries)
    get_direct = scan_vtable_calls(text_data, text_va, GETFVF_OFFSET)
    get_indirect = scan_vtable_mov(text_data, text_va, GETFVF_OFFSET)
    get_total = len(get_direct) + len(get_indirect)
    print(f"  GetFVF:  {get_total} sites")

    all_sites = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]
    if not all_sites:
        print("\n  No SetFVF calls found -- game likely uses vertex declarations instead.")
        print("\n--- DONE ---")
        return

    # Extract FVF values
    # SetFVF(device, FVF) — single DWORD argument
    fvf_values = defaultdict(list)  # fvf -> [call_va, ...]

    for va, reg in all_sites:
        pushes = analyze_pushes(data, sections, image_base, va, window=30)
        # FVF is typically pushed as imm32 (it's a bitfield, usually > 0xFF)
        fvf_val = None
        for _, pval, ptype in pushes:
            if ptype == 'imm32' and pval > 0 and pval < 0x10000:
                fvf_val = pval
                break
            if ptype == 'imm8' and pval > 0:
                # Small FVF like D3DFVF_XYZ (0x002) could be imm8
                fvf_val = pval
                break
        if fvf_val is not None:
            fvf_values[fvf_val].append(va)

    # Decode each unique FVF
    print(f"\n=== Decoded FVF values ({len(fvf_values)} unique) ===")
    for fvf_val in sorted(fvf_values):
        sites = fvf_values[fvf_val]
        print_fvf_decode(fvf_val)
        print(f"    Used at: {len(sites)} call sites")
        if len(sites) <= 5:
            for va in sites:
                print(f"      0x{va:08X}")

    # Summary
    print(f"\n=== FVF Summary ===")
    total = sum(len(s) for s in fvf_values.values())
    unknown = len(all_sites) - total
    print(f"  Total SetFVF calls:  {len(all_sites)}")
    print(f"  Decoded:             {total}")
    if unknown > 0:
        print(f"  Register-loaded:     {unknown}")
    print(f"  Unique FVF codes:    {len(fvf_values)}")

    # Check for pretransformed vertices
    pretrans = [f for f in fvf_values if (f & 0x400E) == 0x004]
    skinned = [f for f in fvf_values if (f & 0x400E) in (0x006, 0x008, 0x00A, 0x00C, 0x00E)]
    if pretrans:
        print(f"  XYZRHW (pretransformed): {len(pretrans)} FVF codes -- "
              f"2D/UI geometry, skips vertex processing")
    if skinned:
        print(f"  Skinned (blend weights): {len(skinned)} FVF codes -- "
              f"hardware vertex blending")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
