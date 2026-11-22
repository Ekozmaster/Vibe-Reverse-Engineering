"""Scan a code region for all D3D9 device vtable call sites.

Useful when you've identified the engine's D3D wrapper code region and
want a complete map of every device method called and from where.

Lists, for every device method:
  - call [reg+OFFSET] where OFFSET is the method's vtable slot
  - mov reg, [reg+OFFSET] that a call through the loaded register follows

A reference below vtable+0x80, where every COM interface has methods, is
labelled unconfirmed unless its object is read from where the code keeps
its device.

The region must lie in one section.

Usage:
    python scan_d3d_region.py <game.exe> <start_va> <end_va>

Example:
    python scan_d3d_region.py game.exe 0xF96000 0xFAA000
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_pe import code_section, load_binary
from dx9_calls import DEVICE_LOW_SLOT_END, device_origin_summary, scan_all_patterns, split_device_hits
from dx9_enums import D3D9_DEVICE_VTABLE

KEY_METHODS = ["SetVertexShader", "SetPixelShader", "SetVertexShaderConstantF",
               "SetPixelShaderConstantF", "DrawPrimitive", "DrawIndexedPrimitive",
               "SetVertexDeclaration", "SetStreamSource", "SetTexture",
               "SetRenderState", "SetTransform", "BeginScene", "EndScene", "Present"]


def section_holding(data, image_base, sections, start_va, end_va):
    """The section the whole region lies in.

    Returns:
        (the section's CodeSection, virtual address of its first byte), or None when no one
        section holds the region.
    """
    for section in sections:
        section_va = image_base + section['va']
        if section_va <= start_va and end_va <= section_va + section['vsz']:
            return code_section(data, sections, section['raw'], section['rawsz']), section_va
    return None


def references_in(section_data, section_va, start_va, end_va):
    """Device method references in the region.

    A reference is judged by the code in front of it, which may start before
    the region, so the scan is handed the whole section.

    Returns:
        {vtable offset: DeviceHits of (va, "call" or "mov")} for the methods
        referenced, each list in address order.
    """
    by_offset = {}
    for offset in D3D9_DEVICE_VTABLE:
        sites = [(va, description.split()[0])
                 for va, description in scan_all_patterns(section_data, section_va, offset,
                                                          region=(start_va, end_va))]
        if sites:
            by_offset[offset] = split_device_hits(section_data, section_va, offset, sites)
    return by_offset


def unconfirmed_suffix(count, reason=""):
    """What follows a count of confirmed references: ", 2 unconfirmed" and *reason*, or nothing when there are none."""
    return f", {count} unconfirmed{reason}" if count else ""


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
    section = section_holding(data, image_base, sections, scan_start, scan_end)
    if section is None:
        print(f"ERROR: scan range 0x{scan_start:X}-0x{scan_end:X} not in one section")
        sys.exit(1)

    print(f"Scanning 0x{scan_start:X}-0x{scan_end:X} ({scan_end - scan_start} bytes)")
    print(f"ImageBase: 0x{image_base:08X}")

    by_offset = references_in(*section, scan_start, scan_end)
    if any(offset < DEVICE_LOW_SLOT_END for offset in by_offset):
        print(device_origin_summary(*section))

    print(f"\n=== D3D9 Device vtable references in 0x{scan_start:X}-0x{scan_end:X} ===\n")

    for offset in sorted(by_offset):
        hits = by_offset[offset]
        unconfirmed = unconfirmed_suffix(len(hits.unconfirmed), " (object not shown to be the device)")
        print(f"[{offset // 4:3d}] {D3D9_DEVICE_VTABLE[offset]} (offset 0x{offset:X}): "
              f"{len(hits.confirmed)} refs{unconfirmed}")
        labelled = [(site, "") for site in hits.confirmed] + [(site, "  unconfirmed") for site in hits.unconfirmed]
        for (va, kind), label in sorted(labelled):
            print(f"        0x{va:08X}  ({kind}){label}")

    unconfirmed = unconfirmed_suffix(sum(len(hits.unconfirmed) for hits in by_offset.values()))
    print(f"\nTotal: {sum(len(hits.confirmed) for hits in by_offset.values())} vtable reference sites{unconfirmed}")
    print(f"Unique methods referenced: {sum(1 for hits in by_offset.values() if hits.confirmed)}")

    print(f"\n=== Key method summary ===")
    hits_by_name = {D3D9_DEVICE_VTABLE[offset]: hits for offset, hits in by_offset.items()}
    for name in KEY_METHODS:
        hits = hits_by_name.get(name)
        status = (f"{len(hits.confirmed)} refs{unconfirmed_suffix(len(hits.unconfirmed))}" if hits
                  else "NOT FOUND")
        print(f"  {name:30s} {status}")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
