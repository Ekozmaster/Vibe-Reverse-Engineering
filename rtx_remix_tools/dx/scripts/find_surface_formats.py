"""Find CreateTexture, CreateRenderTarget, and CreateDepthStencilSurface calls.

Extracts pushed arguments to discover:
  - Texture dimensions and formats (D3DFMT_*)
  - Render target configurations
  - Depth/stencil surface formats
  - Resource pool types (DEFAULT, MANAGED, etc.)

Critical for understanding a game's render pipeline — which formats
Remix needs to handle, whether the game uses float render targets,
sRGB textures, DXT compression, etc.

Usage:
    python find_surface_formats.py <game.exe>
"""
import argparse
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov, method_immediates,
    split_device_hits, device_origin_summary, decode_format, D3DPOOL,
)

# Method signatures (vtable offset, name, arg hints)
METHODS = {
    0x5C: "CreateTexture",
    # CreateTexture(Width, Height, Levels, Usage, Format, Pool, ppTexture, pSharedHandle)
    0x60: "CreateVolumeTexture",
    0x64: "CreateCubeTexture",
    0x70: "CreateRenderTarget",
    # CreateRenderTarget(Width, Height, Format, MultiSample, MultisampleQuality, Lockable, ppSurface, pSharedHandle)
    0x74: "CreateDepthStencilSurface",
    # CreateDepthStencilSurface(Width, Height, Format, MultiSample, MultisampleQuality, Discard, ppSurface, pSharedHandle)
    0x90: "CreateOffscreenPlainSurface",
}


_SIZE_PARAMETERS = ("Width", "Height", "Depth", "EdgeLength")


def size_text(pushed):
    """The created surface's size as "256x128", or None unless every dimension is a constant."""
    dims = [pushed[name] for name in _SIZE_PARAMETERS if name in pushed]
    if None in dims:
        return None
    return "x".join(str(dim) for dim in dims)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--all", action="store_true",
                   help="Show every call site, not just summaries")
    p.add_argument("--unconfirmed", action="store_true",
                   help="List the calls below vtable+0x80 on objects not shown to be the device")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)
    print(device_origin_summary(text_data, text_va))

    all_formats = defaultdict(int)   # format -> count
    rt_formats = defaultdict(int)    # render target formats
    ds_formats = defaultdict(int)    # depth/stencil formats
    tex_formats = defaultdict(int)   # texture formats

    for offset, name in sorted(METHODS.items()):
        direct = split_device_hits(text_data, text_va, offset, scan_vtable_calls(text_data, text_va, offset))
        indirect = split_device_hits(text_data, text_va, offset, scan_vtable_mov(text_data, text_va, offset))

        print(f"\n=== {name} (vtable+0x{offset:03X}) ===")
        print(f"  Direct: {len(direct.confirmed)}, Indirect: {len(indirect.confirmed)}")
        unconfirmed = sorted(va for va, _ in direct.unconfirmed + indirect.unconfirmed)
        if unconfirmed:
            print(f"  Unconfirmed (object not shown to be the device): {len(unconfirmed)}")
            if args.unconfirmed:
                for va in unconfirmed:
                    print(f"    0x{va:08X}")

        for va, _ in direct.confirmed + indirect.confirmed:
            pushed = method_immediates(text_data, text_va, va, name)
            fmt, size, pool = pushed["Format"], size_text(pushed), pushed.get("Pool")

            if fmt is not None:
                all_formats[fmt] += 1
                if offset == 0x70:
                    rt_formats[fmt] += 1
                elif offset == 0x74:
                    ds_formats[fmt] += 1
                elif offset in (0x5C, 0x60, 0x64):
                    tex_formats[fmt] += 1

            if args.all or fmt is not None:
                parts = [f"0x{va:08X}:"]
                if size is not None:
                    parts.append(size)
                if fmt is not None:
                    parts.append(f"fmt={decode_format(fmt)}")
                if pool is not None:
                    parts.append(f"pool={D3DPOOL.get(pool, str(pool))}")
                print(f"    {' '.join(parts)}")

    # -- Format Summary --
    print(f"\n\n{'='*60}")
    print(f"=== Surface Format Summary ===")
    print(f"{'='*60}")

    if tex_formats:
        print(f"\n  -- Texture formats --")
        for fmt in sorted(tex_formats, key=lambda f: -tex_formats[f]):
            print(f"    {decode_format(fmt):25s} {tex_formats[fmt]:3d} creation sites")

    if rt_formats:
        print(f"\n  -- Render target formats --")
        for fmt in sorted(rt_formats, key=lambda f: -rt_formats[f]):
            print(f"    {decode_format(fmt):25s} {rt_formats[fmt]:3d} creation sites")

    if ds_formats:
        print(f"\n  -- Depth/stencil formats --")
        for fmt in sorted(ds_formats, key=lambda f: -ds_formats[f]):
            print(f"    {decode_format(fmt):25s} {ds_formats[fmt]:3d} creation sites")

    if all_formats:
        # Highlight formats that need special attention for Remix
        float_fmts = [f for f in all_formats if f in (111, 112, 113, 114, 115, 116)]
        srgb_note = any(f in (21, 22) for f in all_formats)
        dxt_fmts = [f for f in all_formats if f > 0xFFFF]  # FourCC

        print(f"\n  -- Remix-relevant notes --")
        if float_fmts:
            names = [decode_format(f) for f in float_fmts]
            print(f"    Float render targets: {', '.join(names)}")
        if dxt_fmts:
            names = [decode_format(f) for f in dxt_fmts]
            print(f"    Compressed textures:  {', '.join(names)}")
        if srgb_note:
            print(f"    A8R8G8B8/X8R8G8B8 present (check sRGB sampler state)")
        if ds_formats:
            names = [decode_format(f) for f in ds_formats]
            print(f"    Depth formats:       {', '.join(names)}")
    else:
        print(f"\n  No format arguments decoded (likely register-loaded or via helper)")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
