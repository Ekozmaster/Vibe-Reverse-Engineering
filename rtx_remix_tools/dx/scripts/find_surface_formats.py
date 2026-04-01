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
    scan_vtable_calls, scan_vtable_mov, analyze_pushes,
    decode_format, D3DPOOL,
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


def extract_format_from_pushes(pushes):
    """Heuristic: find the D3DFORMAT argument among pushes.

    Format values are typically in range 20-117 for standard formats,
    or large FourCC values (DXT1-5, etc.).
    """
    # Known DXT FourCC values
    dxt_values = {0x31545844, 0x32545844, 0x33545844, 0x34545844, 0x35545844}

    candidates = []
    for _, val, ptype in pushes:
        # Standard format range
        if 20 <= val <= 117:
            candidates.append(val)
        # FourCC DXT
        elif val in dxt_values:
            candidates.append(val)
        # INTZ shadow format
        elif val == 0x34324E49:
            candidates.append(val)
    return candidates


def extract_dimensions(pushes):
    """Heuristic: find width/height among pushes.

    Dimensions are typically power-of-2 or common screen resolutions.
    """
    dims = []
    for _, val, ptype in pushes:
        if ptype == 'imm32' and val in (64, 128, 256, 512, 1024, 2048, 4096,
                                         320, 480, 640, 720, 768, 800, 960,
                                         1080, 1200, 1280, 1366, 1440, 1600,
                                         1920, 2560, 3840):
            dims.append(val)
        elif ptype == 'imm8' and val == 0:
            continue  # skip zeros
    return dims


def extract_pool(pushes):
    """Heuristic: find D3DPOOL argument."""
    for _, val, _ in pushes:
        if val in D3DPOOL:
            return val
    return None


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--all", action="store_true",
                   help="Show every call site, not just summaries")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    all_formats = defaultdict(int)   # format -> count
    rt_formats = defaultdict(int)    # render target formats
    ds_formats = defaultdict(int)    # depth/stencil formats
    tex_formats = defaultdict(int)   # texture formats

    for offset, name in sorted(METHODS.items()):
        direct = scan_vtable_calls(text_data, text_va, offset)
        indirect = scan_vtable_mov(text_data, text_va, offset)

        print(f"\n=== {name} (vtable+0x{offset:03X}) ===")
        print(f"  Direct: {len(direct)}, Indirect: {len(indirect)}")

        all_sites = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]
        if not all_sites:
            continue

        for va, reg in all_sites:
            pushes = analyze_pushes(data, sections, image_base, va, window=80)
            formats = extract_format_from_pushes(pushes)
            dims = extract_dimensions(pushes)
            pool = extract_pool(pushes)

            for fmt in formats:
                all_formats[fmt] += 1
                if offset == 0x70:
                    rt_formats[fmt] += 1
                elif offset == 0x74:
                    ds_formats[fmt] += 1
                elif offset in (0x5C, 0x60, 0x64):
                    tex_formats[fmt] += 1

            if args.all or formats:
                parts = [f"0x{va:08X}:"]
                if dims:
                    parts.append(f"dims={dims}")
                if formats:
                    parts.append(f"fmt={[decode_format(f) for f in formats]}")
                if pool is not None:
                    parts.append(f"pool={D3DPOOL.get(pool, str(pool))}")
                if args.all or formats:
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
