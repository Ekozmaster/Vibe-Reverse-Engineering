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
from dx9_pe import load_binary, load_text_section, print_header
from dx9_calls import scan_vtable_calls, scan_vtable_mov, method_args, arg_text
from dx9_enums import D3DRS, D3DRS_ID, decode_rs_value

VTABLE_OFFSET = 0xE4  # SetRenderState

# Display grouping for the per-state summary.
_RS_CATEGORY_NAMES = {
    "Depth/Stencil": (
        "ZENABLE", "ZWRITEENABLE", "ZFUNC", "DEPTHBIAS", "SLOPESCALEDEPTHBIAS",
        "STENCILENABLE", "STENCILFAIL", "STENCILZFAIL", "STENCILPASS",
        "STENCILFUNC", "STENCILREF", "STENCILMASK", "STENCILWRITEMASK",
        "TWOSIDEDSTENCILMODE", "CCW_STENCILFAIL", "CCW_STENCILZFAIL",
        "CCW_STENCILPASS", "CCW_STENCILFUNC",
    ),
    "Alpha Blending": (
        "ALPHATESTENABLE", "ALPHAREF", "ALPHAFUNC", "ALPHABLENDENABLE",
        "SRCBLEND", "DESTBLEND", "BLENDOP", "BLENDFACTOR",
        "SEPARATEALPHABLENDENABLE", "SRCBLENDALPHA", "DESTBLENDALPHA",
        "BLENDOPALPHA",
    ),
    "Culling/Fill": ("FILLMODE", "SHADEMODE", "CULLMODE"),
    "Fog": (
        "FOGENABLE", "FOGCOLOR", "FOGTABLEMODE", "FOGSTART", "FOGEND",
        "FOGDENSITY", "RANGEFOGENABLE", "FOGVERTEXMODE",
    ),
    "Lighting/Material": (
        "LIGHTING", "AMBIENT", "SPECULARENABLE", "COLORVERTEX", "LOCALVIEWER",
        "NORMALIZENORMALS", "DIFFUSEMATERIALSOURCE", "SPECULARMATERIALSOURCE",
        "AMBIENTMATERIALSOURCE", "EMISSIVEMATERIALSOURCE",
    ),
    "Vertex Processing": (
        "CLIPPING", "CLIPPLANEENABLE", "VERTEXBLEND",
        "INDEXEDVERTEXBLENDENABLE", "TWEENFACTOR",
    ),
    "Texture Factor": ("TEXTUREFACTOR",),
    "Points": (
        "POINTSIZE", "POINTSIZE_MIN", "POINTSIZE_MAX", "POINTSPRITEENABLE",
        "POINTSCALEENABLE", "POINTSCALE_A", "POINTSCALE_B", "POINTSCALE_C",
    ),
    "Color Write": (
        "COLORWRITEENABLE", "COLORWRITEENABLE1", "COLORWRITEENABLE2",
        "COLORWRITEENABLE3",
    ),
    "Misc": (
        "LASTPIXEL", "DITHERENABLE", "MULTISAMPLEANTIALIAS", "MULTISAMPLEMASK",
        "SCISSORTESTENABLE", "ANTIALIASEDLINEENABLE", "SRGBWRITEENABLE",
    ),
}
RS_CATEGORIES = {
    category: [D3DRS_ID[name] for name in names]
    for category, names in _RS_CATEGORY_NAMES.items()
}


def _value_text(state_id, value):
    """How the Value argument of one call reads: decoded when it is a pushed constant."""
    if value is None or value.value is None:
        return arg_text(value)
    return str(decode_rs_value(state_id, value.value))


def _summary_line(state_id, entries):
    state_name = D3DRS.get(state_id, f"STATE_{state_id}")
    counts = defaultdict(int)
    for _, value in entries:
        counts[_value_text(state_id, value)] += 1
    values = [f"{text} x{count}" if count > 1 else text for text, count in sorted(counts.items())]
    return f"  {state_name:35s} [{len(entries):3d} sites]  values: {', '.join(values)}"


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

    # Track per-state: {state_id: [(call_va, Value argument), ...]}
    state_usage = defaultdict(list)
    unknown_sites = []

    for va, reg in all_sites:
        pushed = method_args(text_data, text_va, va, "SetRenderState")
        state = pushed["State"]
        if state is None or state.value is None:
            unknown_sites.append(va)
        else:
            state_usage[state.value].append((va, pushed["Value"]))

    # -- Per-state summary --
    print(f"\n=== Render State Summary ({len(state_usage)} states found) ===\n")

    categorized = set()
    for cat_name, state_ids in RS_CATEGORIES.items():
        found = [(sid, state_usage[sid]) for sid in state_ids if sid in state_usage]
        if not found:
            continue
        print(f"  -- {cat_name} --")
        for state_id, entries in found:
            print(_summary_line(state_id, entries))
            categorized.add(state_id)
        print()

    # Uncategorized states
    uncategorized = {sid: entries for sid, entries in state_usage.items()
                     if sid not in categorized}
    if uncategorized:
        print(f"  -- Other --")
        for state_id in sorted(uncategorized):
            print(_summary_line(state_id, uncategorized[state_id]))
        print()

    if unknown_sites:
        print(f"  ({len(unknown_sites)} call sites whose State is not a pushed constant -- "
              f"not decoded statically)")

    # -- Detailed per-site output --
    if args.all:
        print(f"\n=== All SetRenderState call sites ===\n")
        for state_id in sorted(state_usage):
            state_name = D3DRS.get(state_id, f"STATE_{state_id}")
            entries = state_usage[state_id]
            print(f"  {state_name} ({state_id}):")
            for va, value in entries:
                raw = f" (0x{value.value:X})" if value and value.value is not None else ""
                print(f"    0x{va:08X}: value = {_value_text(state_id, value)}{raw}")
            print()

    print("--- DONE ---")


if __name__ == "__main__":
    main()
