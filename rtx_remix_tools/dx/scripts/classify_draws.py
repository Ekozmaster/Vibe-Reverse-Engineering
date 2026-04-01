"""Classify draw calls by surrounding D3D state context.

For each DrawPrimitive/DrawIndexedPrimitive call site, scans a window
before the call for nearby vtable patterns to build a "state profile"
showing which D3D methods are called near each draw. Draw calls with
similar profiles are grouped into classes.

This reveals the game's draw call patterns:
  - FFP draws (SetTransform, SetMaterial, SetTexture, SetRenderState)
  - Shader draws (SetVertexShader, SetPixelShader, SetXxxConstantF)
  - Hybrid draws (FFP + shaders)
  - UI draws (SetFVF with XYZRHW, or DrawPrimitiveUP)

Usage:
    python classify_draws.py <game.exe>
    python classify_draws.py <game.exe> --window 512
"""
import argparse
import sys
import struct
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov, va_to_offset,
    D3D9_DEVICE_VTABLE,
)

# Draw methods to classify
DRAW_METHODS = {
    0x144: "DrawPrimitive",
    0x148: "DrawIndexedPrimitive",
    0x14C: "DrawPrimitiveUP",
    0x150: "DrawIndexedPrimitiveUP",
}

# State methods to look for near draw calls (offset -> short tag)
STATE_TAGS = {
    0xB0: "Transform",
    0xC4: "Material",
    0xCC: "Light",
    0xD4: "LightEnable",
    0xE4: "RenderState",
    0x104: "Texture",
    0x10C: "TexStageState",
    0x114: "SamplerState",
    0x164: "SetFVF",
    0x15C: "VertexDecl",
    0x170: "VS",
    0x178: "VSConstF",
    0x180: "VSConstI",
    0x1AC: "PS",
    0x1B4: "PSConstF",
    0x190: "StreamSrc",
    0x1A0: "Indices",
}

# Classification rules
FFP_INDICATORS = {"Transform", "Material", "Light", "LightEnable", "SetFVF"}
SHADER_INDICATORS = {"VS", "PS", "VSConstF", "PSConstF", "VSConstI"}


def scan_context_window(data, sections, image_base, call_va, window_size,
                         state_offsets):
    """Scan bytes before call_va for vtable call patterns.

    Returns set of state tags found in the window.
    """
    file_off = va_to_offset(sections, image_base, call_va)
    if file_off is None:
        return set()

    start = max(0, file_off - window_size)
    window = data[start:file_off]

    found_tags = set()

    for vtable_off, tag in state_offsets.items():
        offset_bytes = struct.pack('<I', vtable_off)

        # call [reg+disp32]: FF 9x OFFSET
        for modrm in (0x90, 0x91, 0x92, 0x93, 0x96, 0x97):
            pattern = bytes([0xFF, modrm]) + offset_bytes
            if window.find(pattern) != -1:
                found_tags.add(tag)
                break

        if tag in found_tags:
            continue

        # mov reg,[reg+disp32]: 8B xx OFFSET (mod=10)
        for src in (0, 1, 2, 3, 5, 6, 7):
            for dst in (0, 1, 2, 3, 5, 6, 7):
                modrm = 0x80 | (dst << 3) | src
                pattern = bytes([0x8B, modrm]) + offset_bytes
                if window.find(pattern) != -1:
                    found_tags.add(tag)
                    break
            if tag in found_tags:
                break

    return found_tags


def classify_profile(tags):
    """Classify a state profile into a category."""
    has_ffp = bool(tags & FFP_INDICATORS)
    has_shader = bool(tags & SHADER_INDICATORS)

    if has_ffp and has_shader:
        return "hybrid"
    if has_shader:
        return "shader"
    if has_ffp:
        return "ffp"
    if not tags:
        return "minimal"
    return "other"


def profile_key(tags):
    """Create a hashable key from a tag set for grouping."""
    return frozenset(tags)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--window", type=int, default=256, metavar="BYTES",
                   help="Context window size in bytes before each draw call (default: 256)")
    p.add_argument("--all", action="store_true",
                   help="Show every draw call site with its profile")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    print(f"\nContext window: {args.window} bytes before each draw call")

    # Collect all draw call sites
    all_draws = []  # (va, method_name)
    for offset, name in sorted(DRAW_METHODS.items()):
        direct = scan_vtable_calls(text_data, text_va, offset)
        indirect = scan_vtable_mov(text_data, text_va, offset)
        for va, _ in direct:
            all_draws.append((va, name))
        for va, _ in indirect:
            all_draws.append((va, name))

    all_draws.sort()
    print(f"\nTotal draw call sites: {len(all_draws)}")

    if not all_draws:
        print("  No draw calls found.")
        print("\n--- DONE ---")
        return

    # Per-method counts
    method_counts = defaultdict(int)
    for _, name in all_draws:
        method_counts[name] += 1
    for name, count in sorted(method_counts.items()):
        print(f"  {name:30s} {count}")

    # Classify each draw call
    profiles = []  # (va, method, tags, category)
    category_counts = defaultdict(int)
    profile_groups = defaultdict(list)  # frozenset(tags) -> [(va, method)]

    for va, method in all_draws:
        tags = scan_context_window(data, sections, image_base, va,
                                    args.window, STATE_TAGS)
        category = classify_profile(tags)
        profiles.append((va, method, tags, category))
        category_counts[category] += 1
        profile_groups[profile_key(tags)].append((va, method))

    # -- Category summary --
    print(f"\n=== Draw Call Classification ===\n")

    cat_order = ["ffp", "shader", "hybrid", "minimal", "other"]
    cat_labels = {
        "ffp": "Fixed-Function Pipeline",
        "shader": "Programmable Shaders",
        "hybrid": "Hybrid (FFP + Shaders)",
        "minimal": "Minimal Context (isolated or wrapper)",
        "other": "Other (state but no clear FFP/shader)",
    }

    for cat in cat_order:
        count = category_counts.get(cat, 0)
        if count == 0:
            continue
        pct = 100.0 * count / len(all_draws)
        print(f"  {cat_labels[cat]:45s} {count:4d}  ({pct:5.1f}%)")

    # -- Profile groups --
    print(f"\n=== Unique State Profiles ({len(profile_groups)} groups) ===\n")

    # Sort by group size descending
    sorted_groups = sorted(profile_groups.items(), key=lambda x: -len(x[1]))

    for i, (tags_key, sites) in enumerate(sorted_groups[:20]):
        tags = sorted(tags_key) if tags_key else ["<none>"]
        category = classify_profile(tags_key)
        print(f"  Group {i + 1}: [{category}] {len(sites)} draw calls")
        print(f"    State: {', '.join(tags)}")
        if args.all or len(sites) <= 5:
            for va, method in sites[:10]:
                print(f"      0x{va:08X}: {method}")
            if len(sites) > 10:
                print(f"      ... and {len(sites) - 10} more")
        print()

    if len(sorted_groups) > 20:
        print(f"  ... and {len(sorted_groups) - 20} more groups")

    # -- Detailed output --
    if args.all:
        print(f"\n=== All Draw Calls ===\n")
        for va, method, tags, category in profiles:
            tag_str = ', '.join(sorted(tags)) if tags else '<none>'
            print(f"  0x{va:08X}: {method:30s} [{category:7s}] {tag_str}")

    # -- Analysis --
    print(f"\n=== Analysis ===\n")

    ffp_pct = 100.0 * category_counts.get("ffp", 0) / len(all_draws) if all_draws else 0
    shader_pct = 100.0 * category_counts.get("shader", 0) / len(all_draws) if all_draws else 0
    hybrid_pct = 100.0 * category_counts.get("hybrid", 0) / len(all_draws) if all_draws else 0

    if ffp_pct > 50:
        print(f"  Primarily FFP ({ffp_pct:.0f}%) -- good candidate for remix-comp proxy.")
    elif shader_pct > 50:
        print(f"  Primarily shader-based ({shader_pct:.0f}%) -- may need shader replacement")
        print(f"  rather than FFP interception for Remix.")
    elif hybrid_pct > 30:
        print(f"  Significant hybrid usage ({hybrid_pct:.0f}%) -- game mixes FFP and shaders.")
        print(f"  remix-comp needs to handle both paths.")

    up_draws = method_counts.get("DrawPrimitiveUP", 0) + method_counts.get("DrawIndexedPrimitiveUP", 0)
    if up_draws > 0:
        print(f"  Uses UP draw calls ({up_draws} sites) -- user-pointer vertex data,")
        print(f"  Remix may need special handling for these.")

    minimal = category_counts.get("minimal", 0)
    if minimal > len(all_draws) * 0.3:
        print(f"  Many minimal-context draws ({minimal}) -- likely called from a wrapper.")
        print(f"  State is set earlier in the call chain. Try --window 512 or larger.")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
