"""Find SetTexture, SetTextureStageState, and SetSamplerState call sites.

Reconstructs the FFP texture combiner pipeline by analyzing:
  - SetTexture (0x104)                — which texture stages are active
  - SetTextureStageState (0x10C)      — TSS color/alpha ops, arguments, coord sources
  - SetSamplerState (0x114)           — filter modes, addressing, sRGB

Extracts push arguments to decode the stage index, state type, and value
for each call site, producing a per-stage texture pipeline summary.

Usage:
    python find_texture_ops.py <game.exe>
"""
import argparse
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov, analyze_pushes,
    D3DTSS, D3DSAMP, decode_tss_value, decode_samp_value,
)

METHODS = {
    0x104: "SetTexture",
    0x10C: "SetTextureStageState",
    0x114: "SetSamplerState",
}


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

    # -- SetTexture --
    offset = 0x104
    print(f"\n=== SetTexture (vtable+0x{offset:03X}) ===")
    direct = scan_vtable_calls(text_data, text_va, offset)
    indirect = scan_vtable_mov(text_data, text_va, offset)
    print(f"  Direct: {len(direct)}, Indirect: {len(indirect)}")

    # SetTexture(device, Stage, pTexture) — push pTexture; push Stage; call
    stage_counts = defaultdict(int)
    all_tex = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]
    for va, reg in all_tex:
        pushes = analyze_pushes(data, sections, image_base, va, window=40)
        if pushes:
            # Last push before call is the stage index (or close to it)
            stage = pushes[-1][1] if len(pushes) >= 1 else None
            # If stage looks like a pointer, try the other push
            if stage is not None and stage > 16 and len(pushes) >= 2:
                stage = pushes[-2][1]
            if stage is not None and stage <= 16:
                stage_counts[stage] += 1
                if args.all:
                    print(f"    0x{va:08X}: stage={stage}")

    if stage_counts:
        print(f"\n  Texture stages used:")
        for stage in sorted(stage_counts):
            print(f"    Stage {stage}: {stage_counts[stage]} call sites")
    else:
        print(f"  (no stage arguments decoded -- likely register-loaded)")

    # -- SetTextureStageState --
    offset = 0x10C
    print(f"\n\n=== SetTextureStageState (vtable+0x{offset:03X}) ===")
    direct = scan_vtable_calls(text_data, text_va, offset)
    indirect = scan_vtable_mov(text_data, text_va, offset)
    print(f"  Direct: {len(direct)}, Indirect: {len(indirect)}")

    # SetTextureStageState(device, Stage, Type, Value)
    # Push order: Value, Type, Stage
    tss_data = defaultdict(lambda: defaultdict(list))  # stage -> type -> [values]
    all_tss = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]

    for va, reg in all_tss:
        pushes = analyze_pushes(data, sections, image_base, va, window=50)
        if len(pushes) >= 3:
            stage = pushes[-3][1]
            tss_type = pushes[-2][1]
            value = pushes[-1][1]
            # Validate: stage 0-7, type in D3DTSS
            if stage <= 7 and tss_type in D3DTSS:
                tss_data[stage][tss_type].append(value)
            elif tss_type <= 7 and stage in D3DTSS:
                # Arguments might be swapped
                tss_data[tss_type][stage].append(value)

    if tss_data:
        print(f"\n  -- Per-stage texture state summary --")
        for stage in sorted(tss_data):
            print(f"\n  Stage {stage}:")
            for tss_type in sorted(tss_data[stage]):
                type_name = D3DTSS.get(tss_type, f"TYPE_{tss_type}")
                values = tss_data[stage][tss_type]
                decoded = []
                seen = set()
                for v in values:
                    d = decode_tss_value(tss_type, v)
                    if d not in seen:
                        decoded.append(d)
                        seen.add(d)
                print(f"    {type_name:30s} = {', '.join(decoded)}")
    else:
        print(f"  (no TSS arguments decoded -- likely register-loaded or via D3DX)")

    # -- SetSamplerState --
    offset = 0x114
    print(f"\n\n=== SetSamplerState (vtable+0x{offset:03X}) ===")
    direct = scan_vtable_calls(text_data, text_va, offset)
    indirect = scan_vtable_mov(text_data, text_va, offset)
    print(f"  Direct: {len(direct)}, Indirect: {len(indirect)}")

    # SetSamplerState(device, Sampler, Type, Value)
    # Push order: Value, Type, Sampler
    samp_data = defaultdict(lambda: defaultdict(list))  # sampler -> type -> [values]
    all_samp = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]

    for va, reg in all_samp:
        pushes = analyze_pushes(data, sections, image_base, va, window=50)
        if len(pushes) >= 3:
            sampler = pushes[-3][1]
            samp_type = pushes[-2][1]
            value = pushes[-1][1]
            if sampler <= 16 and samp_type in D3DSAMP:
                samp_data[sampler][samp_type].append(value)
            elif samp_type <= 16 and sampler in D3DSAMP:
                samp_data[samp_type][sampler].append(value)

    if samp_data:
        print(f"\n  -- Per-sampler state summary --")
        for sampler in sorted(samp_data):
            print(f"\n  Sampler {sampler}:")
            for samp_type in sorted(samp_data[sampler]):
                type_name = D3DSAMP.get(samp_type, f"TYPE_{samp_type}")
                values = samp_data[sampler][samp_type]
                decoded = []
                seen = set()
                for v in values:
                    d = decode_samp_value(samp_type, v)
                    if d not in seen:
                        decoded.append(d)
                        seen.add(d)
                print(f"    {type_name:20s} = {', '.join(decoded)}")
    else:
        print(f"  (no sampler arguments decoded -- likely register-loaded)")

    # -- Overall summary --
    total_sites = sum(
        len(scan_vtable_calls(text_data, text_va, off)) +
        len(scan_vtable_mov(text_data, text_va, off))
        for off in METHODS
    )
    print(f"\n=== Texture pipeline summary ===")
    print(f"  Total texture-related call sites: {total_sites}")
    if stage_counts:
        max_stage = max(stage_counts.keys())
        print(f"  Active texture stages: 0-{max_stage} ({max_stage + 1} stages)")
    if tss_data:
        has_colorop = any(1 in tss_data[s] for s in tss_data)
        has_alphaop = any(4 in tss_data[s] for s in tss_data)
        has_bumpenv = any(any(t in range(7, 11) for t in tss_data[s]) for s in tss_data)
        has_texcoord = any(11 in tss_data[s] for s in tss_data)
        has_textrans = any(24 in tss_data[s] for s in tss_data)
        if has_colorop:
            print(f"  Uses COLOROP:                yes")
        if has_alphaop:
            print(f"  Uses ALPHAOP:                yes")
        if has_bumpenv:
            print(f"  Uses bump env mapping:       yes")
        if has_texcoord:
            print(f"  Uses TEXCOORDINDEX:          yes (coord generation)")
        if has_textrans:
            print(f"  Uses texture transforms:     yes")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
