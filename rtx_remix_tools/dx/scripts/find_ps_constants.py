"""Find SetPixelShaderConstantF/I/B call sites and analyze arguments.

Scans for pixel shader constant upload patterns (D3D9 device vtable):
  - SetPixelShaderConstantF  (0x1B4) — float constants c0-c223
  - SetPixelShaderConstantI  (0x1BC) — integer constants i0-i15
  - SetPixelShaderConstantB  (0x1C4) — boolean constants b0-b15

Also reports CreatePixelShader and SetPixelShader call counts
for overall pixel shader usage context.

Usage:
    python find_ps_constants.py <game.exe>
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov, analyze_pushes,
)

METHODS = {
    0x1B4: ("SetPixelShaderConstantF", "float"),
    0x1BC: ("SetPixelShaderConstantI", "int"),
    0x1C4: ("SetPixelShaderConstantB", "bool"),
}

CONTEXT_METHODS = {
    0x1A8: "CreatePixelShader",
    0x1AC: "SetPixelShader",
    0x1B0: "GetPixelShader",
}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    # Context: pixel shader lifecycle methods
    print("\n=== Pixel Shader context ===")
    for offset, name in sorted(CONTEXT_METHODS.items()):
        direct = scan_vtable_calls(text_data, text_va, offset)
        indirect = scan_vtable_mov(text_data, text_va, offset)
        total = len(direct) + len(indirect)
        print(f"  {name:30s} (0x{offset:03X}): {total} sites "
              f"({len(direct)} direct, {len(indirect)} indirect)")

    # Scan each constant-upload method
    for offset, (name, const_type) in sorted(METHODS.items()):
        print(f"\n\n=== {name} call sites (call [reg+0x{offset:03X}]) ===")

        direct = scan_vtable_calls(text_data, text_va, offset)
        indirect = scan_vtable_mov(text_data, text_va, offset)
        print(f"  Direct calls:   {len(direct)}")
        print(f"  Indirect (mov): {len(indirect)}")

        for va, reg in direct:
            print(f"  0x{va:08X}: call [{reg}+0x{offset:03X}]")

        if indirect:
            for va, desc in indirect:
                print(f"  0x{va:08X}: {desc}")

        # Argument analysis
        all_sites = [(va, reg) for va, reg in direct]
        all_sites += [(va, 'indirect') for va, _ in indirect]

        if not all_sites:
            continue

        print(f"\n=== {name} argument analysis ===")
        # SetPixelShaderConstantF(device, StartRegister, pConstantData, Vector4fCount)
        # Push order (right-to-left): count, data_ptr, start_reg
        show_count = min(len(all_sites), 50)
        if len(all_sites) > 50:
            print(f"  (showing first 50 of {len(all_sites)} sites)")

        reg_usage = {}  # start_reg -> count of sites

        for va, reg in all_sites[:50]:
            pushes = analyze_pushes(data, sections, image_base, va, window=50)
            if len(pushes) >= 2:
                start_reg = pushes[-2][1]
                count = pushes[-1][1]
                # Heuristic: start_reg should be small (0-223 for float, 0-15 for int/bool)
                max_reg = 223 if const_type == 'float' else 15
                if start_reg > max_reg and count <= max_reg:
                    start_reg, count = count, start_reg

                if const_type == 'float':
                    desc = f"c{start_reg}-c{start_reg + count - 1}" if count > 1 else f"c{start_reg}"
                elif const_type == 'int':
                    desc = f"i{start_reg}-i{start_reg + count - 1}" if count > 1 else f"i{start_reg}"
                else:
                    desc = f"b{start_reg}-b{start_reg + count - 1}" if count > 1 else f"b{start_reg}"

                print(f"  0x{va:08X}: StartReg={start_reg}, Count={count}  ({desc})")

                key = (start_reg, count)
                reg_usage[key] = reg_usage.get(key, 0) + 1
            elif pushes:
                vals = ", ".join(f"0x{pv:X}" for _, pv, _ in pushes[-3:])
                print(f"  0x{va:08X}: pushes: [{vals}]")

        # Summary of register ranges
        if reg_usage:
            print(f"\n  -- Register range summary --")
            for (start, count), sites in sorted(reg_usage.items()):
                if const_type == 'float':
                    desc = f"c{start}-c{start + count - 1}" if count > 1 else f"c{start}"
                    vectors = f"{count} vec4{'s' if count > 1 else ''}"
                elif const_type == 'int':
                    desc = f"i{start}-i{start + count - 1}" if count > 1 else f"i{start}"
                    vectors = f"{count} ivec4{'s' if count > 1 else ''}"
                else:
                    desc = f"b{start}-b{start + count - 1}" if count > 1 else f"b{start}"
                    vectors = f"{count} bool{'s' if count > 1 else ''}"
                print(f"    {desc:20s} ({vectors:15s}) -- {sites} call site{'s' if sites > 1 else ''}")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
