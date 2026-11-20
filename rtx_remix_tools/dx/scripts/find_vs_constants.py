"""Find SetVertexShaderConstantF call sites and analyze arguments.

Scans for call [reg+0x178] patterns (D3D9 device vtable slot 94) and
method-pointer loads from that slot, and reads the start register and
count each call is given from the pushes and [esp+disp] stores in front
of it.

Also scans for DrawIndexedPrimitive, SetVertexDeclaration, and
CreateVertexDeclaration call sites.

Usage:
    python find_vs_constants.py <game.exe>
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_pe import load_binary, load_text_section
from dx9_calls import scan_vtable_calls, scan_vtable_mov, method_args, arg_text


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)

    # --- SetVertexShaderConstantF (0x178) ---
    print("=== SetVertexShaderConstantF call sites (call [reg+0x178]) ===")
    results = scan_vtable_calls(text_data, text_va, 0x178)
    for va, reg in results:
        print(f"  0x{va:08X}: call [{reg}+0x178]")
    print(f"Total: {len(results)} direct call sites")

    mov_results = scan_vtable_mov(text_data, text_va, 0x178)
    if mov_results:
        print(f"\n  Indirect dispatch (mov reg, [reg+0x178]): {len(mov_results)} sites")
        for va, desc in mov_results:
            print(f"    0x{va:08X}: {desc}")
    else:
        print("  Indirect dispatch: 0 sites")

    # --- Argument analysis ---
    all_sites = [(va, reg) for va, reg in results]
    all_sites += [(va, 'indirect') for va, _ in mov_results]
    if all_sites:
        print(f"\n=== SetVertexShaderConstantF argument analysis ===")
        if len(all_sites) > 50:
            print(f"  (showing first 50 of {len(all_sites)} sites)")
        for va, reg in all_sites[:50]:
            pushed = method_args(text_data, text_va, va, "SetVertexShaderConstantF")
            print(f"\n  0x{va:08X}: call [{reg}+0x178]")
            print("    " + "  ".join(f"{name}={arg_text(arg)}"
                                     for name, arg in pushed.items() if name != "this"))

    # --- DrawIndexedPrimitive (0x148) ---
    print(f"\n\n=== DrawIndexedPrimitive call sites (call [reg+0x148]) ===")
    dip = scan_vtable_calls(text_data, text_va, 0x148)
    for va, reg in dip:
        print(f"  0x{va:08X}: call [{reg}+0x148]")
    print(f"Total: {len(dip)} call sites")
    dip_mov = scan_vtable_mov(text_data, text_va, 0x148)
    if dip_mov:
        print(f"  Indirect: {len(dip_mov)} sites")
        for va, desc in dip_mov:
            print(f"    0x{va:08X}: {desc}")
    else:
        print("  Indirect: 0 sites")

    # --- SetVertexDeclaration (0x15C) ---
    print(f"\n=== SetVertexDeclaration call sites (call [reg+0x15C]) ===")
    svd = scan_vtable_calls(text_data, text_va, 0x15C)
    for va, reg in svd:
        print(f"  0x{va:08X}: call [{reg}+0x15C]")
    print(f"Total: {len(svd)} call sites")
    svd_mov = scan_vtable_mov(text_data, text_va, 0x15C)
    if svd_mov:
        print(f"  Indirect: {len(svd_mov)} sites")
        for va, desc in svd_mov:
            print(f"    0x{va:08X}: {desc}")
    else:
        print("  Indirect: 0 sites")

    # --- CreateVertexDeclaration (0x158) ---
    print(f"\n=== CreateVertexDeclaration call sites (call [reg+0x158]) ===")
    cvd = scan_vtable_calls(text_data, text_va, 0x158)
    for va, reg in cvd:
        print(f"  0x{va:08X}: call [{reg}+0x158]")
    print(f"Total: {len(cvd)} call sites")
    cvd_mov = scan_vtable_mov(text_data, text_va, 0x158)
    if cvd_mov:
        print(f"  Indirect: {len(cvd_mov)} sites")
        for va, desc in cvd_mov:
            print(f"    0x{va:08X}: {desc}")
    else:
        print("  Indirect: 0 sites")

    print("\n--- DONE ---")

if __name__ == "__main__":
    main()
