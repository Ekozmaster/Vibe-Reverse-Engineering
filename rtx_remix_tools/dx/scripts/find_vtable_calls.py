"""Find D3DX constant table vtable calls (SetMatrix, SetVector, etc.).

Many engines use ID3DXConstantTable to manage shader constants. The
constant table internally calls SetVertexShaderConstantF, which is why
you may not see direct vtable calls in the game exe. Finding the
constant table call sites helps understand the engine's matrix flow.

Also scans for direct D3D9 device vtable calls used by the engine.

Usage:
    python find_vtable_calls.py <game.exe>
"""
import argparse

from dx9_common import (
    load_binary, load_text_section, scan_all_patterns,
    D3DX_CONSTANT_TABLE_METHODS,
)

_REPORTED_CONSTANT_TABLE_METHODS = {
    "GetConstantByName",
    "SetValue", "SetBool", "SetInt", "SetFloat", "SetFloatArray",
    "SetVector", "SetVectorArray",
    "SetMatrix", "SetMatrixArray", "SetMatrixPointerArray",
    "SetMatrixTranspose", "SetMatrixTransposeArray",
    "SetMatrixTransposePointerArray",
}

# ID3DXConstantTable vtable (32-bit, offset = slot * 4)
D3DX_CONST_TABLE = {
    slot * 4: name
    for slot, name in enumerate(D3DX_CONSTANT_TABLE_METHODS)
    if name in _REPORTED_CONSTANT_TABLE_METHODS
}

# Key D3D9 device vtable offsets (32-bit)
D3D9_KEY_METHODS = {
    0x144: "DrawPrimitive",
    0x148: "DrawIndexedPrimitive",
    0x158: "CreateVertexDeclaration",
    0x15C: "SetVertexDeclaration",
    0x170: "SetVertexShader",
    0x178: "SetVertexShaderConstantF",
    0x190: "SetStreamSource",
    0x1A0: "SetIndices",
    0x1AC: "SetPixelShader",
    0x1B4: "SetPixelShaderConstantF",
}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)

    print(f"ImageBase: 0x{image_base:08X}, .text VA: 0x{text_va:08X}")

    # --- D3DX Constant Table calls ---
    print("\n=== ID3DXConstantTable vtable calls ===")
    for vtable_off, method_name in sorted(D3DX_CONST_TABLE.items()):
        results = scan_all_patterns(text_data, text_va, vtable_off)
        if results:
            print(f"\n  {method_name} (vtable+0x{vtable_off:02X}): {len(results)} sites")
            for va, desc in results[:50]:
                print(f"    0x{va:08X}: {desc}")
            if len(results) > 50:
                print(f"    ... and {len(results) - 50} more")
        else:
            print(f"\n  {method_name} (vtable+0x{vtable_off:02X}): 0 sites")

    # --- Direct D3D9 device vtable calls ---
    print("\n\n=== Direct D3D9 device vtable calls ===")
    for vtable_off, method_name in sorted(D3D9_KEY_METHODS.items()):
        results = scan_all_patterns(text_data, text_va, vtable_off)
        if results:
            print(f"\n  {method_name} (vtable+0x{vtable_off:03X}): {len(results)} sites")
            for va, desc in results[:30]:
                print(f"    0x{va:08X}: {desc}")
            if len(results) > 30:
                print(f"    ... and {len(results) - 30} more")
        else:
            print(f"\n  {method_name} (vtable+0x{vtable_off:03X}): 0 sites "
                  "(may be called indirectly via d3dx9)")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
