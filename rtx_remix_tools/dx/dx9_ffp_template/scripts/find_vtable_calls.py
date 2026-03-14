"""Find D3DX constant table vtable calls (SetMatrix, SetVector, etc.).

Many engines use ID3DXConstantTable to manage shader constants. The
constant table internally calls SetVertexShaderConstantF, which is why
you may not see direct vtable calls in the game exe. Finding the
constant table call sites helps understand the engine's matrix flow.

Also scans for direct D3D9 device vtable calls used by the engine.

Usage:
    python find_vtable_calls.py <game.exe>
"""
import sys
import struct
from pathlib import Path

# ID3DXConstantTable vtable (32-bit, offset = slot * 4)
D3DX_CONST_TABLE = {
    0x1C: "GetConstantByName",
    0x28: "SetValue",
    0x2C: "SetBool",
    0x34: "SetInt",
    0x3C: "SetFloat",
    0x40: "SetFloatArray",
    0x44: "SetVector",
    0x48: "SetVectorArray",
    0x4C: "SetMatrix",
    0x50: "SetMatrixArray",
    0x54: "SetMatrixPointerArray",
    0x58: "SetMatrixTranspose",
    0x5C: "SetMatrixTransposeArray",
    0x60: "SetMatrixTransposePointerArray",
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


def parse_pe(data):
    pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
    image_base = struct.unpack_from("<I", data, pe_sig_off + 52)[0]
    num_sections = struct.unpack_from("<H", data, pe_sig_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_sig_off + 20)[0]
    section_start = pe_sig_off + 24 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        off = section_start + i * 40
        s_vsz = struct.unpack_from("<I", data, off + 8)[0]
        s_va = struct.unpack_from("<I", data, off + 12)[0]
        s_rawsz = struct.unpack_from("<I", data, off + 16)[0]
        s_raw = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append((s_va, s_raw, s_rawsz, s_vsz, chars))
    return image_base, sections


def find_text(data, image_base, sections):
    for s_va, s_raw, s_rawsz, s_vsz, chars in sections:
        if chars & 0x20000000:
            return s_raw, s_rawsz, image_base + s_va
    return None, None, None


def scan_calls(text_data, text_va, vtable_off):
    """Find both call [reg+off] and mov reg,[reg+off] patterns."""
    results = []

    # call [reg+disp8] (offset <= 0x7F)
    if vtable_off <= 0x7F:
        reg_map_byte = {0x50: 'eax', 0x51: 'ecx', 0x52: 'edx', 0x53: 'ebx',
                        0x55: 'ebp', 0x56: 'esi', 0x57: 'edi'}
        for mod_rm, reg_name in reg_map_byte.items():
            pattern = bytes([0xFF, mod_rm, vtable_off])
            pos = 0
            while True:
                idx = text_data.find(pattern, pos)
                if idx == -1:
                    break
                results.append((text_va + idx, f"call [{reg_name}+0x{vtable_off:02X}]"))
                pos = idx + 1

    # call [reg+disp32]
    reg_map_dword = {0x90: 'eax', 0x91: 'ecx', 0x92: 'edx', 0x93: 'ebx',
                     0x95: 'ebp', 0x96: 'esi', 0x97: 'edi'}
    offset_bytes = struct.pack('<I', vtable_off)
    for mod_rm, reg_name in reg_map_dword.items():
        pattern = bytes([0xFF, mod_rm]) + offset_bytes
        pos = 0
        while True:
            idx = text_data.find(pattern, pos)
            if idx == -1:
                break
            results.append((text_va + idx, f"call [{reg_name}+0x{vtable_off:03X}]"))
            pos = idx + 1

    # mov reg, [reg+disp32] (indirect dispatch)
    dst_regs = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}
    src_regs = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}
    for src_idx, src_name in src_regs.items():
        for dst_idx, dst_name in dst_regs.items():
            modrm = 0x80 | (dst_idx << 3) | src_idx
            pattern = bytes([0x8B, modrm]) + offset_bytes
            pos = 0
            while True:
                idx = text_data.find(pattern, pos)
                if idx == -1:
                    break
                results.append((text_va + idx, f"mov {dst_name}, [{src_name}+0x{vtable_off:03X}]"))
                pos = idx + 1

    results.sort()
    return results


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <game.exe>")
        sys.exit(1)

    data = Path(sys.argv[1]).read_bytes()
    image_base, sections = parse_pe(data)
    raw_start, raw_size, text_va = find_text(data, image_base, sections)
    if raw_start is None:
        print("ERROR: No executable section found")
        return
    text_data = data[raw_start:raw_start + raw_size]

    print(f"ImageBase: 0x{image_base:08X}, .text VA: 0x{text_va:08X}")

    # --- D3DX Constant Table calls ---
    print("\n=== ID3DXConstantTable vtable calls ===")
    for vtable_off, method_name in sorted(D3DX_CONST_TABLE.items()):
        results = scan_calls(text_data, text_va, vtable_off)
        if results:
            print(f"\n  {method_name} (vtable+0x{vtable_off:02X}): {len(results)} sites")
            for va, desc in results[:50]:
                print(f"    0x{va:08X}: {desc}")
            if len(results) > 50:
                print(f"    ... and {len(results) - 50} more")

    # --- Direct D3D9 device vtable calls ---
    print("\n\n=== Direct D3D9 device vtable calls ===")
    for vtable_off, method_name in sorted(D3D9_KEY_METHODS.items()):
        results = scan_calls(text_data, text_va, vtable_off)
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
