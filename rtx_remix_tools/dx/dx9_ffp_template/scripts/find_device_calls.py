"""Find D3D9 device vtable call sites and device pointer references.

Scans for:
  - References to a known device pointer global (if provided)
  - call [reg+offset] patterns for key D3D9 device methods
  - mov reg, [reg+offset] patterns (indirect vtable dispatch)

Usage:
    python find_device_calls.py <game.exe> [--device-addr 0xADDRESS]

If --device-addr is provided, also searches for mov reg, [device_addr] patterns
to find all code that reads the device pointer global.
"""
import sys
import struct
from pathlib import Path

# IDirect3DDevice9 vtable: slot index -> method name
D3D9_DEVICE_VTABLE = {
    0x00: "QueryInterface", 0x04: "AddRef", 0x08: "Release",
    0x0C: "TestCooperativeLevel", 0x10: "GetAvailableTextureMem",
    0x14: "EvictManagedResources", 0x18: "GetDirect3D", 0x1C: "GetDeviceCaps",
    0x20: "GetDisplayMode", 0x24: "GetCreationParameters",
    0x28: "SetCursorProperties", 0x2C: "SetCursorPosition", 0x30: "ShowCursor",
    0x34: "CreateAdditionalSwapChain", 0x38: "GetSwapChain",
    0x3C: "GetNumberOfSwapChains", 0x40: "Reset", 0x44: "Present",
    0x48: "GetBackBuffer", 0x4C: "GetRasterStatus", 0x50: "SetDialogBoxMode",
    0x54: "SetGammaRamp", 0x58: "GetGammaRamp", 0x5C: "CreateTexture",
    0x60: "CreateVolumeTexture", 0x64: "CreateCubeTexture",
    0x68: "CreateVertexBuffer", 0x6C: "CreateIndexBuffer",
    0x70: "CreateRenderTarget", 0x74: "CreateDepthStencilSurface",
    0x78: "UpdateSurface", 0x7C: "UpdateTexture", 0x80: "GetRenderTargetData",
    0x84: "GetFrontBufferData", 0x88: "StretchRect", 0x8C: "ColorFill",
    0x90: "CreateOffscreenPlainSurface", 0x94: "SetRenderTarget",
    0x98: "GetRenderTarget", 0x9C: "SetDepthStencilSurface",
    0xA0: "GetDepthStencilSurface", 0xA4: "BeginScene", 0xA8: "EndScene",
    0xAC: "Clear", 0xB0: "SetTransform", 0xB4: "GetTransform",
    0xB8: "MultiplyTransform", 0xBC: "SetViewport", 0xC0: "GetViewport",
    0xC4: "SetMaterial", 0xC8: "GetMaterial", 0xCC: "SetLight",
    0xD0: "GetLight", 0xD4: "LightEnable", 0xD8: "GetLightEnable",
    0xDC: "SetClipPlane", 0xE0: "GetClipPlane", 0xE4: "SetRenderState",
    0xE8: "GetRenderState", 0xEC: "CreateStateBlock", 0xF0: "BeginStateBlock",
    0xF4: "EndStateBlock", 0xF8: "SetClipStatus", 0xFC: "GetClipStatus",
    0x100: "GetTexture", 0x104: "SetTexture", 0x108: "GetTextureStageState",
    0x10C: "SetTextureStageState", 0x110: "GetSamplerState",
    0x114: "SetSamplerState", 0x118: "ValidateDevice",
    0x11C: "SetPaletteEntries", 0x120: "GetPaletteEntries",
    0x124: "SetCurrentTexturePalette", 0x128: "GetCurrentTexturePalette",
    0x12C: "SetScissorRect", 0x130: "GetScissorRect",
    0x134: "SetSoftwareVertexProcessing", 0x138: "GetSoftwareVertexProcessing",
    0x13C: "SetNPatchMode", 0x140: "GetNPatchMode",
    0x144: "DrawPrimitive", 0x148: "DrawIndexedPrimitive",
    0x14C: "DrawPrimitiveUP", 0x150: "DrawIndexedPrimitiveUP",
    0x154: "ProcessVertices", 0x158: "CreateVertexDeclaration",
    0x15C: "SetVertexDeclaration", 0x160: "GetVertexDeclaration",
    0x164: "SetFVF", 0x168: "GetFVF", 0x16C: "CreateVertexShader",
    0x170: "SetVertexShader", 0x174: "GetVertexShader",
    0x178: "SetVertexShaderConstantF", 0x17C: "GetVertexShaderConstantF",
    0x180: "SetVertexShaderConstantI", 0x184: "GetVertexShaderConstantI",
    0x188: "SetVertexShaderConstantB", 0x18C: "GetVertexShaderConstantB",
    0x190: "SetStreamSource", 0x194: "GetStreamSource",
    0x198: "SetStreamSourceFreq", 0x19C: "GetStreamSourceFreq",
    0x1A0: "SetIndices", 0x1A4: "GetIndices",
    0x1A8: "CreatePixelShader", 0x1AC: "SetPixelShader",
    0x1B0: "GetPixelShader", 0x1B4: "SetPixelShaderConstantF",
    0x1B8: "GetPixelShaderConstantF", 0x1BC: "SetPixelShaderConstantI",
    0x1C0: "GetPixelShaderConstantI", 0x1C4: "SetPixelShaderConstantB",
    0x1C8: "GetPixelShaderConstantB", 0x1CC: "DrawRectPatch",
    0x1D0: "DrawTriPatch", 0x1D4: "DeletePatch", 0x1D8: "CreateQuery",
}

# Key methods for FFP conversion (the ones you'll most likely intercept)
KEY_METHODS = {
    0xA4: "BeginScene", 0xA8: "EndScene", 0x44: "Present",
    0x40: "Reset",
    0xB0: "SetTransform", 0xC4: "SetMaterial", 0xCC: "SetLight",
    0xD4: "LightEnable", 0xE4: "SetRenderState",
    0x104: "SetTexture", 0x10C: "SetTextureStageState",
    0x144: "DrawPrimitive", 0x148: "DrawIndexedPrimitive",
    0x158: "CreateVertexDeclaration", 0x15C: "SetVertexDeclaration",
    0x164: "SetFVF",
    0x16C: "CreateVertexShader", 0x170: "SetVertexShader",
    0x178: "SetVertexShaderConstantF",
    0x190: "SetStreamSource",
    0x1A8: "CreatePixelShader", 0x1AC: "SetPixelShader",
    0x1B4: "SetPixelShaderConstantF",
}


def parse_pe_sections(data):
    pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
    image_base = struct.unpack_from("<I", data, pe_sig_off + 52)[0]
    num_sections = struct.unpack_from("<H", data, pe_sig_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_sig_off + 20)[0]
    section_start = pe_sig_off + 24 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        off = section_start + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        s_vsz = struct.unpack_from("<I", data, off + 8)[0]
        s_va = struct.unpack_from("<I", data, off + 12)[0]
        s_rawsz = struct.unpack_from("<I", data, off + 16)[0]
        s_raw = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({
            'name': name, 'va': s_va, 'raw': s_raw,
            'rawsz': s_rawsz, 'vsz': s_vsz, 'chars': chars
        })
    return image_base, sections


def find_text_section(data, image_base, sections):
    for s in sections:
        if s['chars'] & 0x20000000:
            return s['raw'], s['rawsz'], image_base + s['va']
    return None, None, None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <game.exe> [--device-addr 0xADDRESS]")
        sys.exit(1)

    exe_path = sys.argv[1]
    device_addr = None
    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == '--device-addr' and i + 1 < len(sys.argv):
            device_addr = int(sys.argv[i + 1], 16)

    data = Path(exe_path).read_bytes()
    image_base, sections = parse_pe_sections(data)
    raw_start, raw_size, text_va = find_text_section(data, image_base, sections)

    if raw_start is None:
        print("ERROR: no executable section found")
        sys.exit(1)

    text_data = data[raw_start:raw_start + raw_size]
    print(f"ImageBase: 0x{image_base:08X}")
    print(f"Executable section: VA 0x{text_va:08X}, size 0x{raw_size:X}")

    # --- Key D3D9 vtable offsets ---
    print("\n=== Key D3D9 Device vtable offsets ===")
    for off, name in sorted(KEY_METHODS.items()):
        slot = off // 4
        print(f"  vtable+0x{off:03X} (slot {slot:3d}) = {name}")

    # --- Device pointer references ---
    if device_addr:
        addr_bytes = struct.pack('<I', device_addr)
        print(f"\n=== References to device pointer 0x{device_addr:08X} ===")
        count = 0
        for prefix, reg in [(b'\xA1', 'eax'), (b'\x8B\x0D', 'ecx'),
                            (b'\x8B\x15', 'edx'), (b'\x8B\x1D', 'ebx'),
                            (b'\x8B\x35', 'esi'), (b'\x8B\x3D', 'edi')]:
            pattern = prefix + addr_bytes
            pos = 0
            while True:
                idx = text_data.find(pattern, pos)
                if idx == -1:
                    break
                ref_va = text_va + idx
                print(f"  0x{ref_va:08X}: mov {reg}, [0x{device_addr:08X}]")
                count += 1
                pos = idx + 1
        print(f"  Total: {count} references")

    # --- call [reg+offset] direct vtable calls ---
    print("\n=== Direct vtable calls: call [reg+offset] ===")
    regs_dword = {0x90: 'eax', 0x91: 'ecx', 0x92: 'edx', 0x93: 'ebx',
                  0x96: 'esi', 0x97: 'edi'}

    for vtable_off, method_name in sorted(KEY_METHODS.items()):
        results = []
        offset_bytes = struct.pack('<I', vtable_off)
        for mod_rm, reg_name in regs_dword.items():
            pattern = bytes([0xFF, mod_rm]) + offset_bytes
            pos = 0
            while True:
                idx = text_data.find(pattern, pos)
                if idx == -1:
                    break
                va = text_va + idx
                results.append((va, reg_name))
                pos = idx + 1
        results.sort()
        if results:
            print(f"\n  {method_name} (vtable+0x{vtable_off:03X}): {len(results)} sites")
            for va, reg in results:
                print(f"    0x{va:08X}: call [{reg}+0x{vtable_off:03X}]")

    # --- mov reg, [reg+offset] indirect dispatch ---
    print("\n\n=== Indirect vtable dispatch: mov reg, [reg+offset] ===")
    dst_regs = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}
    src_regs = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}

    for vtable_off, method_name in sorted(KEY_METHODS.items()):
        results = []
        offset_bytes = struct.pack('<I', vtable_off)
        for src_idx, src_name in src_regs.items():
            for dst_idx, dst_name in dst_regs.items():
                modrm = 0x80 | (dst_idx << 3) | src_idx
                pattern = bytes([0x8B, modrm]) + offset_bytes
                pos = 0
                while True:
                    idx = text_data.find(pattern, pos)
                    if idx == -1:
                        break
                    va = text_va + idx
                    results.append((va, f"mov {dst_name}, [{src_name}+0x{vtable_off:03X}]"))
                    pos = idx + 1
        results.sort()
        if results:
            print(f"\n  {method_name} (vtable+0x{vtable_off:03X}): {len(results)} sites")
            for va, desc in results[:30]:
                print(f"    0x{va:08X}: {desc}")
            if len(results) > 30:
                print(f"    ... and {len(results) - 30} more")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
