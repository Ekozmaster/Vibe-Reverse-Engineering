"""Scan a code region for all D3D9 device vtable call sites.

Useful when you've identified the engine's D3D wrapper code region and
want a complete map of every device method called and from where.

Scans for:
  - mov reg, [reg+OFFSET] where OFFSET is a D3D9 vtable slot
  - call [reg+OFFSET] patterns

Usage:
    python scan_d3d_region.py <game.exe> <start_va> <end_va>

Example:
    python scan_d3d_region.py game.exe 0xF96000 0xFAA000
"""
import sys
import struct
from pathlib import Path

D3D9_DEVICE_METHODS = {
    0: "QueryInterface", 1: "AddRef", 2: "Release",
    3: "TestCooperativeLevel", 4: "GetAvailableTextureMem",
    5: "EvictManagedResources", 6: "GetDirect3D", 7: "GetDeviceCaps",
    8: "GetDisplayMode", 9: "GetCreationParameters",
    10: "SetCursorProperties", 11: "SetCursorPosition", 12: "ShowCursor",
    13: "CreateAdditionalSwapChain", 14: "GetSwapChain",
    15: "GetNumberOfSwapChains", 16: "Reset", 17: "Present",
    18: "GetBackBuffer", 19: "GetRasterStatus", 20: "SetDialogBoxMode",
    21: "SetGammaRamp", 22: "GetGammaRamp", 23: "CreateTexture",
    24: "CreateVolumeTexture", 25: "CreateCubeTexture",
    26: "CreateVertexBuffer", 27: "CreateIndexBuffer",
    28: "CreateRenderTarget", 29: "CreateDepthStencilSurface",
    30: "UpdateSurface", 31: "UpdateTexture", 32: "GetRenderTargetData",
    33: "GetFrontBufferData", 34: "StretchRect", 35: "ColorFill",
    36: "CreateOffscreenPlainSurface", 37: "SetRenderTarget",
    38: "GetRenderTarget", 39: "SetDepthStencilSurface",
    40: "GetDepthStencilSurface", 41: "BeginScene", 42: "EndScene",
    43: "Clear", 44: "SetTransform", 45: "GetTransform",
    46: "MultiplyTransform", 47: "SetViewport", 48: "GetViewport",
    49: "SetMaterial", 50: "GetMaterial", 51: "SetLight", 52: "GetLight",
    53: "LightEnable", 54: "GetLightEnable", 55: "SetClipPlane",
    56: "GetClipPlane", 57: "SetRenderState", 58: "GetRenderState",
    59: "CreateStateBlock", 60: "BeginStateBlock", 61: "EndStateBlock",
    62: "SetClipStatus", 63: "GetClipStatus", 64: "GetTexture",
    65: "SetTexture", 66: "GetTextureStageState", 67: "SetTextureStageState",
    68: "GetSamplerState", 69: "SetSamplerState", 70: "ValidateDevice",
    71: "SetPaletteEntries", 72: "GetPaletteEntries",
    73: "SetCurrentTexturePalette", 74: "GetCurrentTexturePalette",
    75: "SetScissorRect", 76: "GetScissorRect",
    77: "SetSoftwareVertexProcessing", 78: "GetSoftwareVertexProcessing",
    79: "SetNPatchMode", 80: "GetNPatchMode",
    81: "DrawPrimitive", 82: "DrawIndexedPrimitive",
    83: "DrawPrimitiveUP", 84: "DrawIndexedPrimitiveUP",
    85: "ProcessVertices", 86: "CreateVertexDeclaration",
    87: "SetVertexDeclaration", 88: "GetVertexDeclaration",
    89: "SetFVF", 90: "GetFVF", 91: "CreateVertexShader",
    92: "SetVertexShader", 93: "GetVertexShader",
    94: "SetVertexShaderConstantF", 95: "GetVertexShaderConstantF",
    96: "SetVertexShaderConstantI", 97: "GetVertexShaderConstantI",
    98: "SetVertexShaderConstantB", 99: "GetVertexShaderConstantB",
    100: "SetStreamSource", 101: "GetStreamSource",
    102: "SetStreamSourceFreq", 103: "GetStreamSourceFreq",
    104: "SetIndices", 105: "GetIndices",
    106: "CreatePixelShader", 107: "SetPixelShader",
    108: "GetPixelShader", 109: "SetPixelShaderConstantF",
    110: "GetPixelShaderConstantF", 111: "SetPixelShaderConstantI",
    112: "GetPixelShaderConstantI", 113: "SetPixelShaderConstantB",
    114: "GetPixelShaderConstantB", 115: "DrawRectPatch",
    116: "DrawTriPatch", 117: "DeletePatch", 118: "CreateQuery",
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
        sections.append((s_va, s_raw, s_rawsz, s_vsz))
    return image_base, sections


def rva_to_offset(sections, rva):
    for s_va, s_raw, s_rawsz, s_vsz in sections:
        if s_va <= rva < s_va + s_vsz:
            return rva - s_va + s_raw
    return None


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <game.exe> <start_va> <end_va>")
        print(f"Example: {sys.argv[0]} game.exe 0xF96000 0xFAA000")
        sys.exit(1)

    exe_path = sys.argv[1]
    scan_start = int(sys.argv[2], 16)
    scan_end = int(sys.argv[3], 16)

    data = Path(exe_path).read_bytes()
    image_base, sections = parse_pe(data)

    scan_rva_start = scan_start - image_base
    scan_rva_end = scan_end - image_base
    raw_start = rva_to_offset(sections, scan_rva_start)
    raw_end = rva_to_offset(sections, scan_rva_end)

    if raw_start is None or raw_end is None:
        print(f"ERROR: scan range 0x{scan_start:X}-0x{scan_end:X} not in any section")
        sys.exit(1)

    print(f"Scanning 0x{scan_start:X}-0x{scan_end:X} ({scan_end - scan_start} bytes)")
    print(f"ImageBase: 0x{image_base:08X}")

    vtable_calls = []

    for i in range(raw_start, raw_end - 6):
        # mov reg, [reg+disp32]: opcode 0x8B, ModRM with mod=10
        if data[i] == 0x8B:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            dst = (modrm >> 3) & 7
            rm = modrm & 7

            if mod == 2 and rm != 4:  # mod=10 (disp32), no SIB
                disp = struct.unpack_from("<i", data, i + 2)[0]
                if 0 < disp < 0x200 and disp % 4 == 0:
                    slot = disp // 4
                    if slot in D3D9_DEVICE_METHODS:
                        va = None
                        for s_va, s_raw, s_rawsz, s_vsz in sections:
                            if s_raw <= i < s_raw + s_rawsz:
                                va = image_base + s_va + (i - s_raw)
                                break
                        if va:
                            vtable_calls.append((va, disp, D3D9_DEVICE_METHODS[slot], 'mov'))

        # call [reg+disp32]: opcode 0xFF, ModRM with mod=10, reg=010 (call)
        if data[i] == 0xFF:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            reg_opc = (modrm >> 3) & 7
            rm = modrm & 7

            if mod == 2 and reg_opc == 2 and rm != 4:
                disp = struct.unpack_from("<i", data, i + 2)[0]
                if 0 < disp < 0x200 and disp % 4 == 0:
                    slot = disp // 4
                    if slot in D3D9_DEVICE_METHODS:
                        va = None
                        for s_va, s_raw, s_rawsz, s_vsz in sections:
                            if s_raw <= i < s_raw + s_rawsz:
                                va = image_base + s_va + (i - s_raw)
                                break
                        if va:
                            vtable_calls.append((va, disp, D3D9_DEVICE_METHODS[slot], 'call'))

    # Deduplicate
    seen = set()
    unique = []
    for entry in vtable_calls:
        if entry[0] not in seen:
            seen.add(entry[0])
            unique.append(entry)
    unique.sort()

    # Group by method
    by_method = {}
    for va, disp, name, kind in unique:
        by_method.setdefault(name, []).append((va, kind))

    print(f"\n=== D3D9 Device vtable references in 0x{scan_start:X}-0x{scan_end:X} ===\n")

    for slot_idx in sorted(D3D9_DEVICE_METHODS.keys()):
        name = D3D9_DEVICE_METHODS[slot_idx]
        if name not in by_method:
            continue
        addrs = by_method[name]
        offset = slot_idx * 4
        print(f"[{slot_idx:3d}] {name} (offset 0x{offset:X}): {len(addrs)} refs")
        for va, kind in addrs:
            print(f"        0x{va:08X}  ({kind})")

    print(f"\nTotal: {len(unique)} vtable reference sites")
    print(f"Unique methods referenced: {len(by_method)}")

    # Summary of key methods
    print(f"\n=== Key method summary ===")
    key_names = ["SetVertexShader", "SetPixelShader", "SetVertexShaderConstantF",
                 "SetPixelShaderConstantF", "DrawPrimitive", "DrawIndexedPrimitive",
                 "SetVertexDeclaration", "SetStreamSource", "SetTexture",
                 "SetRenderState", "SetTransform", "BeginScene", "EndScene", "Present"]
    for name in key_names:
        count = len(by_method.get(name, []))
        status = f"{count} refs" if count > 0 else "NOT FOUND"
        print(f"  {name:30s} {status}")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
