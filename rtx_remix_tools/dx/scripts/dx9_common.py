"""Shared utilities for DX9 reverse engineering scripts.

Provides PE parsing, vtable scanning, push argument extraction,
and D3D9 enum dictionaries used across all DX scripts.

Usage:
    from dx9_common import parse_pe, va_to_offset, scan_vtable_calls, ...
"""
import struct


# ═══════════════════════════════════════════════════════════════════════
# PE Parsing
# ═══════════════════════════════════════════════════════════════════════

def parse_pe(data):
    """Parse PE headers. Returns (image_base, sections).

    Each section: dict with name, va, raw, rawsz, vsz, chars.
    """
    pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
    image_base = struct.unpack_from("<I", data, pe_sig_off + 52)[0]
    num_sections = struct.unpack_from("<H", data, pe_sig_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_sig_off + 20)[0]
    section_start = pe_sig_off + 24 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        off = section_start + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        s_vsz = struct.unpack_from("<I", data, off + 8)[0]
        s_va = struct.unpack_from("<I", data, off + 12)[0]
        s_rawsz = struct.unpack_from("<I", data, off + 16)[0]
        s_raw = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({
            'name': name, 'va': s_va, 'raw': s_raw,
            'rawsz': s_rawsz, 'vsz': s_vsz, 'chars': chars,
        })
    return image_base, sections


def va_to_offset(sections, image_base, va):
    """Convert virtual address to file offset. Returns None if unmapped."""
    rva = va - image_base
    for s in sections:
        if s['va'] <= rva < s['va'] + s['vsz']:
            return rva - s['va'] + s['raw']
    return None


def offset_to_va(sections, image_base, file_off):
    """Convert file offset to virtual address. Returns None if unmapped."""
    for s in sections:
        if s['raw'] <= file_off < s['raw'] + s['rawsz']:
            return image_base + s['va'] + (file_off - s['raw'])
    return None


def get_executable_sections(data, image_base, sections):
    """Return list of (raw_offset, raw_size, section_va) for code sections."""
    result = []
    for s in sections:
        if s['chars'] & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            result.append((s['raw'], s['rawsz'], image_base + s['va']))
    return result


def get_data_sections(data, image_base, sections):
    """Return list of (raw_offset, raw_size, section_va) for data sections."""
    result = []
    for s in sections:
        if s['chars'] & 0x40000000 and not (s['chars'] & 0x20000000):
            result.append((s['raw'], s['rawsz'], image_base + s['va']))
    return result


def find_text_section(data, image_base, sections):
    """Return (raw_offset, raw_size, section_va) for first executable section."""
    for s in sections:
        if s['chars'] & 0x20000000:
            return s['raw'], s['rawsz'], image_base + s['va']
    return None, None, None


# ═══════════════════════════════════════════════════════════════════════
# Pattern Scanning
# ═══════════════════════════════════════════════════════════════════════

# Register encodings for ModRM byte
_CALL_REGS_DWORD = {0x90: 'eax', 0x91: 'ecx', 0x92: 'edx', 0x93: 'ebx',
                    0x96: 'esi', 0x97: 'edi'}
_CALL_REGS_BYTE = {0x50: 'eax', 0x51: 'ecx', 0x52: 'edx', 0x53: 'ebx',
                   0x55: 'ebp', 0x56: 'esi', 0x57: 'edi'}
_GP_REGS = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}


def scan_vtable_calls(text_data, text_va, vtable_offset):
    """Find call [reg+vtable_offset] patterns (disp32).

    Returns: [(va, reg_name), ...]
    """
    results = []
    offset_bytes = struct.pack('<I', vtable_offset)
    for mod_rm, reg_name in _CALL_REGS_DWORD.items():
        pattern = bytes([0xFF, mod_rm]) + offset_bytes
        pos = 0
        while True:
            idx = text_data.find(pattern, pos)
            if idx == -1:
                break
            results.append((text_va + idx, reg_name))
            pos = idx + 1
    results.sort()
    return results


def scan_vtable_calls_byte(text_data, text_va, vtable_offset):
    """Find call [reg+vtable_offset] patterns (disp8, offset <= 0x7F).

    Returns: [(va, reg_name), ...]
    """
    if vtable_offset > 0x7F:
        return []
    results = []
    for mod_rm, reg_name in _CALL_REGS_BYTE.items():
        pattern = bytes([0xFF, mod_rm, vtable_offset])
        pos = 0
        while True:
            idx = text_data.find(pattern, pos)
            if idx == -1:
                break
            results.append((text_va + idx, reg_name))
            pos = idx + 1
    results.sort()
    return results


def scan_vtable_mov(text_data, text_va, vtable_offset):
    """Find mov reg, [reg+vtable_offset] patterns (disp32).

    Returns: [(va, description), ...]
    """
    results = []
    offset_bytes = struct.pack('<I', vtable_offset)
    for src_idx, src_name in _GP_REGS.items():
        for dst_idx, dst_name in _GP_REGS.items():
            modrm = 0x80 | (dst_idx << 3) | src_idx
            pattern = bytes([0x8B, modrm]) + offset_bytes
            pos = 0
            while True:
                idx = text_data.find(pattern, pos)
                if idx == -1:
                    break
                results.append((text_va + idx,
                                f"mov {dst_name}, [{src_name}+0x{vtable_offset:03X}]"))
                pos = idx + 1
    results.sort()
    return results


def scan_all_patterns(text_data, text_va, vtable_offset):
    """Find call and mov patterns for a vtable offset (disp8 + disp32).

    Returns: [(va, description), ...]
    """
    results = []

    # call [reg+disp8]
    if vtable_offset <= 0x7F:
        for va, reg in scan_vtable_calls_byte(text_data, text_va, vtable_offset):
            results.append((va, f"call [{reg}+0x{vtable_offset:02X}]"))

    # call [reg+disp32]
    for va, reg in scan_vtable_calls(text_data, text_va, vtable_offset):
        results.append((va, f"call [{reg}+0x{vtable_offset:03X}]"))

    # mov reg, [reg+disp32]
    results.extend(scan_vtable_mov(text_data, text_va, vtable_offset))

    results.sort()
    return results


def analyze_pushes(data, sections, image_base, call_va, window=40):
    """Scan backwards from call_va for push imm8/imm32 instructions.

    Returns: [(push_va, value, type_str), ...] oldest-first.
    type_str is 'imm8' or 'imm32'.
    """
    file_off = va_to_offset(sections, image_base, call_va)
    if file_off is None:
        return []
    context_start = max(0, file_off - window)
    context = data[context_start:file_off + 6]
    pushes = []
    i = 0
    while i < len(context) - 6:
        b = context[i]
        if b == 0x6A:  # push imm8
            val = context[i + 1]
            push_va = call_va - (file_off - context_start - i)
            pushes.append((push_va, val, 'imm8'))
            i += 2
        elif b == 0x68:  # push imm32
            val = struct.unpack_from('<I', context, i + 1)[0]
            push_va = call_va - (file_off - context_start - i)
            pushes.append((push_va, val, 'imm32'))
            i += 5
        else:
            i += 1
    return pushes


def find_push_addr_near_call(data, sections, image_base, call_va, window=60):
    """Find push imm32 instructions near a call that point to valid addresses.

    Returns: [(push_va, target_va), ...] oldest-first.
    """
    pushes = analyze_pushes(data, sections, image_base, call_va, window)
    results = []
    for pva, val, ptype in pushes:
        if ptype == 'imm32':
            off = va_to_offset(sections, image_base, val)
            if off is not None:
                results.append((pva, val))
    return results


# ═══════════════════════════════════════════════════════════════════════
# Standard CLI Setup
# ═══════════════════════════════════════════════════════════════════════

def load_binary(path):
    """Read binary + parse PE. Returns (data, image_base, sections)."""
    from pathlib import Path
    data = Path(path).read_bytes()
    image_base, sections = parse_pe(data)
    return data, image_base, sections


def load_text_section(data, image_base, sections):
    """Load first executable section. Returns (text_data, text_va) or exits."""
    import sys
    raw_start, raw_size, text_va = find_text_section(data, image_base, sections)
    if raw_start is None:
        print("ERROR: no executable section found")
        sys.exit(1)
    return data[raw_start:raw_start + raw_size], text_va


def print_header(data, image_base, sections):
    """Print standard binary info header."""
    _, _, text_va = find_text_section(data, image_base, sections)
    print(f"ImageBase: 0x{image_base:08X}")
    if text_va:
        print(f"Executable section VA: 0x{text_va:08X}")


# ═══════════════════════════════════════════════════════════════════════
# IDirect3DDevice9 Vtable (32-bit, offset = slot * 4)
# ═══════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════
# D3DRENDERSTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DRS = {
    7: "ZENABLE", 8: "FILLMODE", 9: "SHADEMODE",
    14: "ZWRITEENABLE", 15: "ALPHATESTENABLE",
    19: "LASTPIXEL", 20: "SRCBLEND", 21: "DESTBLEND",
    22: "CULLMODE", 23: "ZFUNC", 24: "ALPHAREF", 25: "ALPHAFUNC",
    26: "DITHERENABLE", 27: "ALPHABLENDENABLE",
    28: "FOGENABLE", 29: "SPECULARENABLE",
    34: "FOGCOLOR", 35: "FOGTABLEMODE",
    36: "FOGSTART", 37: "FOGEND", 38: "FOGDENSITY",
    48: "RANGEFOGENABLE",
    128: "STENCILENABLE", 129: "STENCILFAIL", 130: "STENCILZFAIL",
    131: "STENCILPASS", 132: "STENCILFUNC",
    133: "STENCILREF", 134: "STENCILMASK", 135: "STENCILWRITEMASK",
    136: "TEXTUREFACTOR",
    137: "WRAP0", 138: "WRAP1", 139: "WRAP2", 140: "WRAP3",
    141: "WRAP4", 142: "WRAP5", 143: "WRAP6", 144: "WRAP7",
    154: "CLIPPING", 155: "LIGHTING",
    157: "AMBIENT", 158: "FOGVERTEXMODE",
    159: "COLORVERTEX", 160: "LOCALVIEWER", 161: "NORMALIZENORMALS",
    162: "DIFFUSEMATERIALSOURCE", 163: "SPECULARMATERIALSOURCE",
    164: "AMBIENTMATERIALSOURCE", 165: "EMISSIVEMATERIALSOURCE",
    168: "VERTEXBLEND", 169: "CLIPPLANEENABLE",
    174: "POINTSIZE", 175: "POINTSIZE_MIN",
    176: "POINTSPRITEENABLE", 177: "POINTSCALEENABLE",
    178: "POINTSCALE_A", 179: "POINTSCALE_B", 180: "POINTSCALE_C",
    181: "MULTISAMPLEANTIALIAS", 182: "MULTISAMPLEMASK",
    183: "PATCHEDGESTYLE", 184: "DEBUGMONITORTOKEN",
    185: "POINTSIZE_MAX", 186: "INDEXEDVERTEXBLENDENABLE",
    187: "COLORWRITEENABLE",
    189: "TWEENFACTOR", 190: "BLENDOP",
    191: "POSITIONDEGREE", 192: "NORMALDEGREE",
    194: "SCISSORTESTENABLE", 195: "SLOPESCALEDEPTHBIAS",
    196: "ANTIALIASEDLINEENABLE",
    198: "MINTESSELLATIONLEVEL", 199: "MAXTESSELLATIONLEVEL",
    200: "ADAPTIVETESS_X", 201: "ADAPTIVETESS_Y",
    202: "ADAPTIVETESS_Z", 203: "ADAPTIVETESS_W",
    204: "ENABLEADAPTIVETESSELLATION",
    205: "TWOSIDEDSTENCILMODE",
    206: "CCW_STENCILFAIL", 207: "CCW_STENCILZFAIL",
    208: "CCW_STENCILPASS", 209: "CCW_STENCILFUNC",
    210: "COLORWRITEENABLE1", 211: "COLORWRITEENABLE2",
    212: "COLORWRITEENABLE3", 213: "BLENDFACTOR",
    214: "SRGBWRITEENABLE", 215: "DEPTHBIAS",
    221: "WRAP8", 222: "WRAP9", 223: "WRAP10", 224: "WRAP11",
    225: "WRAP12", 226: "WRAP13", 227: "WRAP14", 228: "WRAP15",
    230: "SEPARATEALPHABLENDENABLE",
    231: "SRCBLENDALPHA", 232: "DESTBLENDALPHA", 233: "BLENDOPALPHA",
}

# Render state value sub-enums (for decoding the Value argument)
D3DZBUFFERTYPE = {0: "D3DZB_FALSE", 1: "D3DZB_TRUE", 2: "D3DZB_USEW"}
D3DFILLMODE = {1: "POINT", 2: "WIREFRAME", 3: "SOLID"}
D3DSHADEMODE = {1: "FLAT", 2: "GOURAUD", 3: "PHONG"}
D3DBLEND = {
    0: "ZERO", 1: "ONE", 2: "SRCCOLOR", 3: "INVSRCCOLOR",
    4: "SRCALPHA", 5: "INVSRCALPHA", 6: "DESTALPHA", 7: "INVDESTALPHA",
    8: "DESTCOLOR", 9: "INVDESTCOLOR", 10: "SRCALPHASAT",
    11: "BOTHSRCALPHA", 12: "BOTHINVSRCALPHA",
    13: "BLENDFACTOR", 14: "INVBLENDFACTOR",
    15: "SRCCOLOR2", 16: "INVSRCCOLOR2",
}
D3DCMPFUNC = {
    1: "NEVER", 2: "LESS", 3: "EQUAL", 4: "LESSEQUAL",
    5: "GREATER", 6: "NOTEQUAL", 7: "GREATEREQUAL", 8: "ALWAYS",
}
D3DCULL = {1: "NONE", 2: "CW", 3: "CCW"}
D3DFOGMODE = {0: "NONE", 1: "EXP", 2: "EXP2", 3: "LINEAR"}
D3DSTENCILOP = {
    1: "KEEP", 2: "ZERO", 3: "REPLACE", 4: "INCRSAT",
    5: "DECRSAT", 6: "INVERT", 7: "INCR", 8: "DECR",
}
D3DBLENDOP = {1: "ADD", 2: "SUBTRACT", 3: "REVSUBTRACT", 4: "MIN", 5: "MAX"}
D3DMATERIALCOLORSOURCE = {0: "MATERIAL", 1: "COLOR1", 2: "COLOR2"}
D3DVERTEXBLENDFLAGS = {
    0: "DISABLE", 1: "1WEIGHTS", 2: "2WEIGHTS", 3: "3WEIGHTS", 255: "TWEENING",
}

# Map render state -> value decoder
RS_VALUE_DECODERS = {
    7: D3DZBUFFERTYPE,        # ZENABLE
    8: D3DFILLMODE,           # FILLMODE
    9: D3DSHADEMODE,          # SHADEMODE
    20: D3DBLEND,             # SRCBLEND
    21: D3DBLEND,             # DESTBLEND
    22: D3DCULL,              # CULLMODE
    23: D3DCMPFUNC,           # ZFUNC
    25: D3DCMPFUNC,           # ALPHAFUNC
    35: D3DFOGMODE,           # FOGTABLEMODE
    129: D3DSTENCILOP,        # STENCILFAIL
    130: D3DSTENCILOP,        # STENCILZFAIL
    131: D3DSTENCILOP,        # STENCILPASS
    132: D3DCMPFUNC,          # STENCILFUNC
    158: D3DFOGMODE,          # FOGVERTEXMODE
    162: D3DMATERIALCOLORSOURCE,  # DIFFUSEMATERIALSOURCE
    163: D3DMATERIALCOLORSOURCE,  # SPECULARMATERIALSOURCE
    164: D3DMATERIALCOLORSOURCE,  # AMBIENTMATERIALSOURCE
    165: D3DMATERIALCOLORSOURCE,  # EMISSIVEMATERIALSOURCE
    168: D3DVERTEXBLENDFLAGS, # VERTEXBLEND
    190: D3DBLENDOP,          # BLENDOP
    206: D3DSTENCILOP,        # CCW_STENCILFAIL
    207: D3DSTENCILOP,        # CCW_STENCILZFAIL
    208: D3DSTENCILOP,        # CCW_STENCILPASS
    209: D3DCMPFUNC,          # CCW_STENCILFUNC
    231: D3DBLEND,            # SRCBLENDALPHA
    232: D3DBLEND,            # DESTBLENDALPHA
    233: D3DBLENDOP,          # BLENDOPALPHA
}

# Boolean render states (value is 0/1 = FALSE/TRUE)
RS_BOOL_STATES = {
    14, 15, 19, 26, 27, 28, 29, 48, 128, 154, 155, 159, 160, 161,
    176, 177, 181, 186, 194, 196, 204, 205, 214, 230,
}


def decode_rs_value(state_id, value):
    """Decode a render state value to a human-readable string."""
    if state_id in RS_VALUE_DECODERS:
        decoder = RS_VALUE_DECODERS[state_id]
        return decoder.get(value, f"0x{value:X}")
    if state_id in RS_BOOL_STATES:
        return "TRUE" if value else "FALSE"
    # FOGCOLOR, AMBIENT, TEXTUREFACTOR — decode as D3DCOLOR
    if state_id in (34, 157, 136):
        return f"ARGB(0x{value:08X})"
    return str(value)


# ═══════════════════════════════════════════════════════════════════════
# D3DTEXTURESTAGESTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DTSS = {
    1: "COLOROP", 2: "COLORARG1", 3: "COLORARG2",
    4: "ALPHAOP", 5: "ALPHAARG1", 6: "ALPHAARG2",
    7: "BUMPENVMAT00", 8: "BUMPENVMAT01",
    9: "BUMPENVMAT10", 10: "BUMPENVMAT11",
    11: "TEXCOORDINDEX",
    22: "BUMPENVLSCALE", 23: "BUMPENVLOFFSET",
    24: "TEXTURETRANSFORMFLAGS",
    26: "COLORARG0", 27: "ALPHAARG0",
    28: "RESULTARG", 32: "CONSTANT",
}

D3DTEXTUREOP = {
    1: "DISABLE", 2: "SELECTARG1", 3: "SELECTARG2",
    4: "MODULATE", 5: "MODULATE2X", 6: "MODULATE4X",
    7: "ADD", 8: "ADDSIGNED", 9: "ADDSIGNED2X",
    10: "SUBTRACT", 11: "ADDSMOOTH",
    12: "BLENDDIFFUSEALPHA", 13: "BLENDTEXTUREALPHA",
    14: "BLENDFACTORALPHA", 15: "BLENDTEXTUREALPHAPM",
    16: "BLENDCURRENTALPHA", 17: "PREMODULATE",
    18: "MODULATEALPHA_ADDCOLOR", 19: "MODULATECOLOR_ADDALPHA",
    20: "MODULATEINVALPHA_ADDCOLOR", 21: "MODULATEINVCOLOR_ADDALPHA",
    22: "BUMPENVMAP", 23: "BUMPENVMAPLUMINANCE",
    24: "DOTPRODUCT3", 25: "MULTIPLYADD", 26: "LERP",
}

D3DTA = {
    0x00: "DIFFUSE", 0x01: "CURRENT", 0x02: "TEXTURE",
    0x03: "TFACTOR", 0x04: "SPECULAR", 0x05: "TEMP", 0x06: "CONSTANT",
}
D3DTA_COMPLEMENT = 0x10
D3DTA_ALPHAREPLICATE = 0x20


def decode_texture_arg(val):
    """Decode a D3DTA_* argument value to string."""
    base = val & 0x0F
    name = D3DTA.get(base, f"0x{base:X}")
    mods = []
    if val & D3DTA_COMPLEMENT:
        mods.append("COMPLEMENT")
    if val & D3DTA_ALPHAREPLICATE:
        mods.append("ALPHAREPLICATE")
    if mods:
        return f"{name} | {'|'.join(mods)}"
    return name


D3DTEXTURETRANSFORMFLAGS = {
    0: "DISABLE", 1: "COUNT1", 2: "COUNT2", 3: "COUNT3", 4: "COUNT4",
    256: "PROJECTED",
}

# Map TSS type -> value decoder
TSS_VALUE_DECODERS = {
    1: D3DTEXTUREOP,    # COLOROP
    4: D3DTEXTUREOP,    # ALPHAOP
}
TSS_ARG_STATES = {2, 3, 5, 6, 26, 27, 28}  # COLORARG1/2, ALPHAARG1/2, ARG0, RESULTARG


def decode_tss_value(state_id, value):
    """Decode a texture stage state value."""
    if state_id in TSS_VALUE_DECODERS:
        return TSS_VALUE_DECODERS[state_id].get(value, f"0x{value:X}")
    if state_id in TSS_ARG_STATES:
        return decode_texture_arg(value)
    if state_id == 11:  # TEXCOORDINDEX
        tci = value >> 16
        idx = value & 0xFFFF
        tci_names = {0: "PASSTHRU", 1: "CAMERASPACENORMAL",
                     2: "CAMERASPACEPOSITION", 3: "CAMERASPACEREFLECTIONVECTOR"}
        return f"{tci_names.get(tci, f'TCI(0x{tci:X})')}, index={idx}"
    if state_id == 24:  # TEXTURETRANSFORMFLAGS
        proj = " | PROJECTED" if value & 256 else ""
        count = value & 0xFF
        return D3DTEXTURETRANSFORMFLAGS.get(count, f"COUNT({count})") + proj
    return str(value)


# ═══════════════════════════════════════════════════════════════════════
# D3DSAMPLERSTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DSAMP = {
    1: "ADDRESSU", 2: "ADDRESSV", 3: "ADDRESSW",
    4: "BORDERCOLOR", 5: "MAGFILTER", 6: "MINFILTER", 7: "MIPFILTER",
    8: "MIPMAPLODBIAS", 9: "MAXMIPLEVEL", 10: "MAXANISOTROPY",
    11: "SRGBTEXTURE", 12: "ELEMENTINDEX", 13: "DMAPOFFSET",
}

D3DTEXF = {0: "NONE", 1: "POINT", 2: "LINEAR", 3: "ANISOTROPIC",
           4: "PYRAMIDALQUAD", 5: "GAUSSIANQUAD"}
D3DTADDRESS = {1: "WRAP", 2: "MIRROR", 3: "CLAMP", 4: "BORDER", 5: "MIRRORONCE"}

SAMP_VALUE_DECODERS = {
    1: D3DTADDRESS, 2: D3DTADDRESS, 3: D3DTADDRESS,  # ADDRESSU/V/W
    5: D3DTEXF, 6: D3DTEXF, 7: D3DTEXF,              # MAG/MIN/MIP FILTER
}
SAMP_BOOL_STATES = {11}  # SRGBTEXTURE


def decode_samp_value(state_id, value):
    """Decode a sampler state value."""
    if state_id in SAMP_VALUE_DECODERS:
        return SAMP_VALUE_DECODERS[state_id].get(value, f"0x{value:X}")
    if state_id in SAMP_BOOL_STATES:
        return "TRUE" if value else "FALSE"
    if state_id == 4:  # BORDERCOLOR
        return f"ARGB(0x{value:08X})"
    return str(value)


# ═══════════════════════════════════════════════════════════════════════
# D3DTRANSFORMSTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DTS = {
    2: "VIEW", 3: "PROJECTION",
    16: "TEXTURE0", 17: "TEXTURE1", 18: "TEXTURE2", 19: "TEXTURE3",
    20: "TEXTURE4", 21: "TEXTURE5", 22: "TEXTURE6", 23: "TEXTURE7",
    256: "WORLD",  # D3DTS_WORLDMATRIX(0)
}


def decode_transform_type(val):
    """Decode a D3DTRANSFORMSTATETYPE value."""
    if val in D3DTS:
        return D3DTS[val]
    if 256 <= val < 512:
        return f"WORLDMATRIX({val - 256})"
    return f"UNKNOWN(0x{val:X})"


# ═══════════════════════════════════════════════════════════════════════
# D3DFORMAT
# ═══════════════════════════════════════════════════════════════════════

D3DFMT = {
    0: "UNKNOWN",
    20: "R8G8B8", 21: "A8R8G8B8", 22: "X8R8G8B8",
    23: "R5G6B5", 24: "X1R5G5B5", 25: "A1R5G5B5",
    26: "A4R4G4B4", 27: "R3G3B2", 28: "A8",
    29: "A8R3G3B2", 30: "X4R4G4B4",
    31: "A2B10G10R10", 32: "A8B8G8R8", 33: "X8B8G8R8",
    34: "G16R16", 35: "A2R10G10B10", 36: "A16B16G16R16",
    40: "A8P8", 41: "P8",
    50: "L8", 51: "A8L8", 52: "A4L4",
    60: "V8U8", 61: "L6V5U5", 62: "X8L8V8U8",
    63: "Q8W8V8U8", 64: "V16U16", 67: "A2W10V10U10",
    70: "D16_LOCKABLE", 71: "D32", 73: "D15S1",
    75: "D24S8", 77: "D24X8", 79: "D24X4S4",
    80: "D16", 81: "L16",
    82: "D32F_LOCKABLE", 83: "D24FS8",
    84: "D32_LOCKABLE", 85: "S8_LOCKABLE",
    100: "VERTEXDATA", 101: "INDEX16", 102: "INDEX32",
    110: "Q16W16V16U16",
    111: "R16F", 112: "G16R16F", 113: "A16B16G16R16F",
    114: "R32F", 115: "G32R32F", 116: "A32B32G32R32F",
    117: "CxV8U8",
    # FourCC formats
    0x31545844: "DXT1", 0x32545844: "DXT2", 0x33545844: "DXT3",
    0x34545844: "DXT4", 0x35545844: "DXT5",
    0x59565955: "UYVY", 0x32595559: "YUY2",
    0x47424752: "R8G8_B8G8", 0x42475247: "G8R8_G8B8",
    0x3154454D: "MULTI2_ARGB8",
    # NVIDIA specific
    0x34324E49: "INTZ",  # shadow map depth
    0x46313152: "R1F",   # raw
}


def decode_format(val):
    """Decode D3DFORMAT value."""
    if val in D3DFMT:
        return D3DFMT[val]
    # Try as FourCC
    if val > 0xFF:
        try:
            cc = struct.pack('<I', val).decode('ascii', errors='replace')
            return f"FourCC('{cc}')"
        except Exception:
            pass
    return f"UNKNOWN(0x{val:X})"


# ═══════════════════════════════════════════════════════════════════════
# D3DFVF flags
# ═══════════════════════════════════════════════════════════════════════

D3DFVF_POSITION_MASK = 0x400E

D3DFVF_POSITIONS = {
    0x002: "XYZ", 0x004: "XYZRHW", 0x006: "XYZB1",
    0x008: "XYZB2", 0x00A: "XYZB3", 0x00C: "XYZB4",
    0x00E: "XYZB5", 0x4002: "XYZW",
}

D3DFVF_FLAGS = {
    0x010: "NORMAL", 0x020: "PSIZE",
    0x040: "DIFFUSE", 0x080: "SPECULAR",
}

D3DFVF_TEXCOUNT_SHIFT = 8
D3DFVF_TEXCOUNT_MASK = 0xF00
D3DFVF_LASTBETA_UBYTE4 = 0x1000
D3DFVF_LASTBETA_D3DCOLOR = 0x8000

# Per-texcoord size encoding (bits 16-31, 2 bits per coord)
D3DFVF_TEXCOORDSIZE = {0: "FLOAT2", 1: "FLOAT3", 2: "FLOAT4", 3: "FLOAT1"}

# Size in bytes for each position type
_FVF_POS_SIZES = {
    0x002: 12, 0x004: 16, 0x006: 16, 0x008: 20,
    0x00A: 24, 0x00C: 28, 0x00E: 32, 0x4002: 16,
}
_FVF_TEXCOORD_SIZES = {0: 8, 1: 12, 2: 16, 3: 4}


def decode_fvf(fvf):
    """Decode FVF flags into components and compute stride.

    Returns: (components: list[str], stride: int, tex_count: int)
    """
    components = []
    stride = 0

    # Position
    pos = fvf & D3DFVF_POSITION_MASK
    pos_name = D3DFVF_POSITIONS.get(pos)
    if pos_name:
        components.append(pos_name)
        stride += _FVF_POS_SIZES.get(pos, 0)

    if fvf & D3DFVF_LASTBETA_UBYTE4:
        components.append("LASTBETA_UBYTE4")
    if fvf & D3DFVF_LASTBETA_D3DCOLOR:
        components.append("LASTBETA_D3DCOLOR")

    # Fixed flags
    for bit, name in D3DFVF_FLAGS.items():
        if fvf & bit:
            components.append(name)
            if bit == 0x010:
                stride += 12  # NORMAL = 3 floats
            elif bit == 0x020:
                stride += 4   # PSIZE = 1 float
            elif bit in (0x040, 0x080):
                stride += 4   # DIFFUSE/SPECULAR = D3DCOLOR

    # Texture coordinates
    tex_count = (fvf & D3DFVF_TEXCOUNT_MASK) >> D3DFVF_TEXCOUNT_SHIFT
    if tex_count > 0:
        components.append(f"TEX{tex_count}")
        for i in range(tex_count):
            tc_bits = (fvf >> (16 + i * 2)) & 0x3
            tc_name = D3DFVF_TEXCOORDSIZE[tc_bits]
            if tc_bits != 0:  # Non-default (not FLOAT2)
                components.append(f"  TC{i}={tc_name}")
            stride += _FVF_TEXCOORD_SIZES[tc_bits]

    return components, stride, tex_count


# ═══════════════════════════════════════════════════════════════════════
# D3DSTATEBLOCKTYPE
# ═══════════════════════════════════════════════════════════════════════

D3DSTATEBLOCKTYPE = {1: "ALL", 2: "PIXELSTATE", 3: "VERTEXSTATE"}


# ═══════════════════════════════════════════════════════════════════════
# D3DPRIMITIVETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DPRIMTYPE = {
    1: "POINTLIST", 2: "LINELIST", 3: "LINESTRIP",
    4: "TRIANGLELIST", 5: "TRIANGLESTRIP", 6: "TRIANGLEFAN",
}


# ═══════════════════════════════════════════════════════════════════════
# D3DPOOL
# ═══════════════════════════════════════════════════════════════════════

D3DPOOL = {0: "DEFAULT", 1: "MANAGED", 2: "SYSTEMMEM", 3: "SCRATCH"}


# ═══════════════════════════════════════════════════════════════════════
# Shader bytecode helpers
# ═══════════════════════════════════════════════════════════════════════

def validate_shader_token(data, offset):
    """Check if offset points to valid shader bytecode.

    Returns: (shader_type, major, minor) or None.
    shader_type is 'vs' or 'ps'.
    """
    if offset + 4 > len(data):
        return None
    token = struct.unpack_from('<I', data, offset)[0]
    shader_type_bits = (token >> 16) & 0xFFFF
    major = (token >> 8) & 0xFF
    minor = token & 0xFF
    if shader_type_bits == 0xFFFE and 1 <= major <= 3:
        return ('vs', major, minor)
    if shader_type_bits == 0xFFFF and 1 <= major <= 3:
        return ('ps', major, minor)
    return None


def find_shader_end(data, offset, max_scan=65536):
    """Find the END token (0x0000FFFF) in shader bytecode.

    Returns byte length including end token, or None.
    """
    end = min(offset + max_scan, len(data) - 3)
    pos = offset + 4  # skip version token
    while pos < end:
        token = struct.unpack_from('<I', data, pos)[0]
        if token == 0x0000FFFF:
            return (pos + 4) - offset
        pos += 4
    return None
