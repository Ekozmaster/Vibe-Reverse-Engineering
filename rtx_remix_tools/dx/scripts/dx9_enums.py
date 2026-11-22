"""D3D9 method names and enums, with the decoders the scripts turn call arguments into text with."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from graphics.directx.dx9.tracer.d3d9_methods import D3D9_METHODS


# ═══════════════════════════════════════════════════════════════════════
# IDirect3DDevice9 Vtable (32-bit, offset = slot * 4)
# ═══════════════════════════════════════════════════════════════════════

D3D9_DEVICE_VTABLE = {spec.slot * 4: spec.name for spec in D3D9_METHODS.values()}


# ═══════════════════════════════════════════════════════════════════════
# D3DRENDERSTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DRS = {
    7: "ZENABLE", 8: "FILLMODE", 9: "SHADEMODE",
    14: "ZWRITEENABLE", 15: "ALPHATESTENABLE", 16: "LASTPIXEL",
    19: "SRCBLEND", 20: "DESTBLEND",
    22: "CULLMODE", 23: "ZFUNC", 24: "ALPHAREF", 25: "ALPHAFUNC",
    26: "DITHERENABLE", 27: "ALPHABLENDENABLE",
    28: "FOGENABLE", 29: "SPECULARENABLE",
    34: "FOGCOLOR", 35: "FOGTABLEMODE",
    36: "FOGSTART", 37: "FOGEND", 38: "FOGDENSITY",
    48: "RANGEFOGENABLE",
    52: "STENCILENABLE", 53: "STENCILFAIL", 54: "STENCILZFAIL",
    55: "STENCILPASS", 56: "STENCILFUNC",
    57: "STENCILREF", 58: "STENCILMASK", 59: "STENCILWRITEMASK",
    60: "TEXTUREFACTOR",
    128: "WRAP0", 129: "WRAP1", 130: "WRAP2", 131: "WRAP3",
    132: "WRAP4", 133: "WRAP5", 134: "WRAP6", 135: "WRAP7",
    136: "CLIPPING", 137: "LIGHTING",
    139: "AMBIENT", 140: "FOGVERTEXMODE",
    141: "COLORVERTEX", 142: "LOCALVIEWER", 143: "NORMALIZENORMALS",
    145: "DIFFUSEMATERIALSOURCE", 146: "SPECULARMATERIALSOURCE",
    147: "AMBIENTMATERIALSOURCE", 148: "EMISSIVEMATERIALSOURCE",
    151: "VERTEXBLEND", 152: "CLIPPLANEENABLE",
    154: "POINTSIZE", 155: "POINTSIZE_MIN",
    156: "POINTSPRITEENABLE", 157: "POINTSCALEENABLE",
    158: "POINTSCALE_A", 159: "POINTSCALE_B", 160: "POINTSCALE_C",
    161: "MULTISAMPLEANTIALIAS", 162: "MULTISAMPLEMASK",
    163: "PATCHEDGESTYLE", 165: "DEBUGMONITORTOKEN",
    166: "POINTSIZE_MAX", 167: "INDEXEDVERTEXBLENDENABLE",
    168: "COLORWRITEENABLE",
    170: "TWEENFACTOR", 171: "BLENDOP",
    172: "POSITIONDEGREE", 173: "NORMALDEGREE",
    174: "SCISSORTESTENABLE", 175: "SLOPESCALEDEPTHBIAS",
    176: "ANTIALIASEDLINEENABLE",
    178: "MINTESSELLATIONLEVEL", 179: "MAXTESSELLATIONLEVEL",
    180: "ADAPTIVETESS_X", 181: "ADAPTIVETESS_Y",
    182: "ADAPTIVETESS_Z", 183: "ADAPTIVETESS_W",
    184: "ENABLEADAPTIVETESSELLATION",
    185: "TWOSIDEDSTENCILMODE",
    186: "CCW_STENCILFAIL", 187: "CCW_STENCILZFAIL",
    188: "CCW_STENCILPASS", 189: "CCW_STENCILFUNC",
    190: "COLORWRITEENABLE1", 191: "COLORWRITEENABLE2",
    192: "COLORWRITEENABLE3", 193: "BLENDFACTOR",
    194: "SRGBWRITEENABLE", 195: "DEPTHBIAS",
    198: "WRAP8", 199: "WRAP9", 200: "WRAP10", 201: "WRAP11",
    202: "WRAP12", 203: "WRAP13", 204: "WRAP14", 205: "WRAP15",
    206: "SEPARATEALPHABLENDENABLE",
    207: "SRCBLENDALPHA", 208: "DESTBLENDALPHA", 209: "BLENDOPALPHA",
}

# Render state value sub-enums (for decoding the Value argument)
D3DZBUFFERTYPE = {0: "D3DZB_FALSE", 1: "D3DZB_TRUE", 2: "D3DZB_USEW"}
D3DFILLMODE = {1: "POINT", 2: "WIREFRAME", 3: "SOLID"}
D3DSHADEMODE = {1: "FLAT", 2: "GOURAUD", 3: "PHONG"}
D3DBLEND = {
    1: "ZERO", 2: "ONE", 3: "SRCCOLOR", 4: "INVSRCCOLOR",
    5: "SRCALPHA", 6: "INVSRCALPHA", 7: "DESTALPHA", 8: "INVDESTALPHA",
    9: "DESTCOLOR", 10: "INVDESTCOLOR", 11: "SRCALPHASAT",
    12: "BOTHSRCALPHA", 13: "BOTHINVSRCALPHA",
    14: "BLENDFACTOR", 15: "INVBLENDFACTOR",
    16: "SRCCOLOR2", 17: "INVSRCCOLOR2",
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

# Tables that refer to render states name them and resolve the id here, so a
# state's id is written down in exactly one place.
D3DRS_ID = {name: state_id for state_id, name in D3DRS.items()}

_RS_VALUE_DECODERS_BY_NAME = {
    "ZENABLE": D3DZBUFFERTYPE,
    "FILLMODE": D3DFILLMODE,
    "SHADEMODE": D3DSHADEMODE,
    "SRCBLEND": D3DBLEND,
    "DESTBLEND": D3DBLEND,
    "CULLMODE": D3DCULL,
    "ZFUNC": D3DCMPFUNC,
    "ALPHAFUNC": D3DCMPFUNC,
    "FOGTABLEMODE": D3DFOGMODE,
    "STENCILFAIL": D3DSTENCILOP,
    "STENCILZFAIL": D3DSTENCILOP,
    "STENCILPASS": D3DSTENCILOP,
    "STENCILFUNC": D3DCMPFUNC,
    "FOGVERTEXMODE": D3DFOGMODE,
    "DIFFUSEMATERIALSOURCE": D3DMATERIALCOLORSOURCE,
    "SPECULARMATERIALSOURCE": D3DMATERIALCOLORSOURCE,
    "AMBIENTMATERIALSOURCE": D3DMATERIALCOLORSOURCE,
    "EMISSIVEMATERIALSOURCE": D3DMATERIALCOLORSOURCE,
    "VERTEXBLEND": D3DVERTEXBLENDFLAGS,
    "BLENDOP": D3DBLENDOP,
    "CCW_STENCILFAIL": D3DSTENCILOP,
    "CCW_STENCILZFAIL": D3DSTENCILOP,
    "CCW_STENCILPASS": D3DSTENCILOP,
    "CCW_STENCILFUNC": D3DCMPFUNC,
    "SRCBLENDALPHA": D3DBLEND,
    "DESTBLENDALPHA": D3DBLEND,
    "BLENDOPALPHA": D3DBLENDOP,
}

# Map render state -> value decoder
RS_VALUE_DECODERS = {
    D3DRS_ID[name]: decoder for name, decoder in _RS_VALUE_DECODERS_BY_NAME.items()
}

# Boolean render states (value is 0/1 = FALSE/TRUE)
RS_BOOL_STATES = {D3DRS_ID[name] for name in (
    "ZWRITEENABLE", "ALPHATESTENABLE", "LASTPIXEL", "DITHERENABLE",
    "ALPHABLENDENABLE", "FOGENABLE", "SPECULARENABLE", "RANGEFOGENABLE",
    "STENCILENABLE", "CLIPPING", "LIGHTING", "COLORVERTEX", "LOCALVIEWER",
    "NORMALIZENORMALS", "POINTSPRITEENABLE", "POINTSCALEENABLE",
    "MULTISAMPLEANTIALIAS", "INDEXEDVERTEXBLENDENABLE", "SCISSORTESTENABLE",
    "ANTIALIASEDLINEENABLE", "ENABLEADAPTIVETESSELLATION",
    "TWOSIDEDSTENCILMODE", "SRGBWRITEENABLE", "SEPARATEALPHABLENDENABLE",
)}

# Render states whose value is a D3DCOLOR
RS_COLOR_STATES = {D3DRS_ID[name] for name in (
    "FOGCOLOR", "TEXTUREFACTOR", "AMBIENT", "BLENDFACTOR",
)}


def decode_rs_value(state_id, value):
    """Decode a render state value to a human-readable string."""
    if state_id in RS_VALUE_DECODERS:
        decoder = RS_VALUE_DECODERS[state_id]
        return decoder.get(value, f"0x{value:X}")
    if state_id in RS_BOOL_STATES:
        return "TRUE" if value else "FALSE"
    if state_id in RS_COLOR_STATES:
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
           6: "PYRAMIDALQUAD", 7: "GAUSSIANQUAD", 8: "CONVOLUTIONMONO"}
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
    # Driver FourCC, not in d3d9types.h
    0x5A544E49: "INTZ",  # depth buffer readable as a texture
}


def decode_format(val):
    """Decode D3DFORMAT value."""
    if val in D3DFMT:
        return D3DFMT[val]
    if 0xFF < val <= 0xFFFFFFFF:
        cc = struct.pack('<I', val).decode('ascii', errors='replace')
        return f"FourCC('{cc}')"
    return f"UNKNOWN(0x{val:X})"


# ═══════════════════════════════════════════════════════════════════════
# D3DVERTEXELEMENT9
# ═══════════════════════════════════════════════════════════════════════

_MAX_STREAM = 4             # games bind few streams; a larger number is other data
_LAST_DECLTYPE = 17         # D3DDECLTYPE_UNUSED
_LAST_DECLUSAGE = 13        # D3DDECLUSAGE_SAMPLE


def is_vertex_element(raw):
    """Whether *raw* starts with a plausible D3DVERTEXELEMENT9: its stream, type and usage are in range.

    Tells the first element of a vertex declaration from other data a
    pointer argument may lead to.
    """
    if len(raw) < 8:
        return False
    stream, _offset, decl_type, _method, usage, _usage_index = struct.unpack_from("<HHBBBB", raw)
    return stream <= _MAX_STREAM and decl_type <= _LAST_DECLTYPE and usage <= _LAST_DECLUSAGE


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
