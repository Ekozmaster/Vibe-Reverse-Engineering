"""IDirect3DDevice9 method signature database, D3D9 constants, and C code generator.

Defines all 119 vtable methods with arg counts, arg names/types,
data reader specs (for pointer-follow in the trace proxy), and
categories for filtering.

Also provides centralized D3D9 enum constants (render states, transform
types, vertex element types/usages, etc.) for both Python analysis and
C codegen.

Codegen usage:
    python -m graphics.directx.dx9.tracer codegen [--output PATH]

Generates d3d9_trace_hooks.inc for #include in d3d9_trace_device.c.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MethodSpec:
    slot: int
    name: str
    argc: int
    args: list[tuple[str, str]]             # [(name, type), ...]
    category: str = "misc"                  # draw, state, shader, resource, transform, misc
    data_readers: dict[str, Any] = field(default_factory=dict)


def _m(slot, name, args, cat="misc", readers=None):
    return MethodSpec(
        slot=slot, name=name, argc=len(args), args=args,
        category=cat, data_readers=readers or {},
    )


# fmt: off
D3D9_METHODS: dict[int, MethodSpec] = {s.slot: s for s in [
    # IUnknown
    _m(0,  "QueryInterface",              [("riid","ptr"),("ppvObj","ptr")]),
    _m(1,  "AddRef",                      []),
    _m(2,  "Release",                     []),
    # Device status
    _m(3,  "TestCooperativeLevel",        []),
    _m(4,  "GetAvailableTextureMem",      []),
    _m(5,  "EvictManagedResources",       []),
    _m(6,  "GetDirect3D",                 [("ppD3D9","ptr")]),
    _m(7,  "GetDeviceCaps",               [("pCaps","ptr")]),
    _m(8,  "GetDisplayMode",              [("iSwapChain","uint32"),("pMode","ptr")]),
    _m(9,  "GetCreationParameters",       [("pParams","ptr")]),
    # Cursor
    _m(10, "SetCursorProperties",         [("XHotSpot","uint32"),("YHotSpot","uint32"),("pCursorBitmap","ptr")]),
    _m(11, "SetCursorPosition",           [("X","int32"),("Y","int32"),("Flags","uint32")]),
    _m(12, "ShowCursor",                  [("bShow","int32")]),
    # Swap chains
    _m(13, "CreateAdditionalSwapChain",   [("pPresentParams","ptr"),("ppSwapChain","ptr")], "resource"),
    _m(14, "GetSwapChain",                [("iSwapChain","uint32"),("ppSwapChain","ptr")]),
    _m(15, "GetNumberOfSwapChains",       []),
    # Reset / Present
    _m(16, "Reset",                       [("pPresentParams","ptr")]),
    _m(17, "Present",                     [("pSrcRect","ptr"),("pDstRect","ptr"),("hDestWnd","ptr"),("pDirtyRgn","ptr")], "draw"),
    # Back buffer
    _m(18, "GetBackBuffer",               [("iSwapChain","uint32"),("iBackBuffer","uint32"),("Type","uint32"),("ppBackBuffer","ptr")]),
    _m(19, "GetRasterStatus",             [("iSwapChain","uint32"),("pRasterStatus","ptr")]),
    _m(20, "SetDialogBoxMode",            [("bEnableDialogs","int32")]),
    _m(21, "SetGammaRamp",                [("iSwapChain","uint32"),("Flags","uint32"),("pRamp","ptr")]),
    _m(22, "GetGammaRamp",                [("iSwapChain","uint32"),("pRamp","ptr")]),
    # Resource creation
    _m(23, "CreateTexture",               [("Width","uint32"),("Height","uint32"),("Levels","uint32"),("Usage","uint32"),("Format","uint32"),("Pool","uint32"),("ppTexture","ptr"),("pSharedHandle","ptr")], "resource"),
    _m(24, "CreateVolumeTexture",         [("Width","uint32"),("Height","uint32"),("Depth","uint32"),("Levels","uint32"),("Usage","uint32"),("Format","uint32"),("Pool","uint32"),("ppVolTex","ptr"),("pSharedHandle","ptr")], "resource"),
    _m(25, "CreateCubeTexture",           [("EdgeLength","uint32"),("Levels","uint32"),("Usage","uint32"),("Format","uint32"),("Pool","uint32"),("ppCubeTex","ptr"),("pSharedHandle","ptr")], "resource"),
    _m(26, "CreateVertexBuffer",          [("Length","uint32"),("Usage","uint32"),("FVF","uint32"),("Pool","uint32"),("ppVB","ptr"),("pSharedHandle","ptr")], "resource"),
    _m(27, "CreateIndexBuffer",           [("Length","uint32"),("Usage","uint32"),("Format","uint32"),("Pool","uint32"),("ppIB","ptr"),("pSharedHandle","ptr")], "resource"),
    _m(28, "CreateRenderTarget",          [("Width","uint32"),("Height","uint32"),("Format","uint32"),("MultiSample","uint32"),("MSQuality","uint32"),("Lockable","int32"),("ppSurface","ptr"),("pSharedHandle","ptr")], "resource"),
    _m(29, "CreateDepthStencilSurface",   [("Width","uint32"),("Height","uint32"),("Format","uint32"),("MultiSample","uint32"),("MSQuality","uint32"),("Discard","int32"),("ppSurface","ptr"),("pSharedHandle","ptr")], "resource"),
    # Surface ops
    _m(30, "UpdateSurface",               [("pSrcSurf","ptr"),("pSrcRect","ptr"),("pDstSurf","ptr"),("pDstPt","ptr")]),
    _m(31, "UpdateTexture",               [("pSrcTex","ptr"),("pDstTex","ptr")]),
    _m(32, "GetRenderTargetData",         [("pRT","ptr"),("pDstSurf","ptr")]),
    _m(33, "GetFrontBufferData",          [("iSwapChain","uint32"),("pDstSurf","ptr")]),
    _m(34, "StretchRect",                 [("pSrcSurf","ptr"),("pSrcRect","ptr"),("pDstSurf","ptr"),("pDstRect","ptr"),("Filter","uint32")]),
    _m(35, "ColorFill",                   [("pSurface","ptr"),("pRect","ptr"),("Color","uint32")]),
    _m(36, "CreateOffscreenPlainSurface", [("Width","uint32"),("Height","uint32"),("Format","uint32"),("Pool","uint32"),("ppSurface","ptr"),("pSharedHandle","ptr")], "resource"),
    # Render targets
    _m(37, "SetRenderTarget",             [("RenderTargetIndex","uint32"),("pRT","ptr")], "state"),
    _m(38, "GetRenderTarget",             [("RenderTargetIndex","uint32"),("ppRT","ptr")]),
    _m(39, "SetDepthStencilSurface",      [("pNewZStencil","ptr")], "state"),
    _m(40, "GetDepthStencilSurface",      [("ppZStencilSurface","ptr")]),
    # Scene
    _m(41, "BeginScene",                  [], "draw"),
    _m(42, "EndScene",                    [], "draw"),
    _m(43, "Clear",                       [("Count","uint32"),("pRects","ptr"),("Flags","uint32"),("Color","uint32"),("Z","float"),("Stencil","uint32")], "draw"),
    # Transforms
    _m(44, "SetTransform",                [("State","uint32"),("pMatrix","ptr")], "transform",
       {"pMatrix": {"type": "float32", "count": 16}}),
    _m(45, "GetTransform",                [("State","uint32"),("pMatrix","ptr")], "transform"),
    _m(46, "MultiplyTransform",           [("State","uint32"),("pMatrix","ptr")], "transform",
       {"pMatrix": {"type": "float32", "count": 16}}),
    _m(47, "SetViewport",                 [("pViewport","ptr")], "state"),
    _m(48, "GetViewport",                 [("pViewport","ptr")]),
    # Material / Light
    _m(49, "SetMaterial",                 [("pMaterial","ptr")], "state"),
    _m(50, "GetMaterial",                 [("pMaterial","ptr")]),
    _m(51, "SetLight",                    [("Index","uint32"),("pLight","ptr")], "state"),
    _m(52, "GetLight",                    [("Index","uint32"),("pLight","ptr")]),
    _m(53, "LightEnable",                 [("Index","uint32"),("Enable","int32")], "state"),
    _m(54, "GetLightEnable",              [("Index","uint32"),("pEnable","ptr")]),
    _m(55, "SetClipPlane",                [("Index","uint32"),("pPlane","ptr")], "state"),
    _m(56, "GetClipPlane",                [("Index","uint32"),("pPlane","ptr")]),
    # Render state
    _m(57, "SetRenderState",              [("State","uint32"),("Value","uint32")], "state"),
    _m(58, "GetRenderState",              [("State","uint32"),("pValue","ptr")]),
    _m(59, "CreateStateBlock",            [("Type","uint32"),("ppSB","ptr")], "resource"),
    _m(60, "BeginStateBlock",             []),
    _m(61, "EndStateBlock",               [("ppSB","ptr")]),
    _m(62, "SetClipStatus",               [("pClipStatus","ptr")], "state"),
    _m(63, "GetClipStatus",               [("pClipStatus","ptr")]),
    # Texture state
    _m(64, "GetTexture",                  [("Stage","uint32"),("ppTexture","ptr")]),
    _m(65, "SetTexture",                  [("Stage","uint32"),("pTexture","ptr")], "state"),
    _m(66, "GetTextureStageState",        [("Stage","uint32"),("Type","uint32"),("pValue","ptr")]),
    _m(67, "SetTextureStageState",        [("Stage","uint32"),("Type","uint32"),("Value","uint32")], "state"),
    _m(68, "GetSamplerState",             [("Sampler","uint32"),("Type","uint32"),("pValue","ptr")]),
    _m(69, "SetSamplerState",             [("Sampler","uint32"),("Type","uint32"),("Value","uint32")], "state"),
    _m(70, "ValidateDevice",              [("pNumPasses","ptr")]),
    # Palette
    _m(71, "SetPaletteEntries",           [("PaletteNumber","uint32"),("pEntries","ptr")], "state"),
    _m(72, "GetPaletteEntries",           [("PaletteNumber","uint32"),("pEntries","ptr")]),
    _m(73, "SetCurrentTexturePalette",    [("PaletteNumber","uint32")], "state"),
    _m(74, "GetCurrentTexturePalette",    [("pPaletteNumber","ptr")]),
    # Scissor / misc
    _m(75, "SetScissorRect",              [("pRect","ptr")], "state"),
    _m(76, "GetScissorRect",              [("pRect","ptr")]),
    _m(77, "SetSoftwareVertexProcessing", [("bSoftware","int32")]),
    _m(78, "GetSoftwareVertexProcessing", []),
    _m(79, "SetNPatchMode",               [("nSegments","float")]),
    _m(80, "GetNPatchMode",               []),
    # Draw calls
    _m(81, "DrawPrimitive",               [("PrimitiveType","uint32"),("StartVertex","uint32"),("PrimitiveCount","uint32")], "draw"),
    _m(82, "DrawIndexedPrimitive",        [("PrimitiveType","uint32"),("BaseVertexIndex","int32"),("MinVertexIndex","uint32"),("NumVertices","uint32"),("StartIndex","uint32"),("PrimitiveCount","uint32")], "draw"),
    _m(83, "DrawPrimitiveUP",             [("PrimitiveType","uint32"),("PrimitiveCount","uint32"),("pVertexStreamZeroData","ptr"),("VertexStreamZeroStride","uint32")], "draw"),
    _m(84, "DrawIndexedPrimitiveUP",      [("PrimitiveType","uint32"),("MinVertexIndex","uint32"),("NumVertices","uint32"),("PrimitiveCount","uint32"),("pIndexData","ptr"),("IndexDataFormat","uint32"),("pVertexStreamZeroData","ptr"),("VertexStreamZeroStride","uint32")], "draw"),
    _m(85, "ProcessVertices",             [("SrcStartIndex","uint32"),("DestIndex","uint32"),("VertexCount","uint32"),("pDestBuffer","ptr"),("pVertexDecl","ptr"),("Flags","uint32")]),
    # Vertex declarations
    _m(86, "CreateVertexDeclaration",     [("pVertexElements","ptr"),("ppDecl","ptr")], "resource"),
    _m(87, "SetVertexDeclaration",        [("pDecl","ptr")], "state"),
    _m(88, "GetVertexDeclaration",        [("ppDecl","ptr")]),
    _m(89, "SetFVF",                      [("FVF","uint32")], "state"),
    _m(90, "GetFVF",                      [("pFVF","ptr")]),
    # Vertex shaders
    _m(91, "CreateVertexShader",          [("pFunction","ptr"),("ppShader","ptr")], "shader",
       {"pFunction": {"type": "shader_bytecode"}}),
    _m(92, "SetVertexShader",             [("pShader","ptr")], "shader"),
    _m(93, "GetVertexShader",             [("ppShader","ptr")]),
    _m(94, "SetVertexShaderConstantF",    [("StartRegister","uint32"),("pConstantData","ptr"),("Vector4fCount","uint32")], "shader",
       {"pConstantData": {"type": "float32", "count_arg": 2, "multiplier": 4}}),
    _m(95, "GetVertexShaderConstantF",    [("StartRegister","uint32"),("pConstantData","ptr"),("Vector4fCount","uint32")]),
    _m(96, "SetVertexShaderConstantI",    [("StartRegister","uint32"),("pConstantData","ptr"),("Vector4iCount","uint32")], "shader",
       {"pConstantData": {"type": "int32", "count_arg": 2, "multiplier": 4}}),
    _m(97, "GetVertexShaderConstantI",    [("StartRegister","uint32"),("pConstantData","ptr"),("Vector4iCount","uint32")]),
    _m(98, "SetVertexShaderConstantB",    [("StartRegister","uint32"),("pConstantData","ptr"),("BoolCount","uint32")], "shader",
       {"pConstantData": {"type": "int32", "count_arg": 2, "multiplier": 1}}),
    _m(99, "GetVertexShaderConstantB",    [("StartRegister","uint32"),("pConstantData","ptr"),("BoolCount","uint32")]),
    # Stream source
    _m(100,"SetStreamSource",             [("StreamNumber","uint32"),("pStreamData","ptr"),("OffsetInBytes","uint32"),("Stride","uint32")], "state"),
    _m(101,"GetStreamSource",             [("StreamNumber","uint32"),("ppStreamData","ptr"),("pOffsetInBytes","ptr"),("pStride","ptr")]),
    _m(102,"SetStreamSourceFreq",         [("StreamNumber","uint32"),("Setting","uint32")], "state"),
    _m(103,"GetStreamSourceFreq",         [("StreamNumber","uint32"),("pSetting","ptr")]),
    # Indices
    _m(104,"SetIndices",                  [("pIndexData","ptr")], "state"),
    _m(105,"GetIndices",                  [("ppIndexData","ptr")]),
    # Pixel shaders
    _m(106,"CreatePixelShader",           [("pFunction","ptr"),("ppShader","ptr")], "shader",
       {"pFunction": {"type": "shader_bytecode"}}),
    _m(107,"SetPixelShader",              [("pShader","ptr")], "shader"),
    _m(108,"GetPixelShader",              [("ppShader","ptr")]),
    _m(109,"SetPixelShaderConstantF",     [("StartRegister","uint32"),("pConstantData","ptr"),("Vector4fCount","uint32")], "shader",
       {"pConstantData": {"type": "float32", "count_arg": 2, "multiplier": 4}}),
    _m(110,"GetPixelShaderConstantF",     [("StartRegister","uint32"),("pConstantData","ptr"),("Vector4fCount","uint32")]),
    _m(111,"SetPixelShaderConstantI",     [("StartRegister","uint32"),("pConstantData","ptr"),("Vector4iCount","uint32")], "shader",
       {"pConstantData": {"type": "int32", "count_arg": 2, "multiplier": 4}}),
    _m(112,"GetPixelShaderConstantI",     [("StartRegister","uint32"),("pConstantData","ptr"),("Vector4iCount","uint32")]),
    _m(113,"SetPixelShaderConstantB",     [("StartRegister","uint32"),("pConstantData","ptr"),("BoolCount","uint32")], "shader",
       {"pConstantData": {"type": "int32", "count_arg": 2, "multiplier": 1}}),
    _m(114,"GetPixelShaderConstantB",     [("StartRegister","uint32"),("pConstantData","ptr"),("BoolCount","uint32")]),
    # Patches
    _m(115,"DrawRectPatch",               [("Handle","uint32"),("pNumSegs","ptr"),("pRPInfo","ptr")], "draw"),
    _m(116,"DrawTriPatch",                [("Handle","uint32"),("pNumSegs","ptr"),("pTPInfo","ptr")], "draw"),
    _m(117,"DeletePatch",                 [("Handle","uint32")]),
    # Query
    _m(118,"CreateQuery",                 [("Type","uint32"),("ppQuery","ptr")], "resource"),
]}
# fmt: on


# ── Vtable slot lookup ──────────────────────────────────────────────────────

SLOT = {m.name: m.slot for m in D3D9_METHODS.values()}
SLOT_COUNT = len(D3D9_METHODS)


# ── Slot category sets (derived from method categories, no magic numbers) ───

DRAW_SLOTS = frozenset(
    s for s, m in D3D9_METHODS.items() if m.category == "draw"
)

GEOMETRY_DRAW_SLOTS = frozenset(
    SLOT[n] for n in (
        "DrawPrimitive", "DrawIndexedPrimitive",
        "DrawPrimitiveUP", "DrawIndexedPrimitiveUP",
    )
)

STATE_SET_SLOTS = frozenset(
    s for s, m in D3D9_METHODS.items()
    if m.category in ("state", "shader", "transform")
)

DATA_READER_SLOTS = frozenset(
    SLOT[n] for n in (
        "Clear", "SetTransform", "MultiplyTransform",
        "CreateVertexDeclaration",
        "CreateVertexShader", "CreatePixelShader",
        "SetVertexShaderConstantF", "SetPixelShaderConstantF",
        "SetVertexShaderConstantI", "SetPixelShaderConstantI",
        "SetVertexShaderConstantB", "SetPixelShaderConstantB",
    )
)

INIT_CAPTURE_SLOTS = frozenset(
    SLOT[n] for n in (
        "CreateTexture", "CreateVolumeTexture", "CreateCubeTexture",
        "CreateVertexBuffer", "CreateIndexBuffer", "CreateRenderTarget",
        "CreateDepthStencilSurface", "CreateOffscreenPlainSurface",
        "CreateVertexDeclaration", "CreateVertexShader", "CreatePixelShader",
    )
)


# ── D3DRENDERSTATETYPE ──────────────────────────────────────────────────────

D3DRS_ZENABLE                   = 7
D3DRS_FILLMODE                  = 8
D3DRS_SHADEMODE                 = 9
D3DRS_ZWRITEENABLE              = 14
D3DRS_ALPHATESTENABLE           = 15
D3DRS_SRCBLEND                  = 19
D3DRS_DESTBLEND                 = 20
D3DRS_CULLMODE                  = 22
D3DRS_ZFUNC                     = 23
D3DRS_ALPHAREF                  = 24
D3DRS_ALPHAFUNC                 = 25
D3DRS_ALPHABLENDENABLE          = 27
D3DRS_FOGENABLE                 = 28
D3DRS_SPECULARENABLE            = 29
D3DRS_FOGCOLOR                  = 34
D3DRS_FOGTABLEMODE              = 35
D3DRS_FOGSTART                  = 36
D3DRS_FOGEND                    = 37
D3DRS_STENCILENABLE             = 52
D3DRS_STENCILFAIL               = 53
D3DRS_STENCILZFAIL              = 54
D3DRS_STENCILPASS               = 55
D3DRS_STENCILFUNC               = 56
D3DRS_STENCILREF                = 57
D3DRS_STENCILMASK               = 58
D3DRS_STENCILWRITEMASK          = 59
D3DRS_TEXTUREFACTOR             = 60
D3DRS_CLIPPING                  = 136
D3DRS_LIGHTING                  = 137
D3DRS_AMBIENT                   = 139
D3DRS_COLORVERTEX               = 141
D3DRS_NORMALIZENORMALS          = 143
D3DRS_POINTSIZE                 = 154
D3DRS_POINTSPRITEENABLE         = 156
D3DRS_COLORWRITEENABLE          = 168
D3DRS_BLENDOP                   = 171
D3DRS_SCISSORTESTENABLE         = 174
D3DRS_SLOPESCALEDEPTHBIAS       = 175
D3DRS_SRGBWRITEENABLE           = 194
D3DRS_DEPTHBIAS                 = 195
D3DRS_SEPARATEALPHABLENDENABLE  = 206
D3DRS_SRCBLENDALPHA             = 207
D3DRS_DESTBLENDALPHA            = 208
D3DRS_BLENDOPALPHA              = 209

D3DRS_NAMES = {v: k for k, v in dict(locals()).items() if k.startswith("D3DRS_")}


# ── D3DTRANSFORMSTATETYPE ───────────────────────────────────────────────────

D3DTS_VIEW       = 2
D3DTS_PROJECTION = 3
D3DTS_TEXTURE0   = 16
D3DTS_TEXTURE1   = 17
D3DTS_TEXTURE2   = 18
D3DTS_TEXTURE3   = 19
D3DTS_TEXTURE4   = 20
D3DTS_TEXTURE5   = 21
D3DTS_TEXTURE6   = 22
D3DTS_TEXTURE7   = 23
D3DTS_WORLD      = 256

D3DTS_NAMES = {v: k for k, v in dict(locals()).items() if k.startswith("D3DTS_")}


# ── D3DCLEAR flags ──────────────────────────────────────────────────────────

D3DCLEAR_TARGET  = 0x00000001
D3DCLEAR_ZBUFFER = 0x00000002
D3DCLEAR_STENCIL = 0x00000004


# ── D3DPRIMITIVETYPE ────────────────────────────────────────────────────────

D3DPT_POINTLIST     = 1
D3DPT_LINELIST      = 2
D3DPT_LINESTRIP     = 3
D3DPT_TRIANGLELIST  = 4
D3DPT_TRIANGLESTRIP = 5
D3DPT_TRIANGLEFAN   = 6

D3DPT_NAMES = {
    D3DPT_POINTLIST: "PointList", D3DPT_LINELIST: "LineList",
    D3DPT_LINESTRIP: "LineStrip", D3DPT_TRIANGLELIST: "TriangleList",
    D3DPT_TRIANGLESTRIP: "TriangleStrip", D3DPT_TRIANGLEFAN: "TriangleFan",
}


# ── D3DDECLTYPE ─────────────────────────────────────────────────────────────

D3DDECLTYPE_FLOAT1    = 0
D3DDECLTYPE_FLOAT2    = 1
D3DDECLTYPE_FLOAT3    = 2
D3DDECLTYPE_FLOAT4    = 3
D3DDECLTYPE_D3DCOLOR  = 4
D3DDECLTYPE_UBYTE4    = 5
D3DDECLTYPE_SHORT2    = 6
D3DDECLTYPE_SHORT4    = 7
D3DDECLTYPE_UBYTE4N   = 8
D3DDECLTYPE_SHORT2N   = 9
D3DDECLTYPE_SHORT4N   = 10
D3DDECLTYPE_USHORT2N  = 11
D3DDECLTYPE_USHORT4N  = 12
D3DDECLTYPE_FLOAT16_2 = 15
D3DDECLTYPE_FLOAT16_4 = 16
D3DDECLTYPE_UNUSED    = 17

D3DDECLTYPE_NAMES = {v: k.replace("D3DDECLTYPE_", "") for k, v in dict(locals()).items() if k.startswith("D3DDECLTYPE_")}


# ── D3DDECLUSAGE ────────────────────────────────────────────────────────────

D3DDECLUSAGE_POSITION     = 0
D3DDECLUSAGE_BLENDWEIGHT  = 1
D3DDECLUSAGE_BLENDINDICES = 2
D3DDECLUSAGE_NORMAL       = 3
D3DDECLUSAGE_PSIZE        = 4
D3DDECLUSAGE_TEXCOORD     = 5
D3DDECLUSAGE_TANGENT      = 6
D3DDECLUSAGE_BINORMAL     = 7
D3DDECLUSAGE_TESSFACTOR   = 8
D3DDECLUSAGE_POSITIONT    = 9
D3DDECLUSAGE_COLOR        = 10
D3DDECLUSAGE_FOG          = 11
D3DDECLUSAGE_DEPTH        = 12
D3DDECLUSAGE_SAMPLE       = 13

D3DDECLUSAGE_NAMES = {v: k.replace("D3DDECLUSAGE_", "") for k, v in dict(locals()).items() if k.startswith("D3DDECLUSAGE_")}


# ── D3DDECLMETHOD ───────────────────────────────────────────────────────────

D3DDECLMETHOD_DEFAULT = 0

D3DDECLMETHOD_NAMES = {0: "DEFAULT", 1: "PARTIALU", 2: "PARTIALV",
                       3: "CROSSUV", 4: "UV", 5: "LOOKUP", 6: "LOOKUPPRESAMPLED"}


# ── D3DBLEND ────────────────────────────────────────────────────────────────

D3DBLEND_ZERO            = 1
D3DBLEND_ONE             = 2
D3DBLEND_SRCCOLOR        = 3
D3DBLEND_INVSRCCOLOR     = 4
D3DBLEND_SRCALPHA        = 5
D3DBLEND_INVSRCALPHA     = 6
D3DBLEND_DESTALPHA       = 7
D3DBLEND_INVDESTALPHA    = 8
D3DBLEND_DESTCOLOR       = 9
D3DBLEND_INVDESTCOLOR    = 10
D3DBLEND_SRCALPHASAT     = 11
D3DBLEND_BLENDFACTOR     = 14
D3DBLEND_INVBLENDFACTOR  = 15

D3DBLEND_NAMES = {v: k.replace("D3DBLEND_", "") for k, v in dict(locals()).items() if k.startswith("D3DBLEND_")}


# ── D3DBLENDOP ──────────────────────────────────────────────────────────────

D3DBLENDOP_ADD         = 1
D3DBLENDOP_SUBTRACT    = 2
D3DBLENDOP_REVSUBTRACT = 3
D3DBLENDOP_MIN         = 4
D3DBLENDOP_MAX         = 5

D3DBLENDOP_NAMES = {v: k.replace("D3DBLENDOP_", "") for k, v in dict(locals()).items() if k.startswith("D3DBLENDOP_")}


# ── D3DCMPFUNC ──────────────────────────────────────────────────────────────

D3DCMP_NEVER        = 1
D3DCMP_LESS         = 2
D3DCMP_EQUAL        = 3
D3DCMP_LESSEQUAL    = 4
D3DCMP_GREATER      = 5
D3DCMP_NOTEQUAL     = 6
D3DCMP_GREATEREQUAL = 7
D3DCMP_ALWAYS       = 8

D3DCMP_NAMES = {v: k.replace("D3DCMP_", "") for k, v in dict(locals()).items() if k.startswith("D3DCMP_")}


# ── D3DCULL ─────────────────────────────────────────────────────────────────

D3DCULL_NONE = 1
D3DCULL_CW   = 2
D3DCULL_CCW  = 3

D3DCULL_NAMES = {1: "NONE", 2: "CW", 3: "CCW"}


# ── D3DFILLMODE ─────────────────────────────────────────────────────────────

D3DFILL_POINT     = 1
D3DFILL_WIREFRAME = 2
D3DFILL_SOLID     = 3

D3DFILL_NAMES = {1: "POINT", 2: "WIREFRAME", 3: "SOLID"}


# ── Shader bytecode constants ───────────────────────────────────────────────

SHADER_END_TOKEN    = 0x0000FFFF
MAX_SHADER_DWORDS   = 16384
MAX_CONST_REGISTERS = 256
MATRIX_FLOAT_COUNT  = 16
MAX_VTXDECL_ELEMENTS = 64


# ── Codegen ─────────────────────────────────────────────────────────────────

def max_argc() -> int:
    return max(m.argc for m in D3D9_METHODS.values())


def generate_hooks_inc() -> str:
    """Generate d3d9_trace_hooks.inc C source.

    Uses two-phase include guards:
      #define DXTRACE_TABLES  -> emit slot defines + tables (names, arg counts, init bitmap)
      #define DXTRACE_HOOKS   -> emit TRACE_WRAP invocations + vtable
    """
    max_a = max_argc()
    lines = ["/* Auto-generated by d3d9_methods.py -- DO NOT EDIT */", ""]

    # ---- Phase 1: slot defines + tables (included before trace_pre) ----
    lines.append("#ifdef DXTRACE_TABLES")
    lines.append("")

    # Slot defines
    for slot in range(SLOT_COUNT):
        m = D3D9_METHODS[slot]
        lines.append(f"#define SLOT_{m.name:40s} {slot}")
    lines.append("")

    # Domain constants for data readers
    lines.append(f"#define SHADER_END_TOKEN       0x{SHADER_END_TOKEN:08X}")
    lines.append(f"#define MAX_SHADER_DWORDS      {MAX_SHADER_DWORDS}")
    lines.append(f"#define MAX_CONST_REGISTERS    {MAX_CONST_REGISTERS}")
    lines.append(f"#define MATRIX_FLOAT_COUNT     {MATRIX_FLOAT_COUNT}")
    lines.append(f"#define MAX_VTXDECL_ELEMENTS   {MAX_VTXDECL_ELEMENTS}")
    lines.append(f"#define D3DDECL_END_STREAM     0xFF")
    lines.append("")

    # Data reader slot bitmap
    lines.append(f"static const int g_hasDataReader[{SLOT_COUNT}] = {{")
    for i in range(0, SLOT_COUNT, 10):
        chunk = ", ".join(
            "1" if s in DATA_READER_SLOTS else "0"
            for s in range(i, min(i + 10, SLOT_COUNT))
        )
        comma = "," if i + 10 < SLOT_COUNT else ""
        lines.append(f"    {chunk}{comma}")
    lines.append("};")
    lines.append("")

    # Method names
    lines.append(f"static const char *g_methodNames[{SLOT_COUNT}] = {{")
    for i in range(0, SLOT_COUNT, 4):
        chunk = ", ".join(
            f'"{D3D9_METHODS[s].name}"'
            for s in range(i, min(i + 4, SLOT_COUNT))
        )
        comma = "," if i + 4 < SLOT_COUNT else ""
        lines.append(f"    {chunk}{comma}")
    lines.append("};")
    lines.append("")

    # Arg counts
    vals = ", ".join(str(D3D9_METHODS[s].argc) for s in range(SLOT_COUNT))
    lines.append(f"static const int g_methodArgCounts[{SLOT_COUNT}] = {{ {vals} }};")
    lines.append("")

    # Arg names
    lines.append(f"static const char *g_methodArgNames[{SLOT_COUNT}][{max_a}] = {{")
    for slot in range(SLOT_COUNT):
        m = D3D9_METHODS[slot]
        names = [f'"{a[0]}"' for a in m.args]
        while len(names) < max_a:
            names.append("NULL")
        lines.append(f"    {{ {', '.join(names)} }},")
    lines.append("};")
    lines.append("")

    # Init capture bitmap
    lines.append(f"static const int g_initCapture[{SLOT_COUNT}] = {{")
    for i in range(0, SLOT_COUNT, 10):
        chunk = ", ".join(
            "1" if s in INIT_CAPTURE_SLOTS else "0"
            for s in range(i, min(i + 10, SLOT_COUNT))
        )
        comma = "," if i + 10 < SLOT_COUNT else ""
        lines.append(f"    {chunk}{comma}")
    lines.append("};")
    lines.append("")

    # Arg-is-pointer table (1 = hex/ptr, 0 = decimal int)
    lines.append(f"static const int g_argIsPtr[{SLOT_COUNT}][{max_a}] = {{")
    for slot in range(SLOT_COUNT):
        m = D3D9_METHODS[slot]
        flags = []
        for a in m.args:
            flags.append("1" if a[1] == "ptr" else "0")
        while len(flags) < max_a:
            flags.append("0")
        lines.append(f"    {{ {', '.join(flags)} }},")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* DXTRACE_TABLES */")
    lines.append("")

    # ---- Phase 2: wrappers + vtable (included after TRACE_WRAP macro defs) ----
    lines.append("#ifdef DXTRACE_HOOKS")
    lines.append("")

    for slot in range(SLOT_COUNT):
        m = D3D9_METHODS[slot]
        lines.append(f"TRACE_WRAP_{m.argc}({slot})    /* {m.name} */")
    lines.append("")

    lines.append(f"static void *g_traceVtable[{SLOT_COUNT}] = {{")
    for i in range(0, SLOT_COUNT, 10):
        chunk = ", ".join(f"TH_{s}" for s in range(i, min(i + 10, SLOT_COUNT)))
        comma = "," if i + 10 < SLOT_COUNT else ""
        lines.append(f"    {chunk}{comma}")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* DXTRACE_HOOKS */")

    return "\n".join(lines) + "\n"


def _cpp_param_type(arg_type: str) -> str:
    """Map d3d9_methods arg type to C++ parameter type."""
    return {"uint32": "DWORD", "int32": "INT", "float": "float", "ptr": "const void*"}[arg_type]


def _cpp_record_call(arg_name: str, arg_type: str) -> str:
    """Generate the record_arg_xxx call for an argument."""
    if arg_type == "ptr":
        return f't.record_arg_ptr("{arg_name}", {arg_name});'
    if arg_type == "float":
        return f't.record_arg_float("{arg_name}", {arg_name});'
    if arg_type == "int32":
        return f't.record_arg_int("{arg_name}", {arg_name});'
    return f't.record_arg_uint("{arg_name}", {arg_name});'


def _cpp_data_reader_lines(m: MethodSpec) -> list[str]:
    """Generate data reader calls for a method's data_readers dict."""
    lines = []
    for param_name, spec in m.data_readers.items():
        dtype = spec["type"]
        if dtype == "shader_bytecode":
            lines.append(f'    t.record_data_shader("bytecode", (const DWORD*){param_name});')
        elif dtype == "float32" and "count" in spec:
            lines.append(f'    t.record_data_float("matrix", (const float*){param_name}, {spec["count"]});')
        elif dtype == "float32" and "count_arg" in spec:
            count_arg = m.args[spec["count_arg"]][0]
            mult = spec.get("multiplier", 1)
            lines.append(f'    t.record_data_float("constants", (const float*){param_name}, {count_arg} * {mult});')
        elif dtype == "int32" and "count_arg" in spec:
            count_arg = m.args[spec["count_arg"]][0]
            mult = spec.get("multiplier", 1)
            lines.append(f'    t.record_data_int("constants", (const int*){param_name}, {count_arg} * {mult});')
    return lines


def generate_cpp_dispatch_inc() -> str:
    """Generate tracer_dispatch.inc for the remix-comp C++ tracer module.

    Produces:
      - TRACE_IF_ACTIVE / TRACE_IF_ACTIVE_NOARGS macros
      - 119 inline trace_XXX() dispatch functions
      - Special handling for CreateVertexDeclaration and Clear
    """
    lines = [
        "/* Auto-generated by d3d9_methods.py -- DO NOT EDIT */",
        "/* C++ dispatch functions for remix-comp integrated tracer */",
        "",
        "#pragma once",
        "",
        "// -- Macros --",
        "",
        "#define TRACE_IF_ACTIVE(fn, ...) \\",
        "    do { if (comp::tracer::is_active()) fn(comp::tracer::ref(), __VA_ARGS__); } while(0)",
        "",
        "#define TRACE_IF_ACTIVE_NOARGS(fn) \\",
        "    do { if (comp::tracer::is_active()) fn(comp::tracer::ref()); } while(0)",
        "",
        "// -- Dispatch functions --",
        "",
    ]

    for slot in range(SLOT_COUNT):
        m = D3D9_METHODS[slot]

        # Build parameter list
        params = ["tracer& t"]
        for arg_name, arg_type in m.args:
            params.append(f"{_cpp_param_type(arg_type)} {arg_name}")
        param_str = ", ".join(params)

        lines.append(f"inline void trace_{m.name}({param_str})")
        lines.append("{")
        lines.append(f'    t.record_begin("{m.name}", {slot});')

        # Emit arg recording
        for arg_name, arg_type in m.args:
            lines.append(f"    {_cpp_record_call(arg_name, arg_type)}")

        # Special case: CreateVertexDeclaration — emit element array data
        if m.name == "CreateVertexDeclaration":
            lines.append('    t.record_data_vtxdecl("elements", (const BYTE*)pVertexElements);')

        # Special case: Clear — emit clear-specific data fields
        elif m.name == "Clear":
            lines.append("    t.record_clear_data(Flags, Color, Z, Stencil);")

        # Standard data readers
        else:
            for dl in _cpp_data_reader_lines(m):
                lines.append(dl)

        lines.append("    t.record_backtrace();")
        lines.append("    t.record_end();")
        lines.append("}")
        lines.append("")

    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description="Generate d3d9_trace_hooks.inc")
    p.add_argument("--output", "-o", default=None,
                   help="Output path (default: stdout)")
    args = p.parse_args()

    code = generate_hooks_inc()
    if args.output:
        Path(args.output).write_text(code)
        print(f"Generated {args.output} ({SLOT_COUNT} methods, max {max_argc()} args)")
    else:
        sys.stdout.write(code)


if __name__ == "__main__":
    main()
