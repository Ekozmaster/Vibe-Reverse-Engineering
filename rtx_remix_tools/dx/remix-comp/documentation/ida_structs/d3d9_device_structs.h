#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

struct HWND__;
struct tagRECT;
struct tagPOINT;
struct _GUID;
struct IUnknown;
struct IUnknown_vtbl;
struct IDirect3DDevice9;
struct IDirect3D9;
struct _D3DCAPS9;
struct _D3DDISPLAYMODE;
struct _D3DDEVICE_CREATION_PARAMETERS;
struct IDirect3DSurface9;
struct _D3DPRESENT_PARAMETERS_;
struct IDirect3DSwapChain9;
struct _RGNDATA;
struct _D3DRASTER_STATUS;
struct _D3DGAMMARAMP;
struct IDirect3DBaseTexture9;
struct IDirect3DTexture9;
struct IDirect3DVolumeTexture9;
struct IDirect3DCubeTexture9;
struct IDirect3DVertexBuffer9;
struct IDirect3DIndexBuffer9;
struct _D3DRECT;
struct _D3DMATRIX;
struct _D3DVIEWPORT9;
struct _D3DMATERIAL9;
struct _D3DLIGHT9;
struct IDirect3DStateBlock9;
struct _D3DCLIPSTATUS9;
struct tagPALETTEENTRY;
struct IDirect3DVertexDeclaration9;
struct _D3DVERTEXELEMENT9;
struct IDirect3DVertexShader9;
struct IDirect3DPixelShader9;
struct _D3DRECTPATCH_INFO;
struct _D3DTRIPATCH_INFO;
struct IDirect3DQuery9;

/* 104 */
typedef int HRESULT;

/* 239 */
enum _D3DBACKBUFFER_TYPE : __int32
{
  D3DBACKBUFFER_TYPE_MONO = 0x0,
  D3DBACKBUFFER_TYPE_LEFT = 0x1,
  D3DBACKBUFFER_TYPE_RIGHT = 0x2,
  D3DBACKBUFFER_TYPE_FORCE_DWORD = 0x7FFFFFFF,
};

/* 240 */
enum _D3DFORMAT : __int32
{
  D3DFMT_UNKNOWN = 0x0,
  D3DFMT_R8G8B8 = 0x14,
  D3DFMT_A8R8G8B8 = 0x15,
  D3DFMT_X8R8G8B8 = 0x16,
  D3DFMT_R5G6B5 = 0x17,
  D3DFMT_X1R5G5B5 = 0x18,
  D3DFMT_A1R5G5B5 = 0x19,
  D3DFMT_A4R4G4B4 = 0x1A,
  D3DFMT_R3G3B2 = 0x1B,
  D3DFMT_A8 = 0x1C,
  D3DFMT_A8R3G3B2 = 0x1D,
  D3DFMT_X4R4G4B4 = 0x1E,
  D3DFMT_A2B10G10R10 = 0x1F,
  D3DFMT_A8B8G8R8 = 0x20,
  D3DFMT_X8B8G8R8 = 0x21,
  D3DFMT_G16R16 = 0x22,
  D3DFMT_A2R10G10B10 = 0x23,
  D3DFMT_A16B16G16R16 = 0x24,
  D3DFMT_A8P8 = 0x28,
  D3DFMT_P8 = 0x29,
  D3DFMT_L8 = 0x32,
  D3DFMT_A8L8 = 0x33,
  D3DFMT_A4L4 = 0x34,
  D3DFMT_V8U8 = 0x3C,
  D3DFMT_L6V5U5 = 0x3D,
  D3DFMT_X8L8V8U8 = 0x3E,
  D3DFMT_Q8W8V8U8 = 0x3F,
  D3DFMT_V16U16 = 0x40,
  D3DFMT_A2W10V10U10 = 0x43,
  D3DFMT_D16_LOCKABLE = 0x46,
  D3DFMT_D32 = 0x47,
  D3DFMT_D15S1 = 0x49,
  D3DFMT_D24S8 = 0x4B,
  D3DFMT_D24X8 = 0x4D,
  D3DFMT_D24X4S4 = 0x4F,
  D3DFMT_D16 = 0x50,
  D3DFMT_L16 = 0x51,
  D3DFMT_D32F_LOCKABLE = 0x52,
  D3DFMT_D24FS8 = 0x53,
  D3DFMT_VERTEXDATA = 0x64,
  D3DFMT_INDEX16 = 0x65,
  D3DFMT_INDEX32 = 0x66,
  D3DFMT_Q16W16V16U16 = 0x6E,
  D3DFMT_R16F = 0x6F,
  D3DFMT_G16R16F = 0x70,
  D3DFMT_A16B16G16R16F = 0x71,
  D3DFMT_R32F = 0x72,
  D3DFMT_G32R32F = 0x73,
  D3DFMT_A32B32G32R32F = 0x74,
  D3DFMT_CxV8U8 = 0x75,
  D3DFMT_MULTI2_ARGB8 = 0x3154454D,
  D3DFMT_DXT1 = 0x31545844,
  D3DFMT_DXT2 = 0x32545844,
  D3DFMT_YUY2 = 0x32595559,
  D3DFMT_DXT3 = 0x33545844,
  D3DFMT_DXT4 = 0x34545844,
  D3DFMT_DXT5 = 0x35545844,
  D3DFMT_G8R8_G8B8 = 0x42475247,
  D3DFMT_R8G8_B8G8 = 0x47424752,
  D3DFMT_UYVY = 0x59565955,
  D3DFMT_FORCE_DWORD = 0x7FFFFFFF,
};

/* 241 */
enum _D3DPOOL : __int32
{
  D3DPOOL_DEFAULT = 0x0,
  D3DPOOL_MANAGED = 0x1,
  D3DPOOL_SYSTEMMEM = 0x2,
  D3DPOOL_SCRATCH = 0x3,
  D3DPOOL_FORCE_DWORD = 0x7FFFFFFF,
};

/* 242 */
enum _D3DMULTISAMPLE_TYPE : __int32
{
  D3DMULTISAMPLE_NONE = 0x0,
  D3DMULTISAMPLE_NONMASKABLE = 0x1,
  D3DMULTISAMPLE_2_SAMPLES = 0x2,
  D3DMULTISAMPLE_3_SAMPLES = 0x3,
  D3DMULTISAMPLE_4_SAMPLES = 0x4,
  D3DMULTISAMPLE_5_SAMPLES = 0x5,
  D3DMULTISAMPLE_6_SAMPLES = 0x6,
  D3DMULTISAMPLE_7_SAMPLES = 0x7,
  D3DMULTISAMPLE_8_SAMPLES = 0x8,
  D3DMULTISAMPLE_9_SAMPLES = 0x9,
  D3DMULTISAMPLE_10_SAMPLES = 0xA,
  D3DMULTISAMPLE_11_SAMPLES = 0xB,
  D3DMULTISAMPLE_12_SAMPLES = 0xC,
  D3DMULTISAMPLE_13_SAMPLES = 0xD,
  D3DMULTISAMPLE_14_SAMPLES = 0xE,
  D3DMULTISAMPLE_15_SAMPLES = 0xF,
  D3DMULTISAMPLE_16_SAMPLES = 0x10,
  D3DMULTISAMPLE_FORCE_DWORD = 0x7FFFFFFF,
};

/* 243 */
enum _D3DTEXTUREFILTERTYPE : __int32
{
  D3DTEXF_NONE = 0x0,
  D3DTEXF_POINT = 0x1,
  D3DTEXF_LINEAR = 0x2,
  D3DTEXF_ANISOTROPIC = 0x3,
  D3DTEXF_PYRAMIDALQUAD = 0x6,
  D3DTEXF_GAUSSIANQUAD = 0x7,
  D3DTEXF_FORCE_DWORD = 0x7FFFFFFF,
};

/* 244 */
enum _D3DTRANSFORMSTATETYPE : __int32
{
  D3DTS_VIEW = 0x2,
  D3DTS_PROJECTION = 0x3,
  D3DTS_TEXTURE0 = 0x10,
  D3DTS_TEXTURE1 = 0x11,
  D3DTS_TEXTURE2 = 0x12,
  D3DTS_TEXTURE3 = 0x13,
  D3DTS_TEXTURE4 = 0x14,
  D3DTS_TEXTURE5 = 0x15,
  D3DTS_TEXTURE6 = 0x16,
  D3DTS_TEXTURE7 = 0x17,
  D3DTS_FORCE_DWORD = 0x7FFFFFFF,
};

/* 245 */
enum _D3DRENDERSTATETYPE : __int32
{
  D3DRS_ZENABLE = 0x7,
  D3DRS_FILLMODE = 0x8,
  D3DRS_SHADEMODE = 0x9,
  D3DRS_ZWRITEENABLE = 0xE,
  D3DRS_ALPHATESTENABLE = 0xF,
  D3DRS_LASTPIXEL = 0x10,
  D3DRS_SRCBLEND = 0x13,
  D3DRS_DESTBLEND = 0x14,
  D3DRS_CULLMODE = 0x16,
  D3DRS_ZFUNC = 0x17,
  D3DRS_ALPHAREF = 0x18,
  D3DRS_ALPHAFUNC = 0x19,
  D3DRS_DITHERENABLE = 0x1A,
  D3DRS_ALPHABLENDENABLE = 0x1B,
  D3DRS_FOGENABLE = 0x1C,
  D3DRS_SPECULARENABLE = 0x1D,
  D3DRS_FOGCOLOR = 0x22,
  D3DRS_FOGTABLEMODE = 0x23,
  D3DRS_FOGSTART = 0x24,
  D3DRS_FOGEND = 0x25,
  D3DRS_FOGDENSITY = 0x26,
  D3DRS_RANGEFOGENABLE = 0x30,
  D3DRS_STENCILENABLE = 0x34,
  D3DRS_STENCILFAIL = 0x35,
  D3DRS_STENCILZFAIL = 0x36,
  D3DRS_STENCILPASS = 0x37,
  D3DRS_STENCILFUNC = 0x38,
  D3DRS_STENCILREF = 0x39,
  D3DRS_STENCILMASK = 0x3A,
  D3DRS_STENCILWRITEMASK = 0x3B,
  D3DRS_TEXTUREFACTOR = 0x3C,
  D3DRS_WRAP0 = 0x80,
  D3DRS_WRAP1 = 0x81,
  D3DRS_WRAP2 = 0x82,
  D3DRS_WRAP3 = 0x83,
  D3DRS_WRAP4 = 0x84,
  D3DRS_WRAP5 = 0x85,
  D3DRS_WRAP6 = 0x86,
  D3DRS_WRAP7 = 0x87,
  D3DRS_CLIPPING = 0x88,
  D3DRS_LIGHTING = 0x89,
  D3DRS_AMBIENT = 0x8B,
  D3DRS_FOGVERTEXMODE = 0x8C,
  D3DRS_COLORVERTEX = 0x8D,
  D3DRS_LOCALVIEWER = 0x8E,
  D3DRS_NORMALIZENORMALS = 0x8F,
  D3DRS_DIFFUSEMATERIALSOURCE = 0x91,
  D3DRS_SPECULARMATERIALSOURCE = 0x92,
  D3DRS_AMBIENTMATERIALSOURCE = 0x93,
  D3DRS_EMISSIVEMATERIALSOURCE = 0x94,
  D3DRS_VERTEXBLEND = 0x97,
  D3DRS_CLIPPLANEENABLE = 0x98,
  D3DRS_POINTSIZE = 0x9A,
  D3DRS_POINTSIZE_MIN = 0x9B,
  D3DRS_POINTSPRITEENABLE = 0x9C,
  D3DRS_POINTSCALEENABLE = 0x9D,
  D3DRS_POINTSCALE_A = 0x9E,
  D3DRS_POINTSCALE_B = 0x9F,
  D3DRS_POINTSCALE_C = 0xA0,
  D3DRS_MULTISAMPLEANTIALIAS = 0xA1,
  D3DRS_MULTISAMPLEMASK = 0xA2,
  D3DRS_PATCHEDGESTYLE = 0xA3,
  D3DRS_DEBUGMONITORTOKEN = 0xA5,
  D3DRS_POINTSIZE_MAX = 0xA6,
  D3DRS_INDEXEDVERTEXBLENDENABLE = 0xA7,
  D3DRS_COLORWRITEENABLE = 0xA8,
  D3DRS_TWEENFACTOR = 0xAA,
  D3DRS_BLENDOP = 0xAB,
  D3DRS_POSITIONDEGREE = 0xAC,
  D3DRS_NORMALDEGREE = 0xAD,
  D3DRS_SCISSORTESTENABLE = 0xAE,
  D3DRS_SLOPESCALEDEPTHBIAS = 0xAF,
  D3DRS_ANTIALIASEDLINEENABLE = 0xB0,
  D3DRS_MINTESSELLATIONLEVEL = 0xB2,
  D3DRS_MAXTESSELLATIONLEVEL = 0xB3,
  D3DRS_ADAPTIVETESS_X = 0xB4,
  D3DRS_ADAPTIVETESS_Y = 0xB5,
  D3DRS_ADAPTIVETESS_Z = 0xB6,
  D3DRS_ADAPTIVETESS_W = 0xB7,
  D3DRS_ENABLEADAPTIVETESSELLATION = 0xB8,
  D3DRS_TWOSIDEDSTENCILMODE = 0xB9,
  D3DRS_CCW_STENCILFAIL = 0xBA,
  D3DRS_CCW_STENCILZFAIL = 0xBB,
  D3DRS_CCW_STENCILPASS = 0xBC,
  D3DRS_CCW_STENCILFUNC = 0xBD,
  D3DRS_COLORWRITEENABLE1 = 0xBE,
  D3DRS_COLORWRITEENABLE2 = 0xBF,
  D3DRS_COLORWRITEENABLE3 = 0xC0,
  D3DRS_BLENDFACTOR = 0xC1,
  D3DRS_SRGBWRITEENABLE = 0xC2,
  D3DRS_DEPTHBIAS = 0xC3,
  D3DRS_WRAP8 = 0xC6,
  D3DRS_WRAP9 = 0xC7,
  D3DRS_WRAP10 = 0xC8,
  D3DRS_WRAP11 = 0xC9,
  D3DRS_WRAP12 = 0xCA,
  D3DRS_WRAP13 = 0xCB,
  D3DRS_WRAP14 = 0xCC,
  D3DRS_WRAP15 = 0xCD,
  D3DRS_SEPARATEALPHABLENDENABLE = 0xCE,
  D3DRS_SRCBLENDALPHA = 0xCF,
  D3DRS_DESTBLENDALPHA = 0xD0,
  D3DRS_BLENDOPALPHA = 0xD1,
  D3DRS_FORCE_DWORD = 0x7FFFFFFF,
};

/* 246 */
enum _D3DSTATEBLOCKTYPE : __int32
{
  D3DSBT_ALL = 0x1,
  D3DSBT_PIXELSTATE = 0x2,
  D3DSBT_VERTEXSTATE = 0x3,
  D3DSBT_FORCE_DWORD = 0x7FFFFFFF,
};

/* 247 */
enum _D3DTEXTURESTAGESTATETYPE : __int32
{
  D3DTSS_COLOROP = 0x1,
  D3DTSS_COLORARG1 = 0x2,
  D3DTSS_COLORARG2 = 0x3,
  D3DTSS_ALPHAOP = 0x4,
  D3DTSS_ALPHAARG1 = 0x5,
  D3DTSS_ALPHAARG2 = 0x6,
  D3DTSS_BUMPENVMAT00 = 0x7,
  D3DTSS_BUMPENVMAT01 = 0x8,
  D3DTSS_BUMPENVMAT10 = 0x9,
  D3DTSS_BUMPENVMAT11 = 0xA,
  D3DTSS_TEXCOORDINDEX = 0xB,
  D3DTSS_BUMPENVLSCALE = 0x16,
  D3DTSS_BUMPENVLOFFSET = 0x17,
  D3DTSS_TEXTURETRANSFORMFLAGS = 0x18,
  D3DTSS_COLORARG0 = 0x1A,
  D3DTSS_ALPHAARG0 = 0x1B,
  D3DTSS_RESULTARG = 0x1C,
  D3DTSS_CONSTANT = 0x20,
  D3DTSS_FORCE_DWORD = 0x7FFFFFFF,
};

/* 248 */
enum _D3DSAMPLERSTATETYPE : __int32
{
  D3DSAMP_ADDRESSU = 0x1,
  D3DSAMP_ADDRESSV = 0x2,
  D3DSAMP_ADDRESSW = 0x3,
  D3DSAMP_BORDERCOLOR = 0x4,
  D3DSAMP_MAGFILTER = 0x5,
  D3DSAMP_MINFILTER = 0x6,
  D3DSAMP_MIPFILTER = 0x7,
  D3DSAMP_MIPMAPLODBIAS = 0x8,
  D3DSAMP_MAXMIPLEVEL = 0x9,
  D3DSAMP_MAXANISOTROPY = 0xA,
  D3DSAMP_SRGBTEXTURE = 0xB,
  D3DSAMP_ELEMENTINDEX = 0xC,
  D3DSAMP_DMAPOFFSET = 0xD,
  D3DSAMP_FORCE_DWORD = 0x7FFFFFFF,
};

/* 249 */
enum _D3DPRIMITIVETYPE : __int32
{
  D3DPT_POINTLIST = 0x1,
  D3DPT_LINELIST = 0x2,
  D3DPT_LINESTRIP = 0x3,
  D3DPT_TRIANGLELIST = 0x4,
  D3DPT_TRIANGLESTRIP = 0x5,
  D3DPT_TRIANGLEFAN = 0x6,
  D3DPT_FORCE_DWORD = 0x7FFFFFFF,
};

/* 250 */
enum _D3DQUERYTYPE : __int32
{
  D3DQUERYTYPE_VCACHE = 0x4,
  D3DQUERYTYPE_RESOURCEMANAGER = 0x5,
  D3DQUERYTYPE_VERTEXSTATS = 0x6,
  D3DQUERYTYPE_EVENT = 0x8,
  D3DQUERYTYPE_OCCLUSION = 0x9,
  D3DQUERYTYPE_TIMESTAMP = 0xA,
  D3DQUERYTYPE_TIMESTAMPDISJOINT = 0xB,
  D3DQUERYTYPE_TIMESTAMPFREQ = 0xC,
  D3DQUERYTYPE_PIPELINETIMINGS = 0xD,
  D3DQUERYTYPE_INTERFACETIMINGS = 0xE,
  D3DQUERYTYPE_VERTEXTIMINGS = 0xF,
  D3DQUERYTYPE_PIXELTIMINGS = 0x10,
  D3DQUERYTYPE_BANDWIDTHTIMINGS = 0x11,
  D3DQUERYTYPE_CACHEUTILIZATION = 0x12,
};

/* 251 */
struct /*VFT*/ IDirect3DDevice9_vtbl
{
  HRESULT (__stdcall *QueryInterface)(IUnknown *this, const _GUID *, void **);
  unsigned int (__stdcall *AddRef)(IUnknown *this);
  unsigned int (__stdcall *Release)(IUnknown *this);
  HRESULT (__stdcall *TestCooperativeLevel)(IDirect3DDevice9 *this);
  unsigned int (__stdcall *GetAvailableTextureMem)(IDirect3DDevice9 *this);
  HRESULT (__stdcall *EvictManagedResources)(IDirect3DDevice9 *this);
  HRESULT (__stdcall *GetDirect3D)(IDirect3DDevice9 *this, IDirect3D9 **);
  HRESULT (__stdcall *GetDeviceCaps)(IDirect3DDevice9 *this, _D3DCAPS9 *);
  HRESULT (__stdcall *GetDisplayMode)(IDirect3DDevice9 *this, unsigned int, _D3DDISPLAYMODE *);
  HRESULT (__stdcall *GetCreationParameters)(IDirect3DDevice9 *this, _D3DDEVICE_CREATION_PARAMETERS *);
  HRESULT (__stdcall *SetCursorProperties)(IDirect3DDevice9 *this, unsigned int, unsigned int, IDirect3DSurface9 *);
  void (__stdcall *SetCursorPosition)(IDirect3DDevice9 *this, int, int, unsigned int);
  int (__stdcall *ShowCursor)(IDirect3DDevice9 *this, int);
  HRESULT (__stdcall *CreateAdditionalSwapChain)(IDirect3DDevice9 *this, _D3DPRESENT_PARAMETERS_ *, IDirect3DSwapChain9 **);
  HRESULT (__stdcall *GetSwapChain)(IDirect3DDevice9 *this, unsigned int, IDirect3DSwapChain9 **);
  unsigned int (__stdcall *GetNumberOfSwapChains)(IDirect3DDevice9 *this);
  HRESULT (__stdcall *Reset)(IDirect3DDevice9 *this, _D3DPRESENT_PARAMETERS_ *);
  HRESULT (__stdcall *Present)(IDirect3DDevice9 *this, const tagRECT *, const tagRECT *, HWND__ *, const _RGNDATA *);
  HRESULT (__stdcall *GetBackBuffer)(IDirect3DDevice9 *this, unsigned int, unsigned int, _D3DBACKBUFFER_TYPE, IDirect3DSurface9 **);
  HRESULT (__stdcall *GetRasterStatus)(IDirect3DDevice9 *this, unsigned int, _D3DRASTER_STATUS *);
  HRESULT (__stdcall *SetDialogBoxMode)(IDirect3DDevice9 *this, int);
  void (__stdcall *SetGammaRamp)(IDirect3DDevice9 *this, unsigned int, unsigned int, const _D3DGAMMARAMP *);
  void (__stdcall *GetGammaRamp)(IDirect3DDevice9 *this, unsigned int, _D3DGAMMARAMP *);
  HRESULT (__stdcall *CreateTexture)(IDirect3DDevice9 *this, unsigned int, unsigned int, unsigned int, unsigned int, _D3DFORMAT, _D3DPOOL, IDirect3DTexture9 **, void **);
  HRESULT (__stdcall *CreateVolumeTexture)(IDirect3DDevice9 *this, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, _D3DFORMAT, _D3DPOOL, IDirect3DVolumeTexture9 **, void **);
  HRESULT (__stdcall *CreateCubeTexture)(IDirect3DDevice9 *this, unsigned int, unsigned int, unsigned int, _D3DFORMAT, _D3DPOOL, IDirect3DCubeTexture9 **, void **);
  HRESULT (__stdcall *CreateVertexBuffer)(IDirect3DDevice9 *this, unsigned int, unsigned int, unsigned int, _D3DPOOL, IDirect3DVertexBuffer9 **, void **);
  HRESULT (__stdcall *CreateIndexBuffer)(IDirect3DDevice9 *this, unsigned int, unsigned int, _D3DFORMAT, _D3DPOOL, IDirect3DIndexBuffer9 **, void **);
  HRESULT (__stdcall *CreateRenderTarget)(IDirect3DDevice9 *this, unsigned int, unsigned int, _D3DFORMAT, _D3DMULTISAMPLE_TYPE, unsigned int, int, IDirect3DSurface9 **, void **);
  HRESULT (__stdcall *CreateDepthStencilSurface)(IDirect3DDevice9 *this, unsigned int, unsigned int, _D3DFORMAT, _D3DMULTISAMPLE_TYPE, unsigned int, int, IDirect3DSurface9 **, void **);
  HRESULT (__stdcall *UpdateSurface)(IDirect3DDevice9 *this, IDirect3DSurface9 *, const tagRECT *, IDirect3DSurface9 *, const tagPOINT *);
  HRESULT (__stdcall *UpdateTexture)(IDirect3DDevice9 *this, IDirect3DBaseTexture9 *, IDirect3DBaseTexture9 *);
  HRESULT (__stdcall *GetRenderTargetData)(IDirect3DDevice9 *this, IDirect3DSurface9 *, IDirect3DSurface9 *);
  HRESULT (__stdcall *GetFrontBufferData)(IDirect3DDevice9 *this, unsigned int, IDirect3DSurface9 *);
  HRESULT (__stdcall *StretchRect)(IDirect3DDevice9 *this, IDirect3DSurface9 *, const tagRECT *, IDirect3DSurface9 *, const tagRECT *, _D3DTEXTUREFILTERTYPE);
  HRESULT (__stdcall *ColorFill)(IDirect3DDevice9 *this, IDirect3DSurface9 *, const tagRECT *, unsigned int);
  HRESULT (__stdcall *CreateOffscreenPlainSurface)(IDirect3DDevice9 *this, unsigned int, unsigned int, _D3DFORMAT, _D3DPOOL, IDirect3DSurface9 **, void **);
  HRESULT (__stdcall *SetRenderTarget)(IDirect3DDevice9 *this, unsigned int, IDirect3DSurface9 *);
  HRESULT (__stdcall *GetRenderTarget)(IDirect3DDevice9 *this, unsigned int, IDirect3DSurface9 **);
  HRESULT (__stdcall *SetDepthStencilSurface)(IDirect3DDevice9 *this, IDirect3DSurface9 *);
  HRESULT (__stdcall *GetDepthStencilSurface)(IDirect3DDevice9 *this, IDirect3DSurface9 **);
  HRESULT (__stdcall *BeginScene)(IDirect3DDevice9 *this);
  HRESULT (__stdcall *EndScene)(IDirect3DDevice9 *this);
  HRESULT (__stdcall *Clear)(IDirect3DDevice9 *this, unsigned int, const _D3DRECT *, unsigned int, unsigned int, float, unsigned int);
  HRESULT (__stdcall *SetTransform)(IDirect3DDevice9 *this, _D3DTRANSFORMSTATETYPE, const _D3DMATRIX *);
  HRESULT (__stdcall *GetTransform)(IDirect3DDevice9 *this, _D3DTRANSFORMSTATETYPE, _D3DMATRIX *);
  HRESULT (__stdcall *MultiplyTransform)(IDirect3DDevice9 *this, _D3DTRANSFORMSTATETYPE, const _D3DMATRIX *);
  HRESULT (__stdcall *SetViewport)(IDirect3DDevice9 *this, const _D3DVIEWPORT9 *);
  HRESULT (__stdcall *GetViewport)(IDirect3DDevice9 *this, _D3DVIEWPORT9 *);
  HRESULT (__stdcall *SetMaterial)(IDirect3DDevice9 *this, const _D3DMATERIAL9 *);
  HRESULT (__stdcall *GetMaterial)(IDirect3DDevice9 *this, _D3DMATERIAL9 *);
  HRESULT (__stdcall *SetLight)(IDirect3DDevice9 *this, unsigned int, const _D3DLIGHT9 *);
  HRESULT (__stdcall *GetLight)(IDirect3DDevice9 *this, unsigned int, _D3DLIGHT9 *);
  HRESULT (__stdcall *LightEnable)(IDirect3DDevice9 *this, unsigned int, int);
  HRESULT (__stdcall *GetLightEnable)(IDirect3DDevice9 *this, unsigned int, int *);
  HRESULT (__stdcall *SetClipPlane)(IDirect3DDevice9 *this, unsigned int, const float *);
  HRESULT (__stdcall *GetClipPlane)(IDirect3DDevice9 *this, unsigned int, float *);
  HRESULT (__stdcall *SetRenderState)(IDirect3DDevice9 *this, _D3DRENDERSTATETYPE, unsigned int);
  HRESULT (__stdcall *GetRenderState)(IDirect3DDevice9 *this, _D3DRENDERSTATETYPE, unsigned int *);
  HRESULT (__stdcall *CreateStateBlock)(IDirect3DDevice9 *this, _D3DSTATEBLOCKTYPE, IDirect3DStateBlock9 **);
  HRESULT (__stdcall *BeginStateBlock)(IDirect3DDevice9 *this);
  HRESULT (__stdcall *EndStateBlock)(IDirect3DDevice9 *this, IDirect3DStateBlock9 **);
  HRESULT (__stdcall *SetClipStatus)(IDirect3DDevice9 *this, const _D3DCLIPSTATUS9 *);
  HRESULT (__stdcall *GetClipStatus)(IDirect3DDevice9 *this, _D3DCLIPSTATUS9 *);
  HRESULT (__stdcall *GetTexture)(IDirect3DDevice9 *this, unsigned int, IDirect3DBaseTexture9 **);
  HRESULT (__stdcall *SetTexture)(IDirect3DDevice9 *this, unsigned int, IDirect3DBaseTexture9 *);
  HRESULT (__stdcall *GetTextureStageState)(IDirect3DDevice9 *this, unsigned int, _D3DTEXTURESTAGESTATETYPE, unsigned int *);
  HRESULT (__stdcall *SetTextureStageState)(IDirect3DDevice9 *this, unsigned int, _D3DTEXTURESTAGESTATETYPE, unsigned int);
  HRESULT (__stdcall *GetSamplerState)(IDirect3DDevice9 *this, unsigned int, _D3DSAMPLERSTATETYPE, unsigned int *);
  HRESULT (__stdcall *SetSamplerState)(IDirect3DDevice9 *this, unsigned int, _D3DSAMPLERSTATETYPE, unsigned int);
  HRESULT (__stdcall *ValidateDevice)(IDirect3DDevice9 *this, unsigned int *);
  HRESULT (__stdcall *SetPaletteEntries)(IDirect3DDevice9 *this, unsigned int, const tagPALETTEENTRY *);
  HRESULT (__stdcall *GetPaletteEntries)(IDirect3DDevice9 *this, unsigned int, tagPALETTEENTRY *);
  HRESULT (__stdcall *SetCurrentTexturePalette)(IDirect3DDevice9 *this, unsigned int);
  HRESULT (__stdcall *GetCurrentTexturePalette)(IDirect3DDevice9 *this, unsigned int *);
  HRESULT (__stdcall *SetScissorRect)(IDirect3DDevice9 *this, const tagRECT *);
  HRESULT (__stdcall *GetScissorRect)(IDirect3DDevice9 *this, tagRECT *);
  HRESULT (__stdcall *SetSoftwareVertexProcessing)(IDirect3DDevice9 *this, int);
  int (__stdcall *GetSoftwareVertexProcessing)(IDirect3DDevice9 *this);
  HRESULT (__stdcall *SetNPatchMode)(IDirect3DDevice9 *this, float);
  float (__stdcall *GetNPatchMode)(IDirect3DDevice9 *this);
  HRESULT (__stdcall *DrawPrimitive)(IDirect3DDevice9 *this, _D3DPRIMITIVETYPE, unsigned int, unsigned int);
  HRESULT (__stdcall *DrawIndexedPrimitive)(IDirect3DDevice9 *this, _D3DPRIMITIVETYPE, int, unsigned int, unsigned int, unsigned int, unsigned int);
  HRESULT (__stdcall *DrawPrimitiveUP)(IDirect3DDevice9 *this, _D3DPRIMITIVETYPE, unsigned int, const void *, unsigned int);
  HRESULT (__stdcall *DrawIndexedPrimitiveUP)(IDirect3DDevice9 *this, _D3DPRIMITIVETYPE, unsigned int, unsigned int, unsigned int, const void *, _D3DFORMAT, const void *, unsigned int);
  HRESULT (__stdcall *ProcessVertices)(IDirect3DDevice9 *this, unsigned int, unsigned int, unsigned int, IDirect3DVertexBuffer9 *, IDirect3DVertexDeclaration9 *, unsigned int);
  HRESULT (__stdcall *CreateVertexDeclaration)(IDirect3DDevice9 *this, const _D3DVERTEXELEMENT9 *, IDirect3DVertexDeclaration9 **);
  HRESULT (__stdcall *SetVertexDeclaration)(IDirect3DDevice9 *this, IDirect3DVertexDeclaration9 *);
  HRESULT (__stdcall *GetVertexDeclaration)(IDirect3DDevice9 *this, IDirect3DVertexDeclaration9 **);
  HRESULT (__stdcall *SetFVF)(IDirect3DDevice9 *this, unsigned int);
  HRESULT (__stdcall *GetFVF)(IDirect3DDevice9 *this, unsigned int *);
  HRESULT (__stdcall *CreateVertexShader)(IDirect3DDevice9 *this, const unsigned int *, IDirect3DVertexShader9 **);
  HRESULT (__stdcall *SetVertexShader)(IDirect3DDevice9 *this, IDirect3DVertexShader9 *);
  HRESULT (__stdcall *GetVertexShader)(IDirect3DDevice9 *this, IDirect3DVertexShader9 **);
  HRESULT (__stdcall *SetVertexShaderConstantF)(IDirect3DDevice9 *this, unsigned int, const float *, unsigned int);
  HRESULT (__stdcall *GetVertexShaderConstantF)(IDirect3DDevice9 *this, unsigned int, float *, unsigned int);
  HRESULT (__stdcall *SetVertexShaderConstantI)(IDirect3DDevice9 *this, unsigned int, const int *, unsigned int);
  HRESULT (__stdcall *GetVertexShaderConstantI)(IDirect3DDevice9 *this, unsigned int, int *, unsigned int);
  HRESULT (__stdcall *SetVertexShaderConstantB)(IDirect3DDevice9 *this, unsigned int, const int *, unsigned int);
  HRESULT (__stdcall *GetVertexShaderConstantB)(IDirect3DDevice9 *this, unsigned int, int *, unsigned int);
  HRESULT (__stdcall *SetStreamSource)(IDirect3DDevice9 *this, unsigned int, IDirect3DVertexBuffer9 *, unsigned int, unsigned int);
  HRESULT (__stdcall *GetStreamSource)(IDirect3DDevice9 *this, unsigned int, IDirect3DVertexBuffer9 **, unsigned int *, unsigned int *);
  HRESULT (__stdcall *SetStreamSourceFreq)(IDirect3DDevice9 *this, unsigned int, unsigned int);
  HRESULT (__stdcall *GetStreamSourceFreq)(IDirect3DDevice9 *this, unsigned int, unsigned int *);
  HRESULT (__stdcall *SetIndices)(IDirect3DDevice9 *this, IDirect3DIndexBuffer9 *);
  HRESULT (__stdcall *GetIndices)(IDirect3DDevice9 *this, IDirect3DIndexBuffer9 **);
  HRESULT (__stdcall *CreatePixelShader)(IDirect3DDevice9 *this, const unsigned int *, IDirect3DPixelShader9 **);
  HRESULT (__stdcall *SetPixelShader)(IDirect3DDevice9 *this, IDirect3DPixelShader9 *);
  HRESULT (__stdcall *GetPixelShader)(IDirect3DDevice9 *this, IDirect3DPixelShader9 **);
  HRESULT (__stdcall *SetPixelShaderConstantF)(IDirect3DDevice9 *this, unsigned int, const float *, unsigned int);
  HRESULT (__stdcall *GetPixelShaderConstantF)(IDirect3DDevice9 *this, unsigned int, float *, unsigned int);
  HRESULT (__stdcall *SetPixelShaderConstantI)(IDirect3DDevice9 *this, unsigned int, const int *, unsigned int);
  HRESULT (__stdcall *GetPixelShaderConstantI)(IDirect3DDevice9 *this, unsigned int, int *, unsigned int);
  HRESULT (__stdcall *SetPixelShaderConstantB)(IDirect3DDevice9 *this, unsigned int, const int *, unsigned int);
  HRESULT (__stdcall *GetPixelShaderConstantB)(IDirect3DDevice9 *this, unsigned int, int *, unsigned int);
  HRESULT (__stdcall *DrawRectPatch)(IDirect3DDevice9 *this, unsigned int, const float *, const _D3DRECTPATCH_INFO *);
  HRESULT (__stdcall *DrawTriPatch)(IDirect3DDevice9 *this, unsigned int, const float *, const _D3DTRIPATCH_INFO *);
  HRESULT (__stdcall *DeletePatch)(IDirect3DDevice9 *this, unsigned int);
  HRESULT (__stdcall *CreateQuery)(IDirect3DDevice9 *this, _D3DQUERYTYPE, IDirect3DQuery9 **);
};

/* 102 */
struct __cppobj IUnknown
{
  IUnknown_vtbl *__vftable /*VFT*/;
};

/* 80 */
struct _GUID
{
  unsigned int Data1;
  unsigned __int16 Data2;
  unsigned __int16 Data3;
  unsigned __int8 Data4[8];
};

/* 252 */
struct __cppobj IDirect3DDevice9 : IUnknown
{
};

/* 253 */
struct __cppobj IDirect3D9 : IUnknown
{
};

/* 254 */
enum _D3DDEVTYPE : __int32
{
  D3DDEVTYPE_HAL = 0x1,
  D3DDEVTYPE_REF = 0x2,
  D3DDEVTYPE_SW = 0x3,
  D3DDEVTYPE_NULLREF = 0x4,
  D3DDEVTYPE_FORCE_DWORD = 0x7FFFFFFF,
};

/* 255 */
struct _D3DVSHADERCAPS2_0
{
  unsigned int Caps;
  int DynamicFlowControlDepth;
  int NumTemps;
  int StaticFlowControlDepth;
};

/* 256 */
struct _D3DPSHADERCAPS2_0
{
  unsigned int Caps;
  int DynamicFlowControlDepth;
  int NumTemps;
  int StaticFlowControlDepth;
  int NumInstructionSlots;
};

/* 257 */
struct _D3DCAPS9
{
  _D3DDEVTYPE DeviceType;
  unsigned int AdapterOrdinal;
  unsigned int Caps;
  unsigned int Caps2;
  unsigned int Caps3;
  unsigned int PresentationIntervals;
  unsigned int CursorCaps;
  unsigned int DevCaps;
  unsigned int PrimitiveMiscCaps;
  unsigned int RasterCaps;
  unsigned int ZCmpCaps;
  unsigned int SrcBlendCaps;
  unsigned int DestBlendCaps;
  unsigned int AlphaCmpCaps;
  unsigned int ShadeCaps;
  unsigned int TextureCaps;
  unsigned int TextureFilterCaps;
  unsigned int CubeTextureFilterCaps;
  unsigned int VolumeTextureFilterCaps;
  unsigned int TextureAddressCaps;
  unsigned int VolumeTextureAddressCaps;
  unsigned int LineCaps;
  unsigned int MaxTextureWidth;
  unsigned int MaxTextureHeight;
  unsigned int MaxVolumeExtent;
  unsigned int MaxTextureRepeat;
  unsigned int MaxTextureAspectRatio;
  unsigned int MaxAnisotropy;
  float MaxVertexW;
  float GuardBandLeft;
  float GuardBandTop;
  float GuardBandRight;
  float GuardBandBottom;
  float ExtentsAdjust;
  unsigned int StencilCaps;
  unsigned int FVFCaps;
  unsigned int TextureOpCaps;
  unsigned int MaxTextureBlendStages;
  unsigned int MaxSimultaneousTextures;
  unsigned int VertexProcessingCaps;
  unsigned int MaxActiveLights;
  unsigned int MaxUserClipPlanes;
  unsigned int MaxVertexBlendMatrices;
  unsigned int MaxVertexBlendMatrixIndex;
  float MaxPointSize;
  unsigned int MaxPrimitiveCount;
  unsigned int MaxVertexIndex;
  unsigned int MaxStreams;
  unsigned int MaxStreamStride;
  unsigned int VertexShaderVersion;
  unsigned int MaxVertexShaderConst;
  unsigned int PixelShaderVersion;
  float PixelShader1xMaxValue;
  unsigned int DevCaps2;
  float MaxNpatchTessellationLevel;
  unsigned int Reserved5;
  unsigned int MasterAdapterOrdinal;
  unsigned int AdapterOrdinalInGroup;
  unsigned int NumberOfAdaptersInGroup;
  unsigned int DeclTypes;
  unsigned int NumSimultaneousRTs;
  unsigned int StretchRectFilterCaps;
  _D3DVSHADERCAPS2_0 VS20Caps;
  _D3DPSHADERCAPS2_0 PS20Caps;
  unsigned int VertexTextureFilterCaps;
  unsigned int MaxVShaderInstructionsExecuted;
  unsigned int MaxPShaderInstructionsExecuted;
  unsigned int MaxVertexShader30InstructionSlots;
  unsigned int MaxPixelShader30InstructionSlots;
};

/* 258 */
struct _D3DDISPLAYMODE
{
  unsigned int Width;
  unsigned int Height;
  unsigned int RefreshRate;
  _D3DFORMAT Format;
};

/* 259 */
struct _D3DDEVICE_CREATION_PARAMETERS
{
  unsigned int AdapterOrdinal;
  _D3DDEVTYPE DeviceType;
  HWND__ *hFocusWindow;
  unsigned int BehaviorFlags;
};

/* 260 */
struct __cppobj IDirect3DResource9 : IUnknown
{
};

/* 261 */
struct __cppobj IDirect3DSurface9 : IDirect3DResource9
{
};

/* 262 */
enum _D3DSWAPEFFECT : __int32
{
  D3DSWAPEFFECT_DISCARD = 0x1,
  D3DSWAPEFFECT_FLIP = 0x2,
  D3DSWAPEFFECT_COPY = 0x3,
  D3DSWAPEFFECT_FORCE_DWORD = 0x7FFFFFFF,
};

/* 263 */
struct _D3DPRESENT_PARAMETERS_
{
  unsigned int BackBufferWidth;
  unsigned int BackBufferHeight;
  _D3DFORMAT BackBufferFormat;
  unsigned int BackBufferCount;
  _D3DMULTISAMPLE_TYPE MultiSampleType;
  unsigned int MultiSampleQuality;
  _D3DSWAPEFFECT SwapEffect;
  HWND__ *hDeviceWindow;
  int Windowed;
  int EnableAutoDepthStencil;
  _D3DFORMAT AutoDepthStencilFormat;
  unsigned int Flags;
  unsigned int FullScreen_RefreshRateInHz;
  unsigned int PresentationInterval;
};

/* 264 */
struct __cppobj IDirect3DSwapChain9 : IUnknown
{
};

/* 47 */
struct tagRECT
{
  int left;
  int top;
  int right;
  int bottom;
};

/* 41 */
struct HWND__
{
  int unused;
};

/* 265 */
struct _RGNDATAHEADER
{
  unsigned int dwSize;
  unsigned int iType;
  unsigned int nCount;
  unsigned int nRgnSize;
  tagRECT rcBound;
};

/* 266 */
struct __declspec(align(4)) _RGNDATA
{
  _RGNDATAHEADER rdh;
  char Buffer[1];
};

/* 267 */
struct _D3DRASTER_STATUS
{
  int InVBlank;
  unsigned int ScanLine;
};

/* 268 */
struct _D3DGAMMARAMP
{
  unsigned __int16 red[256];
  unsigned __int16 green[256];
  unsigned __int16 blue[256];
};

/* 269 */
struct __cppobj IDirect3DBaseTexture9 : IDirect3DResource9
{
};

/* 270 */
struct __cppobj IDirect3DTexture9 : IDirect3DBaseTexture9
{
};

/* 271 */
struct __cppobj IDirect3DVolumeTexture9 : IDirect3DBaseTexture9
{
};

/* 272 */
struct __cppobj IDirect3DCubeTexture9 : IDirect3DBaseTexture9
{
};

/* 273 */
struct __cppobj IDirect3DVertexBuffer9 : IDirect3DResource9
{
};

/* 274 */
struct __cppobj IDirect3DIndexBuffer9 : IDirect3DResource9
{
};

/* 71 */
struct tagPOINT
{
  int x;
  int y;
};

/* 275 */
struct _D3DRECT
{
  int x1;
  int y1;
  int x2;
  int y2;
};

/* 276 */
struct $40942CBCB8F0A1CDBC81269929B28324
{
  float _11;
  float _12;
  float _13;
  float _14;
  float _21;
  float _22;
  float _23;
  float _24;
  float _31;
  float _32;
  float _33;
  float _34;
  float _41;
  float _42;
  float _43;
  float _44;
};

/* 277 */
union $035D0D8F022FF74D25F9D57A9AC08E23
{
  $40942CBCB8F0A1CDBC81269929B28324 __s0;
  float m[4][4];
};

/* 278 */
struct _D3DMATRIX
{
  $035D0D8F022FF74D25F9D57A9AC08E23 ___u0;
};

/* 279 */
struct _D3DVIEWPORT9
{
  unsigned int X;
  unsigned int Y;
  unsigned int Width;
  unsigned int Height;
  float MinZ;
  float MaxZ;
};

/* 280 */
struct _D3DCOLORVALUE
{
  float r;
  float g;
  float b;
  float a;
};

/* 281 */
struct _D3DMATERIAL9
{
  _D3DCOLORVALUE Diffuse;
  _D3DCOLORVALUE Ambient;
  _D3DCOLORVALUE Specular;
  _D3DCOLORVALUE Emissive;
  float Power;
};

/* 282 */
enum _D3DLIGHTTYPE : __int32
{
  D3DLIGHT_POINT = 0x1,
  D3DLIGHT_SPOT = 0x2,
  D3DLIGHT_DIRECTIONAL = 0x3,
  D3DLIGHT_FORCE_DWORD = 0x7FFFFFFF,
};

/* 283 */
struct _D3DVECTOR
{
  float x;
  float y;
  float z;
};

/* 284 */
struct _D3DLIGHT9
{
  _D3DLIGHTTYPE Type;
  _D3DCOLORVALUE Diffuse;
  _D3DCOLORVALUE Specular;
  _D3DCOLORVALUE Ambient;
  _D3DVECTOR Position;
  _D3DVECTOR Direction;
  float Range;
  float Falloff;
  float Attenuation0;
  float Attenuation1;
  float Attenuation2;
  float Theta;
  float Phi;
};

/* 285 */
struct __cppobj IDirect3DStateBlock9 : IUnknown
{
};

/* 286 */
struct _D3DCLIPSTATUS9
{
  unsigned int ClipUnion;
  unsigned int ClipIntersection;
};

/* 287 */
struct tagPALETTEENTRY
{
  unsigned __int8 peRed;
  unsigned __int8 peGreen;
  unsigned __int8 peBlue;
  unsigned __int8 peFlags;
};

/* 288 */
struct __cppobj IDirect3DVertexDeclaration9 : IUnknown
{
};

/* 289 */
struct _D3DVERTEXELEMENT9
{
  unsigned __int16 Stream;
  unsigned __int16 Offset;
  unsigned __int8 Type;
  unsigned __int8 Method;
  unsigned __int8 Usage;
  unsigned __int8 UsageIndex;
};

/* 290 */
struct __cppobj IDirect3DVertexShader9 : IUnknown
{
};

/* 291 */
struct __cppobj IDirect3DPixelShader9 : IUnknown
{
};

/* 292 */
enum _D3DBASISTYPE : __int32
{
  D3DBASIS_BEZIER = 0x0,
  D3DBASIS_BSPLINE = 0x1,
  D3DBASIS_CATMULL_ROM = 0x2,
  D3DBASIS_FORCE_DWORD = 0x7FFFFFFF,
};

/* 293 */
enum _D3DDEGREETYPE : __int32
{
  D3DDEGREE_LINEAR = 0x1,
  D3DDEGREE_QUADRATIC = 0x2,
  D3DDEGREE_CUBIC = 0x3,
  D3DDEGREE_QUINTIC = 0x5,
  D3DDEGREE_FORCE_DWORD = 0x7FFFFFFF,
};

/* 294 */
struct _D3DRECTPATCH_INFO
{
  unsigned int StartVertexOffsetWidth;
  unsigned int StartVertexOffsetHeight;
  unsigned int Width;
  unsigned int Height;
  unsigned int Stride;
  _D3DBASISTYPE Basis;
  _D3DDEGREETYPE Degree;
};

/* 295 */
struct _D3DTRIPATCH_INFO
{
  unsigned int StartVertexOffset;
  unsigned int NumVertices;
  _D3DBASISTYPE Basis;
  _D3DDEGREETYPE Degree;
};

/* 296 */
struct __cppobj IDirect3DQuery9 : IUnknown
{
};

/* 238 */
struct /*VFT*/ IUnknown_vtbl
{
  HRESULT (__stdcall *QueryInterface)(IUnknown *this, const _GUID *, void **);
  unsigned int (__stdcall *AddRef)(IUnknown *this);
  unsigned int (__stdcall *Release)(IUnknown *this);
};

