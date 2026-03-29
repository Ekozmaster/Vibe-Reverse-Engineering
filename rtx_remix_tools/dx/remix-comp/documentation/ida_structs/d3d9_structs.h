#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

struct _GUID;
struct IUnknown;
struct IUnknown_vtbl;
struct HWND__;
struct IDirect3DDevice9;
struct IDirect3D9;
struct _D3DADAPTER_IDENTIFIER9;
struct _D3DDISPLAYMODE;
struct _D3DCAPS9;
struct HMONITOR__;
struct _D3DPRESENT_PARAMETERS_;

/* 2393 */
typedef int HRESULT;

/* 111 */
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

/* 160 */
enum _D3DDEVTYPE : __int32
{
  D3DDEVTYPE_HAL = 0x1,
  D3DDEVTYPE_REF = 0x2,
  D3DDEVTYPE_SW = 0x3,
  D3DDEVTYPE_NULLREF = 0x4,
  D3DDEVTYPE_FORCE_DWORD = 0x7FFFFFFF,
};

/* 109 */
enum _D3DRESOURCETYPE : __int32
{
  D3DRTYPE_SURFACE = 0x1,
  D3DRTYPE_VOLUME = 0x2,
  D3DRTYPE_TEXTURE = 0x3,
  D3DRTYPE_VOLUMETEXTURE = 0x4,
  D3DRTYPE_CUBETEXTURE = 0x5,
  D3DRTYPE_VERTEXBUFFER = 0x6,
  D3DRTYPE_INDEXBUFFER = 0x7,
  D3DRTYPE_FORCE_DWORD = 0x7FFFFFFF,
};

/* 114 */
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

/* 941 */
struct /*VFT*/ IDirect3D9_vtbl
{
  HRESULT (__stdcall *QueryInterface)(IUnknown *this, const _GUID *, void **);
  unsigned int (__stdcall *AddRef)(IUnknown *this);
  unsigned int (__stdcall *Release)(IUnknown *this);
  HRESULT (__stdcall *RegisterSoftwareDevice)(IDirect3D9 *this, void *);
  unsigned int (__stdcall *GetAdapterCount)(IDirect3D9 *this);
  HRESULT (__stdcall *GetAdapterIdentifier)(IDirect3D9 *this, unsigned int, unsigned int, _D3DADAPTER_IDENTIFIER9 *);
  unsigned int (__stdcall *GetAdapterModeCount)(IDirect3D9 *this, unsigned int, _D3DFORMAT);
  HRESULT (__stdcall *EnumAdapterModes)(IDirect3D9 *this, unsigned int, _D3DFORMAT, unsigned int, _D3DDISPLAYMODE *);
  HRESULT (__stdcall *GetAdapterDisplayMode)(IDirect3D9 *this, unsigned int, _D3DDISPLAYMODE *);
  HRESULT (__stdcall *CheckDeviceType)(IDirect3D9 *this, unsigned int, _D3DDEVTYPE, _D3DFORMAT, _D3DFORMAT, int);
  HRESULT (__stdcall *CheckDeviceFormat)(IDirect3D9 *this, unsigned int, _D3DDEVTYPE, _D3DFORMAT, unsigned int, _D3DRESOURCETYPE, _D3DFORMAT);
  HRESULT (__stdcall *CheckDeviceMultiSampleType)(IDirect3D9 *this, unsigned int, _D3DDEVTYPE, _D3DFORMAT, int, _D3DMULTISAMPLE_TYPE, unsigned int *);
  HRESULT (__stdcall *CheckDepthStencilMatch)(IDirect3D9 *this, unsigned int, _D3DDEVTYPE, _D3DFORMAT, _D3DFORMAT, _D3DFORMAT);
  HRESULT (__stdcall *CheckDeviceFormatConversion)(IDirect3D9 *this, unsigned int, _D3DDEVTYPE, _D3DFORMAT, _D3DFORMAT);
  HRESULT (__stdcall *GetDeviceCaps)(IDirect3D9 *this, unsigned int, _D3DDEVTYPE, _D3DCAPS9 *);
  HMONITOR__ *(__stdcall *GetAdapterMonitor)(IDirect3D9 *this, unsigned int);
  HRESULT (__stdcall *CreateDevice)(IDirect3D9 *this, unsigned int, _D3DDEVTYPE, HWND__ *, unsigned int, _D3DPRESENT_PARAMETERS_ *, IDirect3DDevice9 **);
};

/* 438 */
struct __cppobj IUnknown
{
  IUnknown_vtbl *__vftable /*VFT*/;
};

/* 437 */
const struct _GUID
{
  unsigned int Data1;
  unsigned __int16 Data2;
  unsigned __int16 Data3;
  unsigned __int8 Data4[8];
};

/* 933 */
struct __cppobj IDirect3D9 : IUnknown
{
};

/* 552 */
struct $FAF74743FBE1C8632047CFB668F7028A
{
  unsigned int LowPart;
  int HighPart;
};

/* 551 */
struct _LARGE_INTEGER_s
{
  unsigned int LowPart;
  int HighPart;
};

/* 553 */
union _LARGE_INTEGER
{
  $FAF74743FBE1C8632047CFB668F7028A __s0;
  _LARGE_INTEGER_s u;
  __int64 QuadPart;
};

/* 934 */
struct __unaligned __declspec(align(4)) _D3DADAPTER_IDENTIFIER9
{
  char Driver[512];
  char Description[512];
  char DeviceName[32];
  _LARGE_INTEGER DriverVersion;
  unsigned int VendorId;
  unsigned int DeviceId;
  unsigned int SubSysId;
  unsigned int Revision;
  _GUID DeviceIdentifier;
  unsigned int WHQLLevel;
};

/* 935 */
struct _D3DDISPLAYMODE
{
  unsigned int Width;
  unsigned int Height;
  unsigned int RefreshRate;
  _D3DFORMAT Format;
};

/* 936 */
struct _D3DVSHADERCAPS2_0
{
  unsigned int Caps;
  int DynamicFlowControlDepth;
  int NumTemps;
  int StaticFlowControlDepth;
};

/* 937 */
struct _D3DPSHADERCAPS2_0
{
  unsigned int Caps;
  int DynamicFlowControlDepth;
  int NumTemps;
  int StaticFlowControlDepth;
  int NumInstructionSlots;
};

/* 938 */
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

/* 939 */
struct HMONITOR__
{
  int unused;
};

/* 864 */
struct HWND__
{
  int unused;
};

/* 119 */
enum _D3DSWAPEFFECT : __int32
{
  D3DSWAPEFFECT_DISCARD = 0x1,
  D3DSWAPEFFECT_FLIP = 0x2,
  D3DSWAPEFFECT_COPY = 0x3,
  D3DSWAPEFFECT_FORCE_DWORD = 0x7FFFFFFF,
};

/* 940 */
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

/* 932 */
struct __cppobj IDirect3DDevice9 : IUnknown
{
};

/* 439 */
struct /*VFT*/ IUnknown_vtbl
{
  HRESULT (__stdcall *QueryInterface)(IUnknown *this, const _GUID *, void **);
  unsigned int (__stdcall *AddRef)(IUnknown *this);
  unsigned int (__stdcall *Release)(IUnknown *this);
};

