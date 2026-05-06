#pragma once

namespace d3d9_proxy
{
	// Function pointer types for real d3d9 exports
	typedef IDirect3D9* (WINAPI* PFN_Direct3DCreate9)(UINT);
	typedef HRESULT (WINAPI* PFN_Direct3DCreate9Ex)(UINT, IDirect3D9Ex**);
	typedef int (WINAPI* PFN_D3DPERF_BeginEvent)(D3DCOLOR, LPCWSTR);
	typedef int (WINAPI* PFN_D3DPERF_EndEvent)();
	typedef void (WINAPI* PFN_D3DPERF_SetMarker)(D3DCOLOR, LPCWSTR);
	typedef void (WINAPI* PFN_D3DPERF_SetRegion)(D3DCOLOR, LPCWSTR);
	typedef BOOL (WINAPI* PFN_D3DPERF_QueryRepeatFrame)();
	typedef void (WINAPI* PFN_D3DPERF_SetOptions)(DWORD);
	typedef DWORD (WINAPI* PFN_D3DPERF_GetStatus)();

	// Load the real d3d9 chain (Remix bridge or system d3d9) and resolve exports.
	// Must be called after config is loaded.
	bool init();

	// Load DLL/ASI chains from config
	void load_preload_dlls();
	void load_postload_dlls();

	// Module handle for the real d3d9 chain (Remix bridge or system d3d9.dll)
	HMODULE get_chain_module();

	// Real d3d9 function pointers (call these to reach the underlying implementation)
	PFN_Direct3DCreate9      get_Direct3DCreate9();
	PFN_Direct3DCreate9Ex    get_Direct3DCreate9Ex();
	PFN_D3DPERF_BeginEvent   get_D3DPERF_BeginEvent();
	PFN_D3DPERF_EndEvent     get_D3DPERF_EndEvent();
	PFN_D3DPERF_SetMarker    get_D3DPERF_SetMarker();
	PFN_D3DPERF_SetRegion    get_D3DPERF_SetRegion();
	PFN_D3DPERF_QueryRepeatFrame get_D3DPERF_QueryRepeatFrame();
	PFN_D3DPERF_SetOptions   get_D3DPERF_SetOptions();
	PFN_D3DPERF_GetStatus    get_D3DPERF_GetStatus();
	FARPROC                  get_Direct3DShaderValidatorCreate9();
	FARPROC                  get_DebugSetLevel();
	FARPROC                  get_DebugSetMute();
}
