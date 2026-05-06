#pragma once

// Written once at init, read from the single D3D9 thread — no locks needed.
namespace shared::globals
{
	extern D3DXMATRIX IDENTITY;
	
	extern std::string root_path;
	extern HWND main_window;

#define EXE_BASE shared::globals::exe_module_addr

	extern HMODULE exe_hmodule;
	extern DWORD exe_module_addr; // x64: use uintptr_t
	extern DWORD exe_size;
	extern void setup_exe_module();

	extern HMODULE dll_hmodule;
	extern DWORD dll_module_addr; // x64: use uintptr_t
	extern void setup_dll_module(const HMODULE mod);

	extern void setup_homepath();

	extern IDirect3DDevice9* d3d_device;
	extern IDirect3D9* d3d9_interface;

	// Module handle of the real d3d9 chain (Remix bridge or system d3d9.dll).
	// Set by d3d9_proxy::init(), consumed by remix_api for API lookups.
	extern HMODULE d3d9_chain_module;

	extern bool imgui_is_rendering;
	extern bool imgui_menu_open;
	extern bool imgui_allow_input_bypass;
	extern bool imgui_wants_text_input;
	extern uint32_t imgui_allow_input_bypass_timeout;
}
