#include "std_include.hpp"
#include <psapi.h>

#include "comp.hpp"
#include "d3d9_proxy.hpp"
#include "shared/common/flags.hpp"
#include "shared/common/config.hpp"

namespace comp
{
	std::unordered_set<HWND> wnd_class_list;

	// #Step 1: First launch will dump every visible top-level window's class in the debug
	// console. Copy the class name of the render viewport (the main game window) here.
	// Matching is substring-based (std::string_view::contains), so pick a distinctive portion
	// that won't collide with dialogs (#32770), consoles (ConsoleWindowClass), or our
	// D3DProxyWindow. Examples by engine:
	//   UE2.5 (Tribes Vengeance): "UnrealWWindowsViewport"
	//   Mount & Blade Warband:    "mb_warband"
	//   etc.
	#define WINDOW_CLASS_NAME "YOUR_WINDOW_CLASS_NAME"

	BOOL CALLBACK enum_windows_proc(HWND hwnd, LPARAM lParam)
	{
		DWORD window_pid, target_pid = static_cast<DWORD>(lParam);
		GetWindowThreadProcessId(hwnd, &window_pid);

		if (window_pid == target_pid && IsWindowVisible(hwnd))
		{
			char class_name[256];
			GetClassNameA(hwnd, class_name, sizeof(class_name));

			if (!wnd_class_list.contains(hwnd))
			{
				char debug_msg[256];
				wsprintfA(debug_msg, "> HWND: %p, PID: %u, Class: %s, Visible: %d \n", hwnd, window_pid, class_name, IsWindowVisible(hwnd));
				shared::common::log("Main", debug_msg, shared::common::LOG_TYPE::LOG_TYPE_DEFAULT, false);
				wnd_class_list.insert(hwnd);
			}

			if (std::string_view(class_name).contains(WINDOW_CLASS_NAME))
			{
				shared::globals::main_window = hwnd;
				return FALSE;
			}
		}

		return TRUE;
	}

	DWORD WINAPI find_game_window([[maybe_unused]] LPVOID lpParam)
	{
		std::uint32_t T = 0;

		shared::common::log("Main", "Waiting for window with classname containing '" WINDOW_CLASS_NAME "' ...", shared::common::LOG_TYPE::LOG_TYPE_DEFAULT, false);
		{
			while (!shared::globals::main_window)
			{
				EnumWindows(enum_windows_proc, static_cast<LPARAM>(GetCurrentProcessId()));
				if (!shared::globals::main_window) {
					Sleep(1u); T += 1u;
				}

				if (T >= 30000)
				{
					Beep(300, 100); Sleep(100); Beep(200, 100);
					shared::common::log("Main", "Could not find '" WINDOW_CLASS_NAME "' Window. Not loading RTX Compatibility Mod.", shared::common::LOG_TYPE::LOG_TYPE_ERROR, true);
					return TRUE;
				}
			}
		}

		if (!shared::common::flags::has_flag("nobeep")) {
			Beep(523, 100);
		}

		// Post-load DLLs (after window is found, game is running)
		d3d9_proxy::load_postload_dlls();

		comp::main();
		return 0;
	}
}

BOOL APIENTRY DllMain(HMODULE hmodule, const DWORD ul_reason_for_call, LPVOID)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		// Self-pin. Many engines probe d3d9.dll with LoadLibrary → call one export → FreeLibrary
		// before the real CreateDevice. Without pinning, Windows unloads our proxy image while
		// the game still holds wrapped COM objects whose vtables point into our code; the next
		// virtual call lands in decommitted pages and DEP-faults. Pinning forces the image to
		// stay mapped for the process lifetime. Same technique as dxvk / d9vk / ReShade.
		// Confirmed needed on UE2.5 (Tribes Vengeance). If a future game doesn't need it, the
		// call is harmless — it just keeps us resident.
		{
			HMODULE self = nullptr;
			GetModuleHandleExW(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
				reinterpret_cast<LPCWSTR>(&DllMain), &self);
		}

		shared::common::console();
		shared::globals::setup_dll_module(hmodule);
		shared::globals::setup_exe_module();
		shared::globals::setup_homepath();

		shared::common::set_console_color_blue(true);
		std::cout << "Launching RTX Remix Comp [" << COMP_MOD_VERSION_MAJOR << "." << COMP_MOD_VERSION_MINOR << "." << COMP_MOD_VERSION_PATCH << "]\n";
		std::cout << "> Compiled On : " + std::string(__DATE__) + " " + std::string(__TIME__) + "\n";
		std::cout << "> Based on xoxor4d/remix-comp-base\n";
		std::cout << "> Adapted by kim2091 for Vibe Reverse Engineering\n";
		std::cout << "> Running as d3d9.dll proxy\n\n";
		shared::common::set_console_color_default();

		// Load config from INI file next to the DLL
		shared::common::config::get().load(shared::globals::root_path + "\\remix-comp-proxy.ini");

		// Pre-load DLLs (before the d3d9 chain is established)
		d3d9_proxy::load_preload_dlls();

		// Load the real d3d9 chain (Remix bridge or system d3d9.dll)
		if (!d3d9_proxy::init())
			return TRUE;

		if (const auto MH_INIT_STATUS = MH_Initialize(); MH_INIT_STATUS != MH_STATUS::MH_OK)
		{
			shared::common::log("Main", std::format("MinHook failed to initialize with code: {:d}", static_cast<int>(MH_INIT_STATUS)), shared::common::LOG_TYPE::LOG_TYPE_ERROR, true);
			return TRUE;
		}

		// Setup memory addresses (eg. patterns)
		comp::game::init_game_addresses();

		// Find game window thread (registers modules once window is found)
		if (const auto t = CreateThread(nullptr, 0, comp::find_game_window, nullptr, 0, nullptr); t) {
			CloseHandle(t);
		}
	}

	return TRUE;
}
