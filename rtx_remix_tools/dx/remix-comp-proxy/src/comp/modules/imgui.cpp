#include "std_include.hpp"
#include "imgui.hpp"

#include "imgui_internal.h"
#include "renderer.hpp"
#include "tracer.hpp"
#include "diagnostics.hpp"
#include "shared/common/imgui_helper.hpp"
#include "shared/common/ffp_state.hpp"
#include "shared/common/config.hpp"

// Allow us to directly call the ImGui WndProc function.
extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

#define CENTER_URL(text, link)					\
	ImGui::SetCursorForCenteredText((text));	\
	ImGui::TextURL((text), (link), true);

#define SPACEY16 ImGui::Spacing(0.0f, 16.0f);
#define SPACEY8 ImGui::Spacing(0.0f, 8.0f);

namespace comp
{
	WNDPROC g_game_wndproc = nullptr;
	
	LRESULT __stdcall wnd_proc_hk(HWND window, UINT message_type, WPARAM wparam, LPARAM lparam)
	{
		if (message_type != WM_MOUSEMOVE && message_type != WM_NCMOUSEMOVE)
		{
			if (imgui::get()->input_message(message_type, wparam, lparam)) {
			//	return true;
			}
		}

		// if your game has issues with floating cursors
		/*if (message_type == WM_KILLFOCUS)
		{
			uint32_t counter = 0u;
			while (::ShowCursor(TRUE) < 0 && ++counter < 3) {}
			ClipCursor(NULL);
		}*/

		//printf("MSG 0x%x -- w: 0x%x -- l: 0x%x\n", message_type, wparam, lparam);
		return CallWindowProc(g_game_wndproc, window, message_type, wparam, lparam);
	}

	bool imgui::input_message(const UINT message_type, const WPARAM wparam, const LPARAM lparam)
	{
		if (message_type == WM_KEYUP && wparam == VK_F4) 
		{
			const auto& io = ImGui::GetIO();
			if (!io.MouseDown[1]) {
				shared::globals::imgui_menu_open = !shared::globals::imgui_menu_open;
			} else {
				ImGui_ImplWin32_WndProcHandler(shared::globals::main_window, message_type, wparam, lparam);
			}
		}

		if (shared::globals::imgui_menu_open)
		{
			//auto& io = ImGui::GetIO();
			ImGui_ImplWin32_WndProcHandler(shared::globals::main_window, message_type, wparam, lparam);
		} else {
			shared::globals::imgui_allow_input_bypass = false; // always reset if there is no imgui window open
		}

		return shared::globals::imgui_menu_open;
	}

	// ------

	void imgui::tab_about()
	{
		if (tex_addons::icon)
		{
			const float cursor_y = ImGui::GetCursorPosY();
			ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() * 0.85f, 24));
			ImGui::Image((ImTextureID)tex_addons::icon, ImVec2(48.0f, 48.0f), ImVec2(0.03f, 0.03f), ImVec2(0.96f, 0.96f));
			ImGui::SetCursorPosY(cursor_y);
		}

		ImGui::Spacing(0.0f, 20.0f);

		ImGui::CenterText("remix-comp-proxy");
		ImGui::CenterText("DX9 proxy framework for RTX Remix compatibility mods");

		ImGui::Spacing(0.0f, 24.0f);
		ImGui::CenterText("current version");

		const char* version_str = shared::utils::va("%d.%d.%d :: %s",
			COMP_MOD_VERSION_MAJOR, COMP_MOD_VERSION_MINOR, COMP_MOD_VERSION_PATCH, __DATE__);
		ImGui::CenterText(version_str);

#if DEBUG
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.64f, 0.23f, 0.18f, 1.0f));
		ImGui::CenterText("DEBUG BUILD");
		ImGui::PopStyleColor();
#endif

		SPACEY16;
		CENTER_URL("Vibe Reverse Engineering Toolkit", "https://github.com/Ekozmaster/Vibe-Reverse-Engineering");

		SPACEY16;
		ImGui::Separator();
		SPACEY16;

		ImGui::CenterText("Contributors");

		SPACEY8;

		// xoxor4d
		CENTER_URL("xoxor4d", "https://github.com/xoxor4d");
		ImGui::CenterText("Original remix-comp-base framework, D3D9 proxy architecture,");
		ImGui::CenterText("ImGui integration, module system");
		SPACEY8;
		CENTER_URL("Ko-Fi (xoxor4d)", "https://ko-fi.com/xoxor4d");
		ImGui::SameLine();
		ImGui::TextURL("Patreon", "https://patreon.com/xoxor4d", true);

		SPACEY16;

		// kim2091
		CENTER_URL("kim2091", "https://github.com/kim2091");
		ImGui::CenterText("FFP conversion, skinning module, diagnostic logging,");
		ImGui::CenterText("tracer integration, INI config, toolkit integration");
		SPACEY8;
		CENTER_URL("Ko-Fi (kim2091)", "https://ko-fi.com/kim20913944");

		SPACEY16;

		// momo5502
		CENTER_URL("momo5502", "https://github.com/momo5502");
		ImGui::CenterText("Initial codebase that remix-comp-base was built on");

		SPACEY16;
		ImGui::Separator();
		SPACEY16;

		ImGui::CenterText("Dependencies");

		SPACEY8;

		CENTER_URL("NVIDIA - RTX Remix", "https://github.com/NVIDIAGameWorks/rtx-remix");
		CENTER_URL("Dear ImGui", "https://github.com/ocornut/imgui");
		CENTER_URL("MinHook", "https://github.com/TsudaKageyu/minhook");

		SPACEY16;
		ImGui::CenterText("Thank you to all supporters and contributors!");
	}

	// draw imgui widget
	void imgui::ImGuiStats::draw_stats()
	{
		if (!m_tracking_enabled) {
			return;
		}

		for (const auto& p : m_stat_list)
		{
			if (p.second) {
				display_single_stat(p.first, *p.second);
			}
			else {
				ImGui::Spacing(0, 4);
			}
		}
	}

	void imgui::ImGuiStats::display_single_stat(const char* name, const StatObj& stat)
	{
		switch (stat.get_mode())
		{
		case StatObj::Mode::Single:
			ImGui::Text("%s", name);
			ImGui::SameLine(ImGui::GetContentRegionAvail().x * 0.65f);
			ImGui::Text("%d total", stat.get_total());
			break;

		case StatObj::Mode::ConditionalCheck:
			ImGui::Text("%s", name);
			ImGui::SameLine(ImGui::GetContentRegionAvail().x * 0.65f);
			ImGui::Text("%d total, %d successful", stat.get_total(), stat.get_successful());
			break;

		default:
			throw std::runtime_error("Uncovered Mode in StatObj");
		}
	}

	void dev_debug_container()
	{
		SPACEY16;
		const auto& im = imgui::get();

		if (ImGui::CollapsingHeader("Temp Debug Values"))
		{
			SPACEY8;
			ImGui::DragFloat3("Debug Vector", &im->m_debug_vector.x, 0.01f, 0, 0, "%.6f");
			ImGui::DragFloat3("Debug Vector 2", &im->m_debug_vector2.x, 0.1f, 0, 0, "%.6f");
			ImGui::DragFloat3("Debug Vector 3", &im->m_debug_vector3.x, 0.1f, 0, 0, "%.6f");
			ImGui::DragFloat3("Debug Vector 4", &im->m_debug_vector4.x, 0.1f, 0, 0, "%.6f");
			ImGui::DragFloat3("Debug Vector 5", &im->m_debug_vector5.x, 0.1f, 0, 0, "%.6f");

			ImGui::Checkbox("Debug Bool 1", &im->m_dbg_debug_bool01);
			ImGui::Checkbox("Debug Bool 2", &im->m_dbg_debug_bool02);
			ImGui::Checkbox("Debug Bool 3", &im->m_dbg_debug_bool03);
			ImGui::Checkbox("Debug Bool 4", &im->m_dbg_debug_bool04);
			ImGui::Checkbox("Debug Bool 5", &im->m_dbg_debug_bool05);
			ImGui::Checkbox("Debug Bool 6", &im->m_dbg_debug_bool06);
			ImGui::Checkbox("Debug Bool 7", &im->m_dbg_debug_bool07);
			ImGui::Checkbox("Debug Bool 8", &im->m_dbg_debug_bool08);
			ImGui::Checkbox("Debug Bool 9", &im->m_dbg_debug_bool09);

			ImGui::DragInt("Debug Int 1", &im->m_dbg_int_01, 0.01f);
			ImGui::DragInt("Debug Int 2", &im->m_dbg_int_02, 0.01f);
			ImGui::DragInt("Debug Int 3", &im->m_dbg_int_03, 0.01f);
			ImGui::DragInt("Debug Int 4", &im->m_dbg_int_04, 0.01f);
			ImGui::DragInt("Debug Int 5", &im->m_dbg_int_05, 0.01f);
			SPACEY8;
		}

		if (ImGui::CollapsingHeader("Fake Camera"))
		{
			SPACEY8;
			ImGui::Checkbox("Use Fake Camera", &im->m_dbg_use_fake_camera);
			ImGui::BeginDisabled(!im->m_dbg_use_fake_camera);
			{
				ImGui::SliderFloat3("Camera Position (X, Y, Z)", im->m_dbg_camera_pos, -10000.0f, 10000.0f);
				ImGui::SliderFloat("Yaw (Y-axis)", &im->m_dbg_camera_yaw, -180.0f, 180.0f);
				ImGui::SliderFloat("Pitch (X-axis)", &im->m_dbg_camera_pitch, -90.0f, 90.0f);

				// Projection matrix adjustments
				ImGui::SliderFloat("FOV", &im->m_dbg_camera_fov, 1.0f, 180.0f);
				ImGui::SliderFloat("Aspect Ratio", &im->m_dbg_camera_aspect, 0.2f, 3.555f);
				ImGui::SliderFloat("Near Plane", &im->m_dbg_camera_near_plane, 0.1f, 1000.0f);
				ImGui::SliderFloat("Far Plane", &im->m_dbg_camera_far_plane, 1.0f, 100000.0f);

				ImGui::EndDisabled();
			}
			SPACEY8;
		}

		if (ImGui::CollapsingHeader("Statistics ..."))
		{
			SPACEY8;
			im->m_stats.enable_tracking(true);
			im->m_stats.draw_stats();
			SPACEY8;
		} else {
			im->m_stats.enable_tracking(false);
		}
	}

	void imgui::tab_dev()
	{
		dev_debug_container();
	}

	void imgui::tab_ffp()
	{
		auto& ffp = shared::common::ffp_state::get();
		auto& cfg = shared::common::config::get();

		// FFP enable/disable toggle
		bool ffp_enabled = ffp.is_enabled();
		if (ImGui::Checkbox("FFP Conversion Enabled", &ffp_enabled))
			ffp.set_enabled(ffp_enabled);

		ImGui::SameLine();
		ImGui::TextDisabled("(%s)", ffp.is_ffp_active() ? "ACTIVE" : "inactive");

		ImGui::Separator();

		// State overview
		if (ImGui::CollapsingHeader("State", ImGuiTreeNodeFlags_DefaultOpen))
		{
			ImGui::Text("ViewProj Valid: %s", ffp.view_proj_valid() ? "YES" : "no");
			ImGui::Text("Frame: %u  Draws: %u  Scenes: %u",
				ffp.frame_count(), ffp.draw_call_count(), ffp.scene_count());
			ImGui::Text("Decl: %s%s%s%s",
				ffp.cur_decl_has_normal() ? "NORMAL " : "",
				ffp.cur_decl_has_pos_t() ? "POSITIONT " : "",
				ffp.cur_decl_is_skinned() ? "SKINNED " : "",
				ffp.cur_decl_has_texcoord() ? "TEXCOORD " : "");

			if (ffp.cur_decl_is_skinned())
				ImGui::Text("  Bones: %d (start reg %d)", ffp.num_bones(), ffp.bone_start_reg());
		}

		// Register layout
		if (ImGui::CollapsingHeader("Register Layout"))
		{
			ImGui::Text("View:  c%d - c%d", ffp.reg_view_start(), ffp.reg_view_end() - 1);
			ImGui::Text("Proj:  c%d - c%d", ffp.reg_proj_start(), ffp.reg_proj_end() - 1);
			ImGui::Text("World: c%d - c%d", ffp.reg_world_start(), ffp.reg_world_end() - 1);
			ImGui::Text("Albedo Stage: %d", cfg.ffp.albedo_stage);
		}

		// VS constant register heatmap
		if (ImGui::CollapsingHeader("VS Constant Registers"))
		{
			const auto* write_log = ffp.vs_const_write_log();
			ImGui::Text("Written this frame:");

			// 16 registers per row, colored by write status
			for (int row = 0; row < 16; row++)
			{
				ImGui::Text("c%3d:", row * 16);
				ImGui::SameLine();
				for (int col = 0; col < 16; col++)
				{
					int reg = row * 16 + col;
					if (write_log[reg])
					{
						ImGui::SameLine();
						ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "%02X", reg);
					}
					else
					{
						ImGui::SameLine();
						ImGui::TextDisabled("--");
					}
				}
			}
		}

		// Matrix values
		if (ImGui::CollapsingHeader("Matrices") && ffp.view_proj_valid())
		{
			auto show_matrix = [&](const char* name, int start_reg)
			{
				const float* m = &ffp.vs_const_data()[start_reg * 4];
				if (shared::common::ffp_state::mat4_is_interesting(m))
				{
					if (ImGui::TreeNode(name))
					{
						ImGui::Text("[%8.3f %8.3f %8.3f %8.3f]", m[0], m[1], m[2], m[3]);
						ImGui::Text("[%8.3f %8.3f %8.3f %8.3f]", m[4], m[5], m[6], m[7]);
						ImGui::Text("[%8.3f %8.3f %8.3f %8.3f]", m[8], m[9], m[10], m[11]);
						ImGui::Text("[%8.3f %8.3f %8.3f %8.3f]", m[12], m[13], m[14], m[15]);
						ImGui::TreePop();
					}
				}
			};

			show_matrix("View", ffp.reg_view_start());
			show_matrix("Projection", ffp.reg_proj_start());
			show_matrix("World", ffp.reg_world_start());
		}

		// Texture bindings
		if (ImGui::CollapsingHeader("Texture Stages"))
		{
			for (int ts = 0; ts < 8; ts++)
			{
				auto* tex = ffp.cur_texture(ts);
				if (tex)
					ImGui::Text("Stage %d: %p%s", ts, tex, (ts == cfg.ffp.albedo_stage) ? " [ALBEDO]" : "");
				else
					ImGui::TextDisabled("Stage %d: (null)", ts);
			}
		}
	}

	// -----------

	void tab_tracer()
	{
		auto* t = tracer::get();
		if (!t)
		{
			ImGui::TextColored(ImVec4(1, 0, 0, 1), "Tracer module not loaded");
			return;
		}

		SPACEY16;

		// Status
		if (t->is_capturing())
		{
			ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "CAPTURING");
			ImGui::SameLine();
			ImGui::Text("Frame %d / %d  (%d calls)",
				t->frames_captured(), t->frames_to_capture(), t->sequence());
			ImGui::ProgressBar(static_cast<float>(t->frames_captured()) / t->frames_to_capture());
		}
		else if (t->is_waiting())
		{
			float remaining = t->delay_remaining();
			ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "WAITING");
			ImGui::SameLine();
			ImGui::Text("Capture starts in %.1fs", remaining);
		}
		else
		{
			ImGui::Text("Status: IDLE");
		}

		SPACEY8;
		ImGui::Separator();
		SPACEY8;

		// Controls
		static int frames = 2;
		ImGui::SliderInt("Frames to capture", &frames, 1, 10);

		static int bt_depth = 8;
		ImGui::SliderInt("Backtrace depth", &bt_depth, 0, 16);

		static float delay_seconds = 0.0f;
		ImGui::SliderFloat("Delay (seconds)", &delay_seconds, 0.0f, 30.0f, "%.1f");

		SPACEY8;

		// Category filters
		if (ImGui::TreeNode("Capture Filters"))
		{
			uint32_t mask = t->category_mask();
			auto flag = [&](const char* label, trace_category cat)
			{
				bool on = (mask & cat) != 0;
				if (ImGui::Checkbox(label, &on))
					mask = on ? (mask | cat) : (mask & ~cat);
			};

			flag("Draw calls",  TRACE_DRAW);
			flag("State",       TRACE_STATE);
			flag("Shaders",     TRACE_SHADERS);
			flag("Textures",    TRACE_TEXTURES);
			flag("Transforms",  TRACE_TRANSFORMS);
			flag("Vertex setup", TRACE_VERTEX);
			flag("Resources",   TRACE_RESOURCES);
			flag("Scene flow",  TRACE_SCENE);
			flag("Get* calls",  TRACE_GETTERS);
			flag("Misc",        TRACE_MISC);

			if (mask != t->category_mask())
				t->set_category_mask(mask);

			ImGui::SameLine();
			if (ImGui::SmallButton("All"))
				t->set_category_mask(TRACE_ALL);
			ImGui::SameLine();
			if (ImGui::SmallButton("Default"))
				t->set_category_mask(TRACE_DEFAULT);

			ImGui::TreePop();
		}

		SPACEY8;

		// Editable filename
		static char filename_buf[256] = {};
		static bool filename_initialized = false;
		if (!filename_initialized || (!t->is_capturing() && filename_buf[0] == '\0'))
		{
			auto default_name = tracer::generate_default_filename();
			strncpy_s(filename_buf, default_name.c_str(), sizeof(filename_buf) - 1);
			filename_initialized = true;
		}

		ImGui::InputText("Filename", filename_buf, sizeof(filename_buf));
		ImGui::SameLine();
		ImGui::TextDisabled(".jsonl");

		SPACEY8;

		ImGui::BeginDisabled(t->is_capturing() || t->is_waiting());
		if (ImGui::Button("Start Capture", ImVec2(200, 0)))
		{
			t->set_backtrace_depth(bt_depth);
			std::string fname = filename_buf;
			if (fname.empty())
				fname = tracer::generate_default_filename();
			t->start_capture_delayed(frames, fname, delay_seconds);
			filename_buf[0] = '\0';
			filename_initialized = false;
		}
		ImGui::EndDisabled();

		ImGui::SameLine();

		ImGui::BeginDisabled(!t->is_capturing() && !t->is_waiting());
		if (ImGui::Button(t->is_waiting() ? "Cancel" : "Stop Capture", ImVec2(200, 0)))
		{
			if (t->is_waiting())
				t->cancel_delayed();
			else
				t->stop_capture();
		}
		ImGui::EndDisabled();

		// Last capture info
		SPACEY16;
		if (!t->last_capture_path().empty())
		{
			ImGui::Separator();
			SPACEY8;
			ImGui::Text("Last capture:");
			ImGui::Text("  File: %s", t->last_capture_path().c_str());
			ImGui::Text("  Size: %.1f KB", t->last_capture_size() / 1024.0);
			ImGui::Text("  Records: %d", t->last_capture_records());
			ImGui::Text("  Output dir: %s", t->output_dir().c_str());
		}
	}

	void tab_diagnostics()
	{
		auto* d = diagnostics::get();
		if (!d)
		{
			ImGui::TextColored(ImVec4(1, 0, 0, 1), "Diagnostics module not loaded");
			ImGui::TextWrapped("Set [Diagnostics] Enabled=1 in remix-comp-proxy.ini to enable.");
			return;
		}

		SPACEY16;

		// Status
		if (d->is_capturing())
		{
			ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "CAPTURING");
			ImGui::SameLine();
			ImGui::Text("Frame %d / %d", d->frames_captured(), d->frames_to_capture());
			ImGui::ProgressBar(static_cast<float>(d->frames_captured()) / d->frames_to_capture());
		}
		else
		{
			ImGui::Text("Status: IDLE");
		}

		SPACEY8;
		ImGui::Separator();
		SPACEY8;

		// Capture controls
		static int diag_frames = 3;
		ImGui::SliderInt("Frames to capture", &diag_frames, 1, 30);

		SPACEY8;

		ImGui::BeginDisabled(d->is_capturing());
		if (ImGui::Button("Start Capture", ImVec2(200, 0)))
			d->start_capture(diag_frames);
		ImGui::EndDisabled();

		ImGui::SameLine();

		ImGui::BeginDisabled(!d->is_capturing());
		if (ImGui::Button("Stop Capture", ImVec2(200, 0)))
			d->stop_capture();
		ImGui::EndDisabled();

		// Last capture info
		if (!d->last_log_path().empty())
		{
			SPACEY8;
			ImGui::Text("Last log: %s", d->last_log_path().c_str());
		}

		SPACEY16;
		ImGui::Separator();
		SPACEY8;

		// Log category checkboxes
		ImGui::Text("Log Categories:");
		SPACEY8;

		ImGui::Checkbox("Draw Calls", &d->cat_draw_calls);
		ImGui::SameLine(220);
		ImGui::TextDisabled("DIP/DP params, strides, decl flags");

		ImGui::Checkbox("VS Constants", &d->cat_vs_constants);
		ImGui::SameLine(220);
		ImGui::TextDisabled("Register writes, matrix values");

		ImGui::Checkbox("Vertex Data", &d->cat_vertex_data);
		ImGui::SameLine(220);
		ImGui::TextDisabled("Raw vertex bytes for early draws");

		ImGui::Checkbox("Declarations", &d->cat_declarations);
		ImGui::SameLine(220);
		ImGui::TextDisabled("Vertex element breakdown");

		ImGui::Checkbox("Textures", &d->cat_textures);
		ImGui::SameLine(220);
		ImGui::TextDisabled("Stage bindings, unique counts");

		ImGui::Checkbox("Present Info", &d->cat_present_info);
		ImGui::SameLine(220);
		ImGui::TextDisabled("Frame summary, VS regs written");
	}

	// -----------

	void imgui::devgui()
	{
		ImGui::SetNextWindowSize(ImVec2(900, 800), ImGuiCond_FirstUseEver);
		if (!ImGui::Begin("Remix Comp - FFP Proxy", &shared::globals::imgui_menu_open, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollWithMouse))
		{
			ImGui::End();
			return;
		}

		m_im_window_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_AnyWindow);
		m_im_window_hovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AnyWindow);

		static bool im_demo_menu = false;
		if (im_demo_menu) {
			ImGui::ShowDemoWindow(&im_demo_menu);
		}


#define ADD_TAB(NAME, FUNC) \
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::ColorConvertFloat4ToU32(ImVec4(0, 0, 0, 0)));			\
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(ImGui::GetStyle().FramePadding.x + 12.0f, 8));	\
	if (ImGui::BeginTabItem(NAME)) {																		\
		ImGui::PopStyleVar(1);																				\
		if (ImGui::BeginChild("##child_" NAME, ImVec2(0, ImGui::GetContentRegionAvail().y - 38), ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_AlwaysVerticalScrollbar )) {	\
			FUNC(); ImGui::EndChild();																		\
		} else {																							\
			ImGui::EndChild();																				\
		} ImGui::EndTabItem();																				\
	} else { ImGui::PopStyleVar(1); } ImGui::PopStyleColor();

		// ---------------------------------------

		const auto col_top = ImGui::ColorConvertFloat4ToU32(ImVec4(0, 0, 0, 0.0f));
		const auto col_bottom = ImGui::ColorConvertFloat4ToU32(ImVec4(0, 0, 0, 0.4f));
		const auto col_border = ImGui::ColorConvertFloat4ToU32(ImVec4(0, 0, 0, 0.8f));
		const auto pre_tabbar_spos = ImGui::GetCursorScreenPos() - ImGui::GetStyle().WindowPadding;

		ImGui::GetWindowDrawList()->AddRectFilledMultiColor(pre_tabbar_spos, pre_tabbar_spos + ImVec2(ImGui::GetWindowWidth(), 40.0f),
			col_top, col_top, col_bottom, col_bottom);

		ImGui::GetWindowDrawList()->AddLine(pre_tabbar_spos + ImVec2(0, 40.0f), pre_tabbar_spos + ImVec2(ImGui::GetWindowWidth(), 40.0f),
			col_border, 1.0f);

		ImGui::SetCursorScreenPos(pre_tabbar_spos + ImVec2(12,8));

		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(ImGui::GetStyle().FramePadding.x + 12.0f, 8));
		ImGui::PushStyleColor(ImGuiCol_TabSelected, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
		if (ImGui::BeginTabBar("devgui_tabs"))
		{
			ImGui::PopStyleColor();
			ImGui::PopStyleVar(1);
			ADD_TAB("FFP", tab_ffp);
			ADD_TAB("Diagnostics", tab_diagnostics);
			ADD_TAB("Tracer", tab_tracer);
			ADD_TAB("Dev", tab_dev);
			ADD_TAB("About", tab_about);
			ImGui::EndTabBar();
		}
		else {
			ImGui::PopStyleColor();
			ImGui::PopStyleVar(1);
		}
#undef ADD_TAB

		{
			ImGui::Separator();
			const char* movement_hint_str = "Hold Right Mouse to enable Game Input ";
			const auto avail_width = ImGui::GetContentRegionAvail().x;
			float cur_pos = avail_width - 54.0f;

			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
			{
				ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ImGui::GetStyle().ItemSpacing.y);
				const auto spos = ImGui::GetCursorScreenPos();
				ImGui::TextUnformatted(m_devgui_custom_footer_content.c_str());
				ImGui::SetCursorScreenPos(spos);
				m_devgui_custom_footer_content.clear();
			}
			

			ImGui::SetCursorPos(ImVec2(cur_pos, ImGui::GetCursorPosY() + 2.0f));
			if (ImGui::Button("Demo", ImVec2(50, 0))) {
				im_demo_menu = !im_demo_menu;
			}

			ImGui::SameLine();
			cur_pos = cur_pos - ImGui::CalcTextSize(movement_hint_str).x - 6.0f;
			ImGui::SetCursorPosX(cur_pos);
			ImGui::TextUnformatted(movement_hint_str);
		}
		ImGui::PopStyleVar(1);
		ImGui::End();
	}

	void imgui::on_present()
	{
		if (auto* im = imgui::get(); im)
		{
			if (const auto dev = shared::globals::d3d_device; dev)
			{
				if (!im->m_initialized_device)
				{
					//Sleep(1000);
					shared::common::log("ImGui", "ImGui_ImplDX9_Init");
					ImGui_ImplDX9_Init(dev);
					im->m_initialized_device = true;
				}

				// else so we render the first frame one frame later
				else if (im->m_initialized_device)
				{
					// handle srgb
					DWORD og_srgb_samp, og_srgb_write;
					dev->GetSamplerState(0, D3DSAMP_SRGBTEXTURE, &og_srgb_samp);
					dev->GetRenderState(D3DRS_SRGBWRITEENABLE, &og_srgb_write);
					dev->SetSamplerState(0, D3DSAMP_SRGBTEXTURE, 1);
					dev->SetRenderState(D3DRS_SRGBWRITEENABLE, 1);

					ImGui_ImplDX9_NewFrame();
					ImGui_ImplWin32_NewFrame();
					ImGui::NewFrame();

					auto& io = ImGui::GetIO();

					if (shared::globals::imgui_allow_input_bypass_timeout) {
						shared::globals::imgui_allow_input_bypass_timeout--;
					}

					shared::globals::imgui_wants_text_input = ImGui::GetIO().WantTextInput;

					if (shared::globals::imgui_menu_open) 
					{
						io.MouseDrawCursor = true;
						im->devgui();

						// ---
						// enable game input via right mouse button logic

						if (!im->m_im_window_hovered && io.MouseDown[1])
						{
							// reset stuck rmb if timeout is active 
							if (shared::globals::imgui_allow_input_bypass_timeout)
							{
								io.AddMouseButtonEvent(ImGuiMouseButton_Right, false);
								shared::globals::imgui_allow_input_bypass_timeout = 0u;
							}

							// enable game input if no imgui window is hovered and right mouse is held
							else
							{
								ImGui::SetWindowFocus(); // unfocus input text
								shared::globals::imgui_allow_input_bypass = true;
							}
						}

						// ^ wait until mouse is up
						else if (shared::globals::imgui_allow_input_bypass && !io.MouseDown[1] && !shared::globals::imgui_allow_input_bypass_timeout)
						{
							shared::globals::imgui_allow_input_bypass_timeout = 2u;
							shared::globals::imgui_allow_input_bypass = false;
						}
					}
					else 
					{
						io.MouseDrawCursor = false;
						shared::globals::imgui_allow_input_bypass_timeout = 0u;
						shared::globals::imgui_allow_input_bypass = false;
					}

					if (im->m_stats.is_tracking_enabled()) {
						im->m_stats.reset_stats();
					}

					shared::globals::imgui_is_rendering = true;
					ImGui::EndFrame();
					ImGui::Render();
					ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
					shared::globals::imgui_is_rendering = false;

					// restore
					dev->SetSamplerState(0, D3DSAMP_SRGBTEXTURE, og_srgb_samp);
					dev->SetRenderState(D3DRS_SRGBWRITEENABLE, og_srgb_write);
				}
			}
		}
	}

	void imgui::theme()
	{
		ImGuiStyle& style = ImGui::GetStyle();
		style.Alpha = 1.0f;
		style.DisabledAlpha = 0.5f;

		style.WindowPadding = ImVec2(8.0f, 10.0f);
		style.FramePadding = ImVec2(14.0f, 6.0f);
		style.ItemSpacing = ImVec2(10.0f, 5.0f);
		style.ItemInnerSpacing = ImVec2(4.0f, 8.0f);
		style.IndentSpacing = 16.0f;
		style.ColumnsMinSpacing = 10.0f;
		style.ScrollbarSize = 14.0f;
		style.GrabMinSize = 10.0f;

		style.WindowBorderSize = 1.0f;
		style.ChildBorderSize = 1.0f;
		style.PopupBorderSize = 1.0f;
		style.FrameBorderSize = 1.0f;
		style.TabBorderSize = 0.0f;

		style.WindowRounding = 4.0f;
		style.ChildRounding = 2.0f;
		style.FrameRounding = 2.0f;
		style.PopupRounding = 2.0f;
		style.ScrollbarRounding = 2.0f;
		style.GrabRounding = 1.0f;
		style.TabRounding = 4.0f;

		style.CellPadding = ImVec2(5.0f, 4.0f);

		auto& colors = style.Colors;
		colors[ImGuiCol_Text] = ImVec4(0.93f, 0.93f, 0.93f, 1.00f);
		colors[ImGuiCol_WindowBg] = ImVec4(0.23f, 0.23f, 0.23f, 0.96f);
		colors[ImGuiCol_ChildBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.49f);
		colors[ImGuiCol_FrameBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.54f);
		colors[ImGuiCol_FrameBgHovered] = ImVec4(0.16f, 0.48f, 0.36f, 1.00f);
		colors[ImGuiCol_FrameBgActive] = ImVec4(0.21f, 0.61f, 0.46f, 1.00f);
		colors[ImGuiCol_TitleBgActive] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
		colors[ImGuiCol_CheckMark] = ImVec4(0.16f, 0.48f, 0.36f, 1.00f);
		colors[ImGuiCol_SliderGrab] = ImVec4(0.16f, 0.48f, 0.36f, 1.00f);
		colors[ImGuiCol_SliderGrabActive] = ImVec4(0.21f, 0.60f, 0.45f, 1.00f);
		colors[ImGuiCol_Button] = ImVec4(0.09f, 0.09f, 0.09f, 1.00f);
		colors[ImGuiCol_ButtonHovered] = ImVec4(0.28f, 0.28f, 0.28f, 1.00f);
		colors[ImGuiCol_ButtonActive] = ImVec4(0.48f, 0.48f, 0.48f, 1.00f);
		colors[ImGuiCol_Header] = ImVec4(0.17f, 0.17f, 0.17f, 1.00f);
		colors[ImGuiCol_HeaderHovered] = ImVec4(0.20f, 0.59f, 0.44f, 1.00f);
		colors[ImGuiCol_HeaderActive] = ImVec4(0.20f, 0.58f, 0.44f, 1.00f);
		colors[ImGuiCol_SeparatorHovered] = ImVec4(0.20f, 0.58f, 0.44f, 0.06f);
		colors[ImGuiCol_SeparatorActive] = ImVec4(0.20f, 0.58f, 0.44f, 0.06f);
		colors[ImGuiCol_ResizeGrip] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
		colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.31f, 0.31f, 0.31f, 0.67f);
		colors[ImGuiCol_ResizeGripActive] = ImVec4(0.38f, 0.38f, 0.38f, 0.95f);
		colors[ImGuiCol_TabHovered] = ImVec4(0.19f, 0.57f, 0.43f, 1.00f);
		colors[ImGuiCol_Tab] = ImVec4(0.17f, 0.17f, 0.17f, 1.00f);
		colors[ImGuiCol_TabSelected] = ImVec4(0.16f, 0.48f, 0.36f, 1.00f);
		colors[ImGuiCol_TabSelectedOverline] = ImVec4(0.16f, 0.48f, 0.36f, 1.00f);
		colors[ImGuiCol_TabDimmed] = ImVec4(0.07f, 0.22f, 0.16f, 1.00f);
		colors[ImGuiCol_TabDimmedSelected] = ImVec4(0.12f, 0.33f, 0.24f, 1.00f);
	}
	
	imgui::imgui()
	{
		p_this = this;

		IMGUI_CHECKVERSION();
		ImGui::CreateContext();

		//ImGuiIO& io = ImGui::GetIO(); (void)io;
		//io.MouseDrawCursor = true;
		//io.ConfigFlags |= ImGuiConfigFlags_IsSRGB;
		//io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;

		theme();

		ImGui_ImplWin32_Init(shared::globals::main_window);
		g_game_wndproc = reinterpret_cast<WNDPROC>(SetWindowLongPtr(shared::globals::main_window, GWLP_WNDPROC, LONG_PTR(wnd_proc_hk)));

		// ---
		m_initialized = true;
		shared::common::log("ImGui", "Module initialized.", shared::common::LOG_TYPE::LOG_TYPE_DEFAULT, false);
	}
}



