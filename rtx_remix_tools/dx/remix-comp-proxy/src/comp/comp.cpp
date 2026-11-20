#include "std_include.hpp"

#include "modules/imgui.hpp"
#include "modules/renderer.hpp"
#include "modules/diagnostics.hpp"
#include "modules/skinning.hpp"
#include "modules/tracer.hpp"
#include "shared/common/remix_api.hpp"
#include "shared/common/config.hpp"

// see comment in main()
//#include "shared/common/dinput_hook_v1.hpp"
//#include "shared/common/dinput_hook_v2.hpp"

namespace comp
{
	void on_begin_scene_cb()
	{
		if (!tex_addons::initialized) {
			tex_addons::init_texture_addons();
		}

		// fake camera

		const auto& im = imgui::get();
		if (im->m_dbg_use_fake_camera)
		{
			// No roll, for simplicity
			const auto rotation = DirectX::XMMatrixRotationRollPitchYaw(
				DEG2RAD(im->m_dbg_camera_pitch), DEG2RAD(im->m_dbg_camera_yaw), 0.0f);

			// Negated: a camera moves the world the opposite way
			const auto translation = DirectX::XMMatrixTranslation(
				-im->m_dbg_camera_pos[0], -im->m_dbg_camera_pos[1], -im->m_dbg_camera_pos[2]);

			const auto view_matrix = shared::utils::to_d3dmatrix(DirectX::XMMatrixMultiply(rotation, translation));

			// Values typed into the sliders can leave their range; XMMatrixPerspectiveFovLH asserts on
			// a zero field of view or aspect, a near plane at or behind the camera and near == far
			const float fov = std::clamp(im->m_dbg_camera_fov, 1.0f, 179.0f);
			const float aspect = (std::max)(im->m_dbg_camera_aspect, 0.01f);
			const float near_plane = (std::max)(im->m_dbg_camera_near_plane, 0.001f);
			const float far_plane = (std::max)(im->m_dbg_camera_far_plane, near_plane * 1.01f + 0.01f);
			const auto proj_matrix = shared::utils::to_d3dmatrix(DirectX::XMMatrixPerspectiveFovLH(
				DEG2RAD(fov), aspect, near_plane, far_plane));

			// D3DTS_WORLD belongs to ffp_state, which keeps each object's world matrix in place
			shared::globals::d3d_device->SetTransform(D3DTS_VIEW, &view_matrix);
			shared::globals::d3d_device->SetTransform(D3DTS_PROJECTION, &proj_matrix);
		}

		// Example: if you found a game struct with view/proj matrices, apply them here
		//if (const auto viewport = game::vp; viewport)
		//{
		//	shared::globals::d3d_device->SetTransform(D3DTS_VIEW, &viewport->view);
		//	shared::globals::d3d_device->SetTransform(D3DTS_PROJECTION, &viewport->proj);
		//}
	}


	void main()
	{
		// #Step 2: init remix api if you want to use it or comment it otherwise
		// Requires "exposeRemixApi = True" in the "bridge.conf" that is located in the .trex folder
		shared::common::remix_api::initialize(nullptr, nullptr, nullptr, false);

		// Core modules
		shared::common::loader::module_loader::register_module(std::make_unique<tracer>());
		shared::common::loader::module_loader::register_module(std::make_unique<imgui>());
		shared::common::loader::module_loader::register_module(std::make_unique<renderer>());

		auto& cfg = shared::common::config::get();

		// Diagnostics module (on-demand capture available from ImGui when loaded)
		if (cfg.diagnostics.enabled)
			shared::common::loader::module_loader::register_module(std::make_unique<diagnostics>());

		// Skinning module (conditional on config)
		if (cfg.skinning.enabled)
			shared::common::loader::module_loader::register_module(std::make_unique<skinning>());

		// #Step 3: hook dinput if your game uses direct input (for ImGui) - ONLY USE ONE
		//shared::common::loader::module_loader::register_module(std::make_unique<shared::common::dinput_v1>()); // v1: might cause issues with the Alt+X menu
		//shared::common::loader::module_loader::register_module(std::make_unique<shared::common::dinput_v2>()); // v2: better but might need further tweaks

		MH_EnableHook(MH_ALL_HOOKS);
	}
}
