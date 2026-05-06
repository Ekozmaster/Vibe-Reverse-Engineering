#include "std_include.hpp"
#include "renderer.hpp"

namespace comp
{
	bool drawcall_mod_context::has_saved_renderstate(const D3DRENDERSTATETYPE& state) const
	{
		return saved_render_state_.contains(state);
	}

	bool drawcall_mod_context::has_saved_renderstate(const uint32_t& state) const
	{
		return has_saved_renderstate((D3DRENDERSTATETYPE)state);
	}

	void drawcall_mod_context::set_texture_transform(IDirect3DDevice9* device, const D3DXMATRIX* matrix)
	{
		if (matrix)
		{
			device->SetTransform(D3DTS_TEXTURE0, matrix);
			tex0_transform_set_ = true;
		}
	}

	void drawcall_mod_context::save_vs(IDirect3DDevice9* device)
	{
		device->GetVertexShader(&vs_);
		vs_set_ = true;
	}

	void drawcall_mod_context::save_ps(IDirect3DDevice9* device)
	{
		device->GetPixelShader(&ps_);
		ps_set_ = true;
	}

	void drawcall_mod_context::save_texture(IDirect3DDevice9* device, const bool stage)
	{
		if (!stage)
		{
#if DEBUG
			if (tex0_set_) {
				OutputDebugStringA("save_texture:: tex0 was already saved\n"); return;
			}
#endif
			device->GetTexture(0, &tex0_);
			tex0_set_ = true;
		}
		else
		{
#if DEBUG
			if (tex1_set_) {
				OutputDebugStringA("save_texture:: tex1 was already saved\n"); return;
			}
#endif
			device->GetTexture(1, &tex1_);
			tex1_set_ = true;
		}
	}

	bool drawcall_mod_context::save_rs(IDirect3DDevice9* device, const D3DRENDERSTATETYPE& state)
	{
		if (saved_render_state_.contains(state)) {
			return false;
		}
		DWORD temp;
		device->GetRenderState(state, &temp);
		saved_render_state_[state] = temp;
		return true;
	}

	bool drawcall_mod_context::save_rs(IDirect3DDevice9* device, const uint32_t& state)
	{
		return save_rs(device, (D3DRENDERSTATETYPE)state);
	}

	void drawcall_mod_context::save_ss(IDirect3DDevice9* device, const D3DSAMPLERSTATETYPE& state)
	{
		if (saved_sampler_state_.contains(state)) {
			return;
		}
		DWORD temp;
		device->GetSamplerState(0, state, &temp);
		saved_sampler_state_[state] = temp;
	}

	bool drawcall_mod_context::save_tss(IDirect3DDevice9* device, const D3DTEXTURESTAGESTATETYPE& type)
	{
		if (saved_texture_stage_state_.contains(type)) {
			return false;
		}
		DWORD temp;
		device->GetTextureStageState(0, type, &temp);
		saved_texture_stage_state_[type] = temp;
		return true;
	}

	void drawcall_mod_context::save_view_transform(IDirect3DDevice9* device)
	{
		device->GetTransform(D3DTS_VIEW, &view_transform_);
		view_transform_set_ = true;
	}

	void drawcall_mod_context::save_projection_transform(IDirect3DDevice9* device)
	{
		device->GetTransform(D3DTS_PROJECTION, &projection_transform_);
		projection_transform_set_ = true;
	}

	void drawcall_mod_context::restore_vs(IDirect3DDevice9* device)
	{
		if (vs_set_)
		{
			device->SetVertexShader(vs_);
			if (vs_) vs_->Release();
			vs_ = nullptr;
			vs_set_ = false;
		}
	}

	void drawcall_mod_context::restore_ps(IDirect3DDevice9* device)
	{
		if (ps_set_)
		{
			device->SetPixelShader(ps_);
			if (ps_) ps_->Release();
			ps_ = nullptr;
			ps_set_ = false;
		}
	}

	void drawcall_mod_context::restore_texture(IDirect3DDevice9* device, const bool stage)
	{
		if (!stage)
		{
			if (tex0_set_)
			{
				device->SetTexture(0, tex0_);
				if (tex0_) tex0_->Release();
				tex0_ = nullptr;
				tex0_set_ = false;
			}
		}
		else
		{
			if (tex1_set_)
			{
				device->SetTexture(1, tex1_);
				if (tex1_) tex1_->Release();
				tex1_ = nullptr;
				tex1_set_ = false;
			}
		}
	}

	void drawcall_mod_context::restore_render_state(IDirect3DDevice9* device, const D3DRENDERSTATETYPE& state)
	{
		if (saved_render_state_.contains(state)) {
			device->SetRenderState(state, saved_render_state_[state]);
		}
	}

	void drawcall_mod_context::restore_sampler_state(IDirect3DDevice9* device, const D3DSAMPLERSTATETYPE& state)
	{
		if (saved_sampler_state_.contains(state)) {
			device->SetSamplerState(0, state, saved_sampler_state_[state]);
		}
	}

	void drawcall_mod_context::restore_texture_stage_state(IDirect3DDevice9* device, const D3DTEXTURESTAGESTATETYPE& type)
	{
		if (saved_texture_stage_state_.contains(type)) {
			device->SetTextureStageState(0, type, saved_texture_stage_state_[type]);
		}
	}

	void drawcall_mod_context::restore_texture_transform(IDirect3DDevice9* device)
	{
		if (tex0_transform_set_)
		{
			device->SetTransform(D3DTS_TEXTURE0, &shared::globals::IDENTITY);
			tex0_transform_set_ = false;
		}
	}

	void drawcall_mod_context::restore_view_transform(IDirect3DDevice9* device)
	{
		if (view_transform_set_)
		{
			device->SetTransform(D3DTS_VIEW, &view_transform_);
			view_transform_set_ = false;
		}
	}

	void drawcall_mod_context::restore_projection_transform(IDirect3DDevice9* device)
	{
		if (projection_transform_set_)
		{
			device->SetTransform(D3DTS_PROJECTION, &projection_transform_);
			projection_transform_set_ = false;
		}
	}

	void drawcall_mod_context::restore_all(IDirect3DDevice9* device)
	{
		for (auto& rs : saved_render_state_) {
			device->SetRenderState(rs.first, rs.second);
		}
		for (auto& ss : saved_sampler_state_) {
			device->SetSamplerState(0, ss.first, ss.second);
		}
		for (auto& tss : saved_texture_stage_state_) {
			device->SetTextureStageState(0, tss.first, tss.second);
		}
	}

	void drawcall_mod_context::reset_context()
	{
		if (vs_set_ && vs_) vs_->Release();
		vs_ = nullptr; vs_set_ = false;
		if (ps_set_ && ps_) ps_->Release();
		ps_ = nullptr; ps_set_ = false;
		if (tex0_set_ && tex0_) tex0_->Release();
		tex0_ = nullptr; tex0_set_ = false;
		if (tex1_set_ && tex1_) tex1_->Release();
		tex1_ = nullptr; tex1_set_ = false;
		tex0_transform_set_ = false;
		view_transform_set_ = false;
		projection_transform_set_ = false;
		saved_render_state_.clear();
		saved_sampler_state_.clear();
		saved_texture_stage_state_.clear();
		modifiers.reset();
		info.reset();
	}
}
