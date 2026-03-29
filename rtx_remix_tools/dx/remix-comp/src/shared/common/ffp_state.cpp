#include "std_include.hpp"
#include "ffp_state.hpp"

namespace shared::common
{
	ffp_state& ffp_state::get()
	{
		static ffp_state instance;
		return instance;
	}

	void ffp_state::init(IDirect3DDevice9* /*real_device*/)
	{
		cfg_ = &config::get().ffp;
		enabled_ = cfg_->enabled;
		create_tick_ = GetTickCount();

		log("FFP", std::format("State tracker initialized, FFP={}", enabled_ ? "ON" : "OFF"));
	}

	// ---- State mutators ----

	void ffp_state::on_set_vs_const_f(UINT start_reg, const float* data, UINT count)
	{
		if (!data || start_reg + count > 256) return;

		std::memcpy(&vs_const_[start_reg * 4], data, count * 4 * sizeof(float));

		// Dirty tracking keyed to game-specific register layout
		UINT end_reg = start_reg + count;
		if (start_reg < static_cast<UINT>(cfg_->vs_reg_proj_end) &&
			end_reg > static_cast<UINT>(cfg_->vs_reg_view_start))
		{
			view_proj_dirty_ = true;
		}
		if (start_reg < static_cast<UINT>(cfg_->vs_reg_world_end) &&
			end_reg > static_cast<UINT>(cfg_->vs_reg_world_start))
		{
			world_dirty_ = true;
		}

		// Mark View+Proj valid once both ranges have been written
		auto view_start = static_cast<UINT>(cfg_->vs_reg_view_start);
		auto proj_start = static_cast<UINT>(cfg_->vs_reg_proj_start);
		auto proj_end = static_cast<UINT>(cfg_->vs_reg_proj_end);

		if (start_reg <= proj_start && start_reg + count >= proj_end)
		{
			view_proj_valid_ = true;
		}
		else if (start_reg == view_start && count >= 4 && vs_const_write_log_[proj_start])
		{
			view_proj_valid_ = true;
		}
		else if (start_reg == proj_start && count >= 4 && vs_const_write_log_[view_start])
		{
			view_proj_valid_ = true;
		}

		for (UINT i = 0; i < count; i++)
		{
			if (start_reg + i < 256)
				vs_const_write_log_[start_reg + i] = 1;
		}

		// Bone palette detection (for skinning module)
		if (config::get().skinning.enabled &&
			start_reg >= static_cast<UINT>(cfg_->vs_reg_bone_threshold) &&
			count >= static_cast<UINT>(cfg_->vs_bone_min_regs) &&
			(count % static_cast<UINT>(cfg_->vs_regs_per_bone)) == 0)
		{
			bone_start_reg_ = static_cast<int>(start_reg);
			num_bones_ = static_cast<int>(count) / cfg_->vs_regs_per_bone;
		}
	}

	void ffp_state::on_set_ps_const_f(UINT start_reg, const float* data, UINT count)
	{
		if (!data || start_reg + count > 32) return;

		std::memcpy(&ps_const_[start_reg * 4], data, count * 4 * sizeof(float));
		ps_const_dirty_ = true;
	}

	void ffp_state::on_set_vertex_shader(IDirect3DVertexShader9* shader)
	{
		if (shader) shader->AddRef();
		if (last_vs_) last_vs_->Release();
		last_vs_ = shader;
		ffp_active_ = false;
	}

	bool ffp_state::on_set_pixel_shader(IDirect3DPixelShader9* shader)
	{
		if (shader) shader->AddRef();
		if (last_ps_) last_ps_->Release();
		last_ps_ = shader;

		// Swallow the call while in FFP mode (don't forward to real device)
		return ffp_active_;
	}

	void ffp_state::on_set_texture(UINT stage, IDirect3DBaseTexture9* texture)
	{
		if (stage < 8)
			cur_texture_[stage] = texture;
	}

	void ffp_state::on_set_stream_source(UINT stream, IDirect3DVertexBuffer9* vb, UINT offset, UINT stride)
	{
		if (stream < 4)
		{
			stream_vb_[stream] = vb;
			stream_offset_[stream] = offset;
			stream_stride_[stream] = stride;
		}
	}

	void ffp_state::on_set_vertex_declaration(IDirect3DVertexDeclaration9* decl)
	{
		last_decl_ = decl;
		cur_decl_is_skinned_ = false;
		cur_decl_has_texcoord_ = false;
		cur_decl_has_normal_ = false;
		cur_decl_has_color_ = false;
		cur_decl_has_pos_t_ = false;
		cur_decl_texcoord_type_ = -1;
		cur_decl_texcoord_off_ = 0;
		cur_decl_num_weights_ = 0;
		cur_decl_blend_weight_off_ = 0;
		cur_decl_blend_weight_type_ = 0;
		cur_decl_blend_indices_off_ = 0;
		cur_decl_pos_off_ = 0;
		cur_decl_normal_off_ = 0;
		cur_decl_normal_type_ = -1;

		if (!decl) return;

		UINT num_elems = 0;
		if (FAILED(decl->GetDeclaration(nullptr, &num_elems))) return;
		if (num_elems == 0 || num_elems > 32) return;

		D3DVERTEXELEMENT9 elems[32];
		if (FAILED(decl->GetDeclaration(elems, &num_elems))) return;

		bool has_blend_weight = false;
		bool has_blend_indices = false;
		BYTE blend_weight_type = 0;

		for (UINT e = 0; e < num_elems; e++)
		{
			const auto& el = elems[e];
			if (el.Stream == 0xFF) break;

			switch (el.Usage)
			{
			case D3DDECLUSAGE_POSITIONT:
				cur_decl_has_pos_t_ = true;
				break;

			case D3DDECLUSAGE_BLENDWEIGHT:
				has_blend_weight = true;
				blend_weight_type = el.Type;
				cur_decl_blend_weight_off_ = el.Offset;
				cur_decl_blend_weight_type_ = el.Type;
				break;

			case D3DDECLUSAGE_BLENDINDICES:
				has_blend_indices = true;
				cur_decl_blend_indices_off_ = el.Offset;
				break;

			case D3DDECLUSAGE_POSITION:
				if (el.Stream == 0)
					cur_decl_pos_off_ = el.Offset;
				break;

			case D3DDECLUSAGE_NORMAL:
				if (el.Stream == 0)
				{
					cur_decl_has_normal_ = true;
					cur_decl_normal_off_ = el.Offset;
					cur_decl_normal_type_ = el.Type;
				}
				break;

			case D3DDECLUSAGE_TEXCOORD:
				if (el.UsageIndex == 0 && el.Stream == 0)
				{
					cur_decl_has_texcoord_ = true;
					cur_decl_texcoord_type_ = el.Type;
					cur_decl_texcoord_off_ = el.Offset;
				}
				break;

			case D3DDECLUSAGE_COLOR:
				cur_decl_has_color_ = true;
				break;
			}
		}

		if (has_blend_weight && has_blend_indices)
		{
			cur_decl_is_skinned_ = true;

			switch (blend_weight_type)
			{
			case D3DDECLTYPE_FLOAT1:  cur_decl_num_weights_ = 1; break;
			case D3DDECLTYPE_FLOAT2:  cur_decl_num_weights_ = 2; break;
			case D3DDECLTYPE_FLOAT3:  cur_decl_num_weights_ = 3; break;
			case D3DDECLTYPE_FLOAT4:  cur_decl_num_weights_ = 3; break;
			case D3DDECLTYPE_UBYTE4N: cur_decl_num_weights_ = 3; break;
			default:                  cur_decl_num_weights_ = 3; break;
			}
		}
	}

	void ffp_state::on_present()
	{
		frame_count_++;
		ffp_setup_ = false;
		draw_call_count_ = 0;
		scene_count_ = 0;
		disengage(shared::globals::d3d_device);
		std::memset(vs_const_write_log_, 0, sizeof(vs_const_write_log_));
	}

	void ffp_state::on_begin_scene()
	{
		ffp_setup_ = false;
		scene_count_++;
	}

	void ffp_state::on_reset()
	{
		if (last_vs_) { last_vs_->Release(); last_vs_ = nullptr; }
		if (last_ps_) { last_ps_->Release(); last_ps_ = nullptr; }

		view_proj_valid_ = false;
		ffp_setup_ = false;
		world_dirty_ = false;
		view_proj_dirty_ = false;
		ps_const_dirty_ = false;
		ffp_active_ = false;
		bone_start_reg_ = 0;
		num_bones_ = 0;

		log("FFP", "State reset");
	}

	// ---- State consumers ----

	void ffp_state::engage(IDirect3DDevice9* dev)
	{
		if (!enabled_ || !dev) return;

		if (!ffp_active_)
		{
			dev->SetVertexShader(nullptr);
			dev->SetPixelShader(nullptr);
			ffp_active_ = true;
		}

		apply_transforms(dev);
		setup_texture_stages(dev);

		if (!ffp_setup_)
		{
			setup_lighting(dev);
			ffp_setup_ = true;
		}
	}

	void ffp_state::disengage(IDirect3DDevice9* dev)
	{
		if (!ffp_active_ || !dev) return;

		dev->SetVertexShader(last_vs_);
		dev->SetPixelShader(last_ps_);
		ffp_active_ = false;
	}

	void ffp_state::setup_albedo_texture(IDirect3DDevice9* dev)
	{
		if (!dev) return;

		int as = cfg_->albedo_stage;
		auto* albedo = (as >= 0 && as < 8) ? cur_texture_[as] : cur_texture_[0];

		dev->SetTexture(0, albedo);
		for (DWORD ts = 1; ts < 8; ts++)
			dev->SetTexture(ts, nullptr);
	}

	void ffp_state::restore_textures(IDirect3DDevice9* dev)
	{
		if (!dev) return;

		for (DWORD ts = 0; ts < 8; ts++)
			dev->SetTexture(ts, cur_texture_[ts]);
	}

	// ---- Internal helpers ----

	void ffp_state::apply_transforms(IDirect3DDevice9* dev)
	{
		float transposed[16];

		if (view_proj_dirty_)
		{
			mat4_transpose(transposed, &vs_const_[cfg_->vs_reg_view_start * 4]);
			dev->SetTransform(D3DTS_VIEW, reinterpret_cast<const D3DMATRIX*>(transposed));

			mat4_transpose(transposed, &vs_const_[cfg_->vs_reg_proj_start * 4]);
			dev->SetTransform(D3DTS_PROJECTION, reinterpret_cast<const D3DMATRIX*>(transposed));

			view_proj_dirty_ = false;
		}

		if (world_dirty_)
		{
			mat4_transpose(transposed, &vs_const_[cfg_->vs_reg_world_start * 4]);
			dev->SetTransform(D3DTS_WORLD, reinterpret_cast<const D3DMATRIX*>(transposed));

			world_dirty_ = false;
		}
	}

	void ffp_state::setup_lighting(IDirect3DDevice9* dev)
	{
		dev->SetRenderState(D3DRS_LIGHTING, FALSE);

		D3DMATERIAL9 mat = {};
		mat.Diffuse = { 1.0f, 1.0f, 1.0f, 1.0f };
		mat.Ambient = { 1.0f, 1.0f, 1.0f, 1.0f };
		dev->SetMaterial(&mat);
	}

	void ffp_state::setup_texture_stages(IDirect3DDevice9* dev)
	{
		// Stage 0: modulate texture color with vertex/material diffuse
		dev->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
		dev->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
		dev->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_CURRENT);
		dev->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
		dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
		dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
		dev->SetTextureStageState(0, D3DTSS_TEXCOORDINDEX, 0);
		dev->SetTextureStageState(0, D3DTSS_TEXTURETRANSFORMFLAGS, D3DTTFF_DISABLE);

		// Disable stages 1-7: the game binds shadow maps, LUTs, normal maps etc.
		// on higher stages for its pixel shaders. In FFP mode those become active
		// and Remix may consume the wrong textures.
		for (DWORD s = 1; s <= 7; s++)
		{
			dev->SetTextureStageState(s, D3DTSS_COLOROP, D3DTOP_DISABLE);
			dev->SetTextureStageState(s, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
		}
	}

	// ---- Utility ----

	void ffp_state::mat4_transpose(float* dst, const float* src)
	{
		dst[0]  = src[0];  dst[1]  = src[4];  dst[2]  = src[8];  dst[3]  = src[12];
		dst[4]  = src[1];  dst[5]  = src[5];  dst[6]  = src[9];  dst[7]  = src[13];
		dst[8]  = src[2];  dst[9]  = src[6];  dst[10] = src[10]; dst[11] = src[14];
		dst[12] = src[3];  dst[13] = src[7];  dst[14] = src[11]; dst[15] = src[15];
	}

	bool ffp_state::mat4_is_interesting(const float* m)
	{
		bool all_zero = true;
		for (int i = 0; i < 16; i++)
		{
			if (m[i] != 0.0f) { all_zero = false; break; }
		}
		if (all_zero) return false;

		// Check for identity
		if (m[0] == 1.0f && m[1] == 0.0f && m[2] == 0.0f  && m[3] == 0.0f &&
			m[4] == 0.0f && m[5] == 1.0f && m[6] == 0.0f  && m[7] == 0.0f &&
			m[8] == 0.0f && m[9] == 0.0f && m[10] == 1.0f && m[11] == 0.0f &&
			m[12] == 0.0f && m[13] == 0.0f && m[14] == 0.0f && m[15] == 1.0f)
			return false;

		return true;
	}
}
