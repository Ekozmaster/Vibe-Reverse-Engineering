#include "std_include.hpp"
#include "ffp_state.hpp"

namespace shared::common
{
	namespace
	{
		// Bytes a vertex element of this D3DDECLTYPE takes; 0 for D3DDECLTYPE_UNUSED
		UINT decl_type_size(BYTE type)
		{
			switch (type)
			{
			case D3DDECLTYPE_FLOAT1:    return 4;
			case D3DDECLTYPE_FLOAT2:    return 8;
			case D3DDECLTYPE_FLOAT3:    return 12;
			case D3DDECLTYPE_FLOAT4:    return 16;
			case D3DDECLTYPE_SHORT4:
			case D3DDECLTYPE_SHORT4N:
			case D3DDECLTYPE_USHORT4N:
			case D3DDECLTYPE_FLOAT16_4: return 8;
			case D3DDECLTYPE_UNUSED:    return 0;
			default:                    return 4;	// D3DCOLOR, UBYTE4(N), SHORT2(N), USHORT2N, UDEC3, DEC3N, FLOAT16_2
			}
		}

		// Whether [start_reg, start_reg + count) lies inside a register file of register_count registers
		bool registers_in_range(UINT start_reg, UINT count, UINT register_count)
		{
			return start_reg <= register_count && count <= register_count - start_reg;
		}

		// Element formats the skinning module can copy into its expanded vertex
		bool skinning_reads_texcoord(int type)
		{
			return type == D3DDECLTYPE_FLOAT2 || type == D3DDECLTYPE_FLOAT3 || type == D3DDECLTYPE_FLOAT4 ||
				type == D3DDECLTYPE_FLOAT16_2;
		}

		bool skinning_reads_normal(int type)
		{
			return type == D3DDECLTYPE_FLOAT3 || type == D3DDECLTYPE_DEC3N || type == D3DDECLTYPE_UBYTE4N;
		}
	}

	ffp_state& ffp_state::get()
	{
		static ffp_state instance;
		return instance;
	}

	void ffp_state::init(IDirect3DDevice9* /*real_device*/)
	{
		const auto& ffp = config::get().ffp;
		enabled_ = ffp.enabled;
		create_tick_ = GetTickCount();

		log("FFP", std::format("State tracker initialized, FFP={}", enabled_ ? "ON" : "OFF"));
		const auto& regs = ffp.registers;
		log("FFP", std::format("Registers: View=c{}-c{} Proj=c{}-c{} World=c{}-c{}",
			regs.view_start, regs.view_end - 1,
			regs.proj_start, regs.proj_end - 1,
			regs.world_start, regs.world_end - 1));
	}

	// ---- State mutators ----

	void ffp_state::on_set_vs_const_f(UINT start_reg, const float* data, UINT count)
	{
		if (!data || !registers_in_range(start_reg, count, 256)) return;

		std::memcpy(&vs_const_[start_reg * 4], data, count * 4 * sizeof(float));

		const auto& regs = config::get().ffp.registers;
		const auto& skinning = config::get().skinning;

		// Dirty tracking keyed to game-specific register layout
		const UINT end_reg = start_reg + count;
		const auto writes_into = [&](const int first, const int end)
		{
			return start_reg < static_cast<UINT>(end) && end_reg > static_cast<UINT>(first);
		};

		if (writes_into(regs.view_start, regs.view_end) || writes_into(regs.proj_start, regs.proj_end))
			view_proj_dirty_ = true;

		if (writes_into(regs.world_start, regs.world_end))
		{
			world_dirty_ = true;
			world_written_ = true;
		}

		for (UINT i = 0; i < count; i++)
			vs_const_write_log_[start_reg + i] = 1;

		// View+Proj become valid once all four registers of each have been written in one frame,
		// in any order and by any number of uploads
		if (!view_proj_valid_ && matrix_written(regs.view_start) && matrix_written(regs.proj_start))
			view_proj_valid_ = true;

		// Bone palette detection (for skinning module)
		if (skinning.enabled &&
			start_reg >= static_cast<UINT>(skinning.bone_threshold) &&
			count >= static_cast<UINT>(skinning.bone_min_regs) &&
			(count % static_cast<UINT>(skinning.regs_per_bone)) == 0)
		{
			bone_start_reg_ = static_cast<int>(start_reg);
			num_bones_ = static_cast<int>(count) / skinning.regs_per_bone;
		}
	}

	bool ffp_state::matrix_written(int first_reg) const
	{
		for (int r = first_reg; r < first_reg + 4; r++)
			if (!vs_const_write_log_[r]) return false;
		return true;
	}

	void ffp_state::on_set_ps_const_f(UINT start_reg, const float* data, UINT count)
	{
		if (!data || !registers_in_range(start_reg, count, 32)) return;

		std::memcpy(&ps_const_[start_reg * 4], data, count * 4 * sizeof(float));
	}

	void ffp_state::on_set_vertex_shader(IDirect3DVertexShader9* shader)
	{
		if (shader) shader->AddRef();
		if (last_vs_) last_vs_->Release();
		last_vs_ = shader;
	}

	void ffp_state::on_set_pixel_shader(IDirect3DPixelShader9* shader)
	{
		if (shader) shader->AddRef();
		if (last_ps_) last_ps_->Release();
		last_ps_ = shader;
	}

	void ffp_state::on_set_texture(UINT stage, IDirect3DBaseTexture9* texture)
	{
		if (stage < 8)
			cur_texture_[stage] = texture;
	}

	void ffp_state::on_set_vertex_declaration(IDirect3DVertexDeclaration9* decl)
	{
		if (decl) decl->AddRef();
		if (last_decl_) last_decl_->Release();
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
		cur_decl_skin_vertex_bytes_ = 0;

		if (!decl) return;

		UINT num_elems = 0;
		if (FAILED(decl->GetDeclaration(nullptr, &num_elems))) return;
		if (num_elems == 0 || num_elems > 32) return;

		D3DVERTEXELEMENT9 elems[32];
		if (FAILED(decl->GetDeclaration(elems, &num_elems))) return;

		bool has_blend_weight = false;
		bool has_blend_indices = false;
		int pos_type = -1;
		int blend_indices_type = -1;

		// The skinning module reads stream 0 alone. skin_vertex_bytes runs from the start of a
		// stream-0 vertex to the end of the last element it reads.
		bool skinning_reads_stream_0_alone = true;
		UINT skin_vertex_bytes = 0;
		const auto read_by_skinning = [&](const D3DVERTEXELEMENT9& el)
		{
			skinning_reads_stream_0_alone &= el.Stream == 0;
			skin_vertex_bytes = (std::max)(skin_vertex_bytes, static_cast<UINT>(el.Offset) + decl_type_size(el.Type));
		};

		for (UINT e = 0; e < num_elems; e++)
		{
			const auto& el = elems[e];
			if (el.Stream == 0xFF) break;

			switch (el.Usage)
			{
			case D3DDECLUSAGE_POSITIONT:
				cur_decl_has_pos_t_ = true;
				break;

			// Blend elements on any stream mark the declaration as skinned, and a normal or a
			// first texture coordinate on any stream is one the declaration has
			case D3DDECLUSAGE_BLENDWEIGHT:
				has_blend_weight = true;
				cur_decl_blend_weight_off_ = el.Offset;
				cur_decl_blend_weight_type_ = el.Type;
				read_by_skinning(el);
				break;

			case D3DDECLUSAGE_BLENDINDICES:
				has_blend_indices = true;
				cur_decl_blend_indices_off_ = el.Offset;
				blend_indices_type = el.Type;
				read_by_skinning(el);
				break;

			case D3DDECLUSAGE_POSITION:
				if (el.Stream == 0 && el.UsageIndex == 0)
				{
					pos_type = el.Type;
					cur_decl_pos_off_ = el.Offset;
					read_by_skinning(el);
				}
				break;

			case D3DDECLUSAGE_NORMAL:
				if (el.UsageIndex == 0)
				{
					cur_decl_has_normal_ = true;
					cur_decl_normal_off_ = el.Offset;
					cur_decl_normal_type_ = el.Type;
					read_by_skinning(el);
				}
				break;

			case D3DDECLUSAGE_TEXCOORD:
				if (el.UsageIndex == 0)
				{
					cur_decl_has_texcoord_ = true;
					cur_decl_texcoord_type_ = el.Type;
					cur_decl_texcoord_off_ = el.Offset;
					read_by_skinning(el);
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

			// The weights a vertex stores explicitly; the blend derives one more from them. A fourth
			// stored weight is left out, as fixed-function blending takes at most three. 0 for a
			// format the skinning module cannot read.
			switch (cur_decl_blend_weight_type_)
			{
			case D3DDECLTYPE_FLOAT1:  cur_decl_num_weights_ = 1; break;
			case D3DDECLTYPE_FLOAT2:  cur_decl_num_weights_ = 2; break;
			case D3DDECLTYPE_FLOAT3:
			case D3DDECLTYPE_FLOAT4:
			case D3DDECLTYPE_UBYTE4N: cur_decl_num_weights_ = 3; break;
			default:                  cur_decl_num_weights_ = 0; break;
			}

			// The skinning module reads a FLOAT3 position, weights it can decode, four index bytes
			// and, where the declaration has them, a normal and a texture coordinate in a format
			// it can decode, all of them from stream 0. D3DCOLOR indices are taken in memory
			// order, the order D3DCOLORtoUBYTE4 gives a shader.
			const bool readable_indices = blend_indices_type == D3DDECLTYPE_UBYTE4 || blend_indices_type == D3DDECLTYPE_D3DCOLOR;
			const bool expandable = skinning_reads_stream_0_alone && readable_indices && cur_decl_num_weights_ > 0 &&
				(pos_type == D3DDECLTYPE_FLOAT3 || pos_type == D3DDECLTYPE_FLOAT4) &&
				(!cur_decl_has_normal_ || skinning_reads_normal(cur_decl_normal_type_)) &&
				(!cur_decl_has_texcoord_ || skinning_reads_texcoord(cur_decl_texcoord_type_));
			cur_decl_skin_vertex_bytes_ = expandable ? skin_vertex_bytes : 0;
		}
	}

	void ffp_state::on_set_fvf(DWORD fvf)
	{
		// Direct3D ignores an FVF of 0. Any other takes the place of the declaration, and a draw
		// without one is left to the game's shaders.
		if (fvf != 0)
			on_set_vertex_declaration(nullptr);
	}

	void ffp_state::on_present(IDirect3DDevice9* dev)
	{
		frame_count_++;
		ffp_setup_ = false;
		draw_call_count_ = 0;
		scene_count_ = 0;
		// A frame whose last draw was converted ends engaged
		disengage(dev);
		std::memset(vs_const_write_log_, 0, sizeof(vs_const_write_log_));
	}

	void ffp_state::on_begin_scene()
	{
		ffp_setup_ = false;
		scene_count_++;
	}

	void ffp_state::on_reset()
	{
		// The device may stay in use, so it gets the game's shaders back before they are let go of
		disengage(ffp_device_);

		if (last_vs_) { last_vs_->Release(); last_vs_ = nullptr; }
		if (last_ps_) { last_ps_->Release(); last_ps_ = nullptr; }
		if (last_decl_) { last_decl_->Release(); last_decl_ = nullptr; }

		// Default-pool textures are released by the game before Reset
		std::memset(cur_texture_, 0, sizeof(cur_texture_));

		view_proj_valid_ = false;
		ffp_setup_ = false;
		world_dirty_ = false;
		world_written_ = false;
		view_proj_dirty_ = false;
		bone_start_reg_ = 0;
		num_bones_ = 0;

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
		cur_decl_skin_vertex_bytes_ = 0;

		std::memset(vs_const_write_log_, 0, sizeof(vs_const_write_log_));

		log("FFP", "State reset");
	}

	// ---- State consumers ----

	void ffp_state::engage(IDirect3DDevice9* dev)
	{
		if (!enabled_ || !dev) return;

		if (!ffp_device_)
		{
			dev->SetVertexShader(nullptr);
			dev->SetPixelShader(nullptr);
			ffp_device_ = dev;
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
		if (!dev || dev != ffp_device_) return;

		dev->SetVertexShader(last_vs_);
		dev->SetPixelShader(last_ps_);
		ffp_device_ = nullptr;
	}

	void ffp_state::setup_albedo_texture(IDirect3DDevice9* dev)
	{
		if (!dev) return;

		int as = config::get().ffp.albedo_stage;
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

	void ffp_state::restore_world(IDirect3DDevice9* dev)
	{
		if (!dev) return;

		// Until the game uploads a world matrix (since device creation or Reset), FFP draws use identity
		if (!world_written_)
		{
			dev->SetTransform(D3DTS_WORLD, &shared::globals::IDENTITY);
			return;
		}

		world_dirty_ = true;
		apply_transforms(dev);
	}

	// ---- Internal helpers ----

	void ffp_state::apply_transforms(IDirect3DDevice9* dev)
	{
		const auto& regs = config::get().ffp.registers;
		float transposed[16];

		if (view_proj_dirty_)
		{
			mat4_transpose(transposed, &vs_const_[regs.view_start * 4]);
			dev->SetTransform(D3DTS_VIEW, reinterpret_cast<const D3DMATRIX*>(transposed));

			mat4_transpose(transposed, &vs_const_[regs.proj_start * 4]);
			dev->SetTransform(D3DTS_PROJECTION, reinterpret_cast<const D3DMATRIX*>(transposed));

			view_proj_dirty_ = false;
		}

		if (world_dirty_)
		{
			mat4_transpose(transposed, &vs_const_[regs.world_start * 4]);
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
