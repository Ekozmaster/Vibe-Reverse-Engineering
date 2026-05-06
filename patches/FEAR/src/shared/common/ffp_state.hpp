#pragma once
#include "config.hpp"

namespace shared::common
{
	/*
	 * FFP state tracker — captures D3D9 state needed for fixed-function pipeline conversion.
	 *
	 * The D3D9Device proxy calls on_xxx() methods when the game sets shaders, constants,
	 * textures, vertex declarations, etc. The renderer reads state via accessors to make
	 * draw routing decisions, then calls engage/disengage to switch between shader and FFP modes.
	 */
	class ffp_state
	{
	public:
		static ffp_state& get();

		void init(IDirect3DDevice9* real_device);

		// --- State mutators (called from D3D9Device interceptions) ---

		void on_set_vs_const_f(UINT start_reg, const float* data, UINT count);
		void on_set_ps_const_f(UINT start_reg, const float* data, UINT count);
		void on_set_vertex_shader(IDirect3DVertexShader9* shader);

		void on_set_pixel_shader(IDirect3DPixelShader9* shader);

		void on_set_texture(UINT stage, IDirect3DBaseTexture9* texture);
		void on_set_stream_source(UINT stream, IDirect3DVertexBuffer9* vb, UINT offset, UINT stride);
		void on_set_vertex_declaration(IDirect3DVertexDeclaration9* decl);
		void on_present();
		void on_begin_scene();
		void on_reset();

		// --- State consumers (called from renderer draw routing) ---

		void engage(IDirect3DDevice9* dev);
		void disengage(IDirect3DDevice9* dev);

		// Bind albedo texture to stage 0, NULL stages 1-7. Call before draw.
		void setup_albedo_texture(IDirect3DDevice9* dev);

		// Restore original texture bindings on all 8 stages. Call after draw.
		void restore_textures(IDirect3DDevice9* dev);

		// --- Read-only accessors for renderer ---

		bool is_enabled() const { return enabled_; }
		void set_enabled(bool e) { enabled_ = e; }

		bool view_proj_valid() const { return view_proj_valid_; }
		bool is_ffp_active() const { return ffp_active_; }
		bool cur_decl_is_skinned() const { return cur_decl_is_skinned_; }
		bool cur_decl_has_normal() const { return cur_decl_has_normal_; }
		bool cur_decl_has_pos_t() const { return cur_decl_has_pos_t_; }
		bool cur_decl_has_texcoord() const { return cur_decl_has_texcoord_; }
		bool cur_decl_has_color() const { return cur_decl_has_color_; }
		int cur_decl_texcoord_type() const { return cur_decl_texcoord_type_; }

		IDirect3DVertexShader9* last_vs() const { return last_vs_; }
		IDirect3DPixelShader9* last_ps() const { return last_ps_; }
		IDirect3DVertexDeclaration9* last_decl() const { return last_decl_; }

		// --- Diagnostic data access ---

		const float* vs_const_data() const { return vs_const_; }
		const float* ps_const_data() const { return ps_const_; }
		const int* vs_const_write_log() const { return vs_const_write_log_; }
		UINT draw_call_count() const { return draw_call_count_; }
		UINT frame_count() const { return frame_count_; }
		UINT scene_count() const { return scene_count_; }
		DWORD create_tick() const { return create_tick_; }

		// Texture tracking (stages 0-7)
		IDirect3DBaseTexture9* cur_texture(UINT stage) const { return stage < 8 ? cur_texture_[stage] : nullptr; }

		// Stream source tracking
		IDirect3DVertexBuffer9* stream_vb(UINT stream) const { return stream < 4 ? stream_vb_[stream] : nullptr; }
		UINT stream_offset(UINT stream) const { return stream < 4 ? stream_offset_[stream] : 0; }
		UINT stream_stride(UINT stream) const { return stream < 4 ? stream_stride_[stream] : 0; }

		// VS constant register layout (game-specific, edit defaults when porting)
		int reg_view_start() const { return vs_reg_view_start_; }
		int reg_view_end() const { return vs_reg_view_end_; }
		int reg_proj_start() const { return vs_reg_proj_start_; }
		int reg_proj_end() const { return vs_reg_proj_end_; }
		int reg_world_start() const { return vs_reg_world_start_; }
		int reg_world_end() const { return vs_reg_world_end_; }
		int reg_bone_threshold() const { return vs_reg_bone_threshold_; }
		int regs_per_bone() const { return vs_regs_per_bone_; }
		int bone_min_regs() const { return vs_bone_min_regs_; }

		// Skinning data (populated by skinning module via on_set_vs_const_f bone detection)
		int bone_start_reg() const { return bone_start_reg_; }
		int num_bones() const { return num_bones_; }
		int cur_decl_num_weights() const { return cur_decl_num_weights_; }
		int cur_decl_blend_weight_off() const { return cur_decl_blend_weight_off_; }
		int cur_decl_blend_weight_type() const { return cur_decl_blend_weight_type_; }
		int cur_decl_blend_indices_off() const { return cur_decl_blend_indices_off_; }
		int cur_decl_pos_off() const { return cur_decl_pos_off_; }
		int cur_decl_normal_off() const { return cur_decl_normal_off_; }
		int cur_decl_normal_type() const { return cur_decl_normal_type_; }
		int cur_decl_texcoord_off() const { return cur_decl_texcoord_off_; }

		void increment_draw_count() { draw_call_count_++; }

		// --- Utility ---

		static void mat4_transpose(float* dst, const float* src);
		static bool mat4_is_interesting(const float* m);

	private:
		bool enabled_ = true;

		// VS/PS constant capture
		float vs_const_[256 * 4] = {};
		float ps_const_[32 * 4] = {};

		// Dirty tracking
		bool world_dirty_ = false;
		bool view_proj_dirty_ = false;
		bool view_proj_valid_ = false;
		bool ffp_active_ = false;
		bool ffp_setup_ = false;

		// Shader tracking
		IDirect3DVertexShader9* last_vs_ = nullptr;
		IDirect3DPixelShader9* last_ps_ = nullptr;

		// Vertex declaration tracking
		IDirect3DVertexDeclaration9* last_decl_ = nullptr;
		bool cur_decl_is_skinned_ = false;
		bool cur_decl_has_texcoord_ = false;
		bool cur_decl_has_normal_ = false;
		bool cur_decl_has_color_ = false;
		bool cur_decl_has_pos_t_ = false;
		int cur_decl_texcoord_type_ = -1;
		int cur_decl_texcoord_off_ = 0;

		// Skinning-related declaration data
		int cur_decl_num_weights_ = 0;
		int cur_decl_blend_weight_off_ = 0;
		int cur_decl_blend_weight_type_ = 0;
		int cur_decl_blend_indices_off_ = 0;
		int cur_decl_pos_off_ = 0;
		int cur_decl_normal_off_ = 0;
		int cur_decl_normal_type_ = -1;

		// VS constant register layout (game-specific defaults — edit when porting)
		int vs_reg_view_start_ = 0;
		int vs_reg_view_end_ = 4;
		int vs_reg_proj_start_ = 4;
		int vs_reg_proj_end_ = 8;
		int vs_reg_world_start_ = 16;
		int vs_reg_world_end_ = 20;
		int vs_reg_bone_threshold_ = 20;
		int vs_regs_per_bone_ = 3;
		int vs_bone_min_regs_ = 3;

		// Bone detection
		int bone_start_reg_ = 0;
		int num_bones_ = 0;

		// Texture tracking
		IDirect3DBaseTexture9* cur_texture_[8] = {};

		// Stream source tracking
		IDirect3DVertexBuffer9* stream_vb_[4] = {};
		UINT stream_offset_[4] = {};
		UINT stream_stride_[4] = {};

		// Frame/draw counters
		UINT frame_count_ = 0;
		UINT draw_call_count_ = 0;
		UINT scene_count_ = 0;
		DWORD create_tick_ = 0;

		// VS constant write log (for diagnostics: which registers have been written)
		int vs_const_write_log_[256] = {};

		// Cached config
		const config::ffp_settings* cfg_ = nullptr;

		// Internal helpers
		void apply_transforms(IDirect3DDevice9* dev);
		void setup_lighting(IDirect3DDevice9* dev);
		void setup_texture_stages(IDirect3DDevice9* dev);
	};
}
