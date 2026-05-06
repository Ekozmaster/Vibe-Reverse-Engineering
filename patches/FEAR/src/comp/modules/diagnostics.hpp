#pragma once

namespace comp
{
	/*
	 * Diagnostic logging module for FFP conversion debugging.
	 *
	 * Two capture modes:
	 *   Auto:      After a configurable delay, captures N frames automatically.
	 *   On-demand: Triggered from ImGui, captures N frames immediately.
	 *
	 * Log categories control what gets written during any capture:
	 *   draw_calls     - DIP/DP parameters, strides, decl flags
	 *   vs_constants   - SetVertexShaderConstantF register writes, matrix dumps
	 *   vertex_data    - Raw vertex bytes from the first few draw calls
	 *   declarations   - Vertex declaration element breakdown (deduplicated)
	 *   textures       - Texture bindings per stage, unique texture counts
	 *   present_info   - Frame summary (draw count, scene count, VS regs written)
	 */
	class diagnostics final : public shared::common::loader::component_module
	{
	public:
		diagnostics();
		~diagnostics();

		static inline diagnostics* p_this = nullptr;
		static diagnostics* get() { return p_this; }

		// True when actively logging (auto or on-demand)
		bool is_active() const;

		// On-demand capture from ImGui
		void start_capture(int frames);
		void stop_capture();
		bool is_capturing() const { return on_demand_active_; }
		int frames_captured() const { return on_demand_logged_; }
		int frames_to_capture() const { return on_demand_frames_; }

		// Called from d3d9ex/renderer hooks
		void on_draw_indexed_prim(UINT draw_count, IDirect3DDevice9* dev,
			D3DPRIMITIVETYPE pt, INT base_vtx, UINT num_verts, UINT prim_count);
		void on_draw_primitive(UINT draw_count, D3DPRIMITIVETYPE pt,
			UINT start_vtx, UINT prim_count);
		void on_present(UINT frame_count, UINT draw_count, UINT scene_count);
		void on_set_vs_const_f(UINT start_reg, const float* data, UINT count);
		void on_begin_scene(UINT scene_count);
		void on_set_vertex_shader(void* shader_ptr);

		// Deduplicated vertex declaration logging
		void log_decl(IDirect3DVertexDeclaration9* decl);

		// Log category flags (mutable at runtime from ImGui)
		bool cat_draw_calls = true;
		bool cat_vs_constants = true;
		bool cat_vertex_data = true;
		bool cat_declarations = true;
		bool cat_textures = true;
		bool cat_present_info = true;

		// Last capture info (for ImGui display)
		const std::string& last_log_path() const { return last_log_path_; }

	private:
		HANDLE log_file_ = INVALID_HANDLE_VALUE;

		// Auto-capture state
		DWORD delay_ms_ = 50000;
		int auto_max_frames_ = 3;
		int auto_logged_frames_ = 0;
		bool auto_enabled_ = true;
		DWORD create_tick_ = 0;

		// On-demand capture state
		bool on_demand_active_ = false;
		int on_demand_frames_ = 0;
		int on_demand_logged_ = 0;

		std::string last_log_path_;

		// Auto-capture active check
		bool auto_is_active() const;

		// File management
		void open_log(const std::string& path);
		void close_log();

		// Dedup for declaration logging
		IDirect3DVertexDeclaration9* logged_decls_[32] = {};
		int logged_decl_count_ = 0;

		// Unique texture tracking per stage per frame
		IDirect3DBaseTexture9* diag_tex_seen_[8][32] = {};
		int diag_tex_uniq_[8] = {};

		void log_str(const char* s);
		void log_int(const char* prefix, int val);
		void log_hex(const char* prefix, unsigned int val);
		void log_floats_dec(const char* prefix, const float* data, unsigned int count);
		void log_matrix(const char* name, const float* m);

		void track_unique_textures();
		void reset_frame_diag();
	};
}
