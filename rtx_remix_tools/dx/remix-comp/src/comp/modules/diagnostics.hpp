#pragma once

namespace comp
{
	/*
	 * Diagnostic logging module for FFP conversion debugging.
	 *
	 * After a configurable delay (default 50 seconds), logs N frames of
	 * draw call data to ffp_proxy.log in the game directory. This captures:
	 * - VS constant register writes and matrix values
	 * - Vertex declaration elements and skinning flags
	 * - Texture stage bindings
	 * - Draw call parameters and strides
	 * - Raw vertex bytes for early draw calls
	 *
	 * The delay ensures the game is in-game with real geometry before logging.
	 */
	class diagnostics final : public shared::common::loader::component_module
	{
	public:
		diagnostics();
		~diagnostics();

		static inline diagnostics* p_this = nullptr;
		static diagnostics* get() { return p_this; }

		bool is_active() const;

		// Called from renderer draw hooks
		void on_draw_indexed_prim(UINT draw_count, IDirect3DDevice9* dev,
			D3DPRIMITIVETYPE pt, INT base_vtx, UINT num_verts, UINT prim_count);
		void on_draw_primitive(UINT draw_count, D3DPRIMITIVETYPE pt,
			UINT start_vtx, UINT prim_count);

		// Called from d3d9ex hooks via ffp_state
		void on_present(UINT frame_count, UINT draw_count, UINT scene_count);
		void on_set_vs_const_f(UINT start_reg, const float* data, UINT count);

		// Deduplicated vertex declaration logging
		void log_decl(IDirect3DVertexDeclaration9* decl);

	private:
		HANDLE log_file_ = INVALID_HANDLE_VALUE;
		DWORD delay_ms_ = 50000;
		int max_frames_ = 3;
		int logged_frames_ = 0;
		DWORD create_tick_ = 0;

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
