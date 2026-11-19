#pragma once

namespace comp
{
	/*
	 * Optional skinning module for FFP conversion.
	 *
	 * When enabled via [Skinning] Enabled=1 in remix-comp-proxy.ini, this module
	 * handles skinned mesh rendering by expanding compressed vertex data,
	 * uploading bone matrices via SetTransform(WORLDMATRIX(i)), and drawing
	 * with D3D FFP indexed vertex blending.
	 *
	 * Only enable after rigid FFP geometry works correctly.
	 */
	class skinning final : public shared::common::loader::component_module
	{
	public:
		skinning();
		~skinning();

		static inline skinning* p_this = nullptr;
		static skinning* get() { return p_this; }

		static bool is_available()
		{
			return p_this != nullptr;
		}

		// Called from renderer when cur_decl_is_skinned
		HRESULT draw_skinned_dip(IDirect3DDevice9* dev,
			D3DPRIMITIVETYPE pt, INT base_vtx, UINT min_vtx, UINT num_verts,
			UINT start_idx, UINT prim_count);

		// Called on device reset
		void on_reset();

	private:
		static constexpr int SKIN_VTX_SIZE = 48;
		static constexpr int SKIN_CACHE_SIZE = 64;
		static constexpr int MAX_BONES = 256;	// D3DTS_WORLDMATRIX takes indices 0-255

		IDirect3DVertexDeclaration9* skin_exp_decl_ = nullptr;

		// The vertices of one draw, in the expanded layout. A buffer is reused for as long as
		// the same range of the same source buffer is drawn with the same declaration, so the
		// game is taken not to rewrite a skinned mesh's vertices.
		struct expanded_range
		{
			IDirect3DVertexBuffer9* source = nullptr;
			IDirect3DVertexDeclaration9* source_decl = nullptr;
			UINT first_byte = 0;
			UINT num_verts = 0;
			UINT stride = 0;
			IDirect3DVertexBuffer9* expanded = nullptr;
		};
		expanded_range skin_exp_cache_[SKIN_CACHE_SIZE] = {};

		bool initialized_ = false;

		void create_expanded_decl(IDirect3DDevice9* dev);
		void release_cache();

		// Vertex expansion
		IDirect3DVertexBuffer9* get_expanded_vb(IDirect3DDevice9* dev,
			IDirect3DVertexBuffer9* src_vb, UINT first_byte, UINT num_verts, UINT stride);
		void expand_skin_vertex(unsigned char* dst, const unsigned char* src, UINT stride);

		// Bone upload
		void upload_bones(IDirect3DDevice9* dev);
		void disable_skinning(IDirect3DDevice9* dev);

		// Format decoders
		static float half_to_float(unsigned short h);
		static void decode_normal(const unsigned char* src, int type, float* out);
	};
}
