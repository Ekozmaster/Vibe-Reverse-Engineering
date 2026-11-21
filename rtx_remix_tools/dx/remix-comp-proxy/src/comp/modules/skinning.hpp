#pragma once

#include <optional>

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

		// Called from renderer when cur_decl_is_skinned. Draws with FFP indexed vertex blending
		// and returns the result of the draw, or returns nullopt without drawing when the draw
		// has to be left to the game's shaders.
		std::optional<HRESULT> draw_skinned_dip(IDirect3DDevice9* dev,
			D3DPRIMITIVETYPE pt, INT base_vtx, UINT min_vtx, UINT num_verts,
			UINT start_idx, UINT prim_count);

		// Lets go of everything created on the device or kept from it. Called before the device
		// is Reset and when the game releases it.
		void release_device_objects();

	private:
		static constexpr int SKIN_VTX_SIZE = 48;
		static constexpr int SKIN_CACHE_SIZE = 64;

		IDirect3DVertexDeclaration9* skin_exp_decl_ = nullptr;

		// Vertices of a source buffer: num_verts of them from first_byte on. No vertices when num_verts is 0.
		struct vertex_range
		{
			UINT first_byte = 0;
			UINT num_verts = 0;
		};

		// The vertices of one draw, in the expanded layout. A buffer is reused for as long as
		// the same range of the same source buffer is drawn with the same declaration, so the
		// game is taken not to rewrite a skinned mesh's vertices; a D3DUSAGE_DYNAMIC source,
		// made to be rewritten, is not expanded. The entry holds a reference to its source
		// buffer and declaration until it is evicted. The expanded buffer has first_slot
		// zeroed vertices in front, so that the draw's indices address it unchanged.
		struct expanded_range
		{
			IDirect3DVertexBuffer9* source = nullptr;
			IDirect3DVertexDeclaration9* source_decl = nullptr;
			UINT first_byte = 0;
			UINT num_verts = 0;
			UINT stride = 0;
			UINT first_slot = 0;
			IDirect3DVertexBuffer9* expanded = nullptr;
			BYTE max_blend_index = 0;	// highest bone index the blend reads in these vertices
		};

		// Memory cost: up to SKIN_CACHE_SIZE default-pool buffers of SKIN_VTX_SIZE bytes per
		// index from 0 to the highest one a draw names (MinVertexIndex + NumVertices), and each
		// entry keeps a game vertex buffer and declaration alive after the game releases them.
		// An entry is replaced when another range hashes to its slot; all are released by
		// release_device_objects.
		expanded_range skin_exp_cache_[SKIN_CACHE_SIZE] = {};

		void create_expanded_decl(IDirect3DDevice9* dev);
		static void evict(expanded_range& entry);

		// Vertex expansion. vertices_in_buffer gives the part of the num_verts vertices from
		// vertex first_vertex of the stream on that src_vb holds; none when first_vertex lies
		// outside the buffer or when the buffer is dynamic or cannot be read back.
		static vertex_range vertices_in_buffer(IDirect3DVertexBuffer9* src_vb, UINT stream_offset, INT64 first_vertex, UINT num_verts, UINT stride);
		// The cache entry for the range read with src_decl, expanded now if it was not cached, its
		// vertices in the slots from first_slot on; nullptr on failure
		const expanded_range* get_expanded_vb(IDirect3DDevice9* dev,
			IDirect3DVertexBuffer9* src_vb, IDirect3DVertexDeclaration9* src_decl,
			const vertex_range& range, UINT stride, UINT first_slot);
		// Writes one vertex in the expanded layout; returns the highest bone index its blend reads
		BYTE expand_skin_vertex(unsigned char* dst, const unsigned char* src);

		// Bone upload
		void upload_bones(IDirect3DDevice9* dev);
		void disable_skinning(IDirect3DDevice9* dev);

		// Format decoders
		static float half_to_float(unsigned short h);
		// type is FLOAT3, DEC3N or UBYTE4N, the formats ffp_state takes as expandable
		static void decode_normal(const unsigned char* src, int type, float* out);
	};
}
