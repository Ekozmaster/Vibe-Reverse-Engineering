#include "std_include.hpp"
#include "skinning.hpp"

#include "shared/common/config.hpp"
#include "shared/common/ffp_state.hpp"

#include <limits>
#include <wrl/client.h>

namespace comp
{
	using Microsoft::WRL::ComPtr;

	skinning::skinning()
	{
		p_this = this;
		shared::common::log("Skinning", "Module initialized.", shared::common::LOG_TYPE::LOG_TYPE_WARN);
	}

	skinning::~skinning()
	{
		release_device_objects();
		p_this = nullptr;
	}

	std::optional<HRESULT> skinning::draw_skinned_dip(IDirect3DDevice9* dev,
		D3DPRIMITIVETYPE pt, INT base_vtx, UINT min_vtx, UINT num_verts,
		UINT start_idx, UINT prim_count)
	{
		auto& ffp = shared::common::ffp_state::get();

		// Stream 0 and the declaration are the device's own: a state block changes them without
		// a call the wrapper sees. The layout ffp_state holds describes ffp.last_decl() alone.
		ComPtr<IDirect3DVertexDeclaration9> decl;
		ComPtr<IDirect3DVertexBuffer9> src_vb;
		UINT stream_offset = 0;
		UINT stride = 0;
		if (FAILED(dev->GetVertexDeclaration(&decl)) || decl.Get() != ffp.last_decl() ||
			FAILED(dev->GetStreamSource(0, &src_vb, &stream_offset, &stride)))
			return std::nullopt;

		if (!skin_exp_decl_)
			create_expanded_decl(dev);

		const bool convertible = skin_exp_decl_ && src_vb && ffp.num_bones() > 0 &&
			ffp.cur_decl_skin_vertex_bytes() > 0 && stride >= ffp.cur_decl_skin_vertex_bytes();

		// The draw reads num_verts vertices of the stream, from vertex base_vtx + min_vtx on
		const auto source_range = convertible
			? vertices_in_buffer(src_vb.Get(), stream_offset, static_cast<INT64>(base_vtx) + min_vtx, num_verts, stride)
			: vertex_range{};
		const auto* expanded = source_range.num_verts
			? get_expanded_vb(dev, src_vb.Get(), decl.Get(), source_range, stride, min_vtx)
			: nullptr;

		// No bone palette, a layout the expansion cannot read, no vertices inside the buffer, a
		// buffer that cannot be read back or a vertex blended by a bone past the end of the
		// palette: the game's shaders draw it
		if (!expanded || expanded->max_blend_index >= ffp.num_bones())
			return std::nullopt;

		// Engage FFP with skinning
		ffp.engage(dev);
		ffp.setup_albedo_texture(dev);
		upload_bones(dev);

		// Slot i of the expanded buffer holds the vertex the index i names, so the draw keeps the
		// game's indices and MinVertexIndex and needs no base vertex index
		dev->SetVertexDeclaration(skin_exp_decl_);
		dev->SetStreamSource(0, expanded->expanded, 0, SKIN_VTX_SIZE);
		const HRESULT hr = dev->DrawIndexedPrimitive(pt, 0, min_vtx, source_range.num_verts, start_idx, prim_count);

		dev->SetVertexDeclaration(decl.Get());
		dev->SetStreamSource(0, src_vb.Get(), stream_offset, stride);

		disable_skinning(dev);
		ffp.restore_world(dev);	// bone 0 went to WORLDMATRIX(0), which is D3DTS_WORLD
		ffp.restore_textures(dev);

		return hr;
	}

	void skinning::release_device_objects()
	{
		for (auto& entry : skin_exp_cache_)
			evict(entry);

		if (skin_exp_decl_)
		{
			skin_exp_decl_->Release();
			skin_exp_decl_ = nullptr;
		}
	}

	void skinning::create_expanded_decl(IDirect3DDevice9* dev)
	{
		// Expanded skinned vertex layout: FLOAT3 pos + FLOAT3 weights + UBYTE4 idx + FLOAT3 normal + FLOAT2 uv
		D3DVERTEXELEMENT9 elems[] = {
			{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
			{ 0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
			{ 0, 24, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
			{ 0, 28, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
			{ 0, 40, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
			D3DDECL_END()
		};

		HRESULT hr = dev->CreateVertexDeclaration(elems, &skin_exp_decl_);
		if (FAILED(hr))
		{
			shared::common::log("Skinning", "Failed to create expanded vertex declaration!",
				shared::common::LOG_TYPE::LOG_TYPE_ERROR, true);
			skin_exp_decl_ = nullptr;
		}
	}

	void skinning::evict(expanded_range& entry)
	{
		if (entry.expanded) entry.expanded->Release();
		if (entry.source) entry.source->Release();
		if (entry.source_decl) entry.source_decl->Release();
		entry = {};
	}

	skinning::vertex_range skinning::vertices_in_buffer(IDirect3DVertexBuffer9* src_vb, UINT stream_offset, INT64 first_vertex, UINT num_verts, UINT stride)
	{
		D3DVERTEXBUFFER_DESC desc = {};
		if (first_vertex < 0 || FAILED(src_vb->GetDesc(&desc)) || stream_offset >= desc.Size)
			return {};

		// The game rewrites a dynamic buffer, and an expansion is kept for as long as its source is drawn
		if (desc.Usage & D3DUSAGE_DYNAMIC)
			return {};

		// Direct3D documents a read of a write-only buffer as failing. The managed and system
		// memory pools keep a copy that reads back whatever the usage.
		const bool keeps_readable_copy = desc.Pool == D3DPOOL_MANAGED || desc.Pool == D3DPOOL_SYSTEMMEM;
		if ((desc.Usage & D3DUSAGE_WRITEONLY) && !keeps_readable_copy)
			return {};

		const UINT64 bytes_from_stream_start = desc.Size - stream_offset;
		if (static_cast<UINT64>(first_vertex) >= bytes_from_stream_start / stride)
			return {};

		// A loose NumVertices may run past the end of the buffer; the vertices the indices reach lie inside it
		const UINT64 vertex_bytes = shared::common::ffp_state::get().cur_decl_skin_vertex_bytes();
		const UINT64 room = bytes_from_stream_start - static_cast<UINT64>(first_vertex) * stride;
		const UINT64 fitting = room < vertex_bytes ? 0 : (room - vertex_bytes) / stride + 1;
		return { static_cast<UINT>(desc.Size - room), static_cast<UINT>((std::min)(static_cast<UINT64>(num_verts), fitting)) };
	}

	const skinning::expanded_range* skinning::get_expanded_vb(IDirect3DDevice9* dev,
		IDirect3DVertexBuffer9* src_vb, IDirect3DVertexDeclaration9* src_decl,
		const vertex_range& range, UINT stride, UINT first_slot)
	{
		auto& ffp = shared::common::ffp_state::get();
		const UINT first_byte = range.first_byte;
		const UINT num_verts = range.num_verts;

		unsigned int hash = static_cast<unsigned int>(reinterpret_cast<uintptr_t>(src_vb));
		hash ^= first_byte * 0x9E3779B9u;
		hash ^= num_verts * 0x517CC1B7u;
		hash ^= stride * 0x6C62272Eu;
		hash ^= first_slot * 0x85EBCA6Bu;

		auto& entry = skin_exp_cache_[hash % SKIN_CACHE_SIZE];

		// Cache hit
		if (entry.expanded && entry.source == src_vb && entry.source_decl == src_decl &&
			entry.first_byte == first_byte && entry.num_verts == num_verts && entry.stride == stride &&
			entry.first_slot == first_slot)
			return &entry;

		// The buffer has a slot for every index up to the last one drawn. No index names a slot
		// below first_slot; those are zeroed, so the buffer reads the same whoever reads all of it.
		const UINT64 expanded_bytes = (static_cast<UINT64>(first_slot) + num_verts) * SKIN_VTX_SIZE;
		if (expanded_bytes > (std::numeric_limits<UINT>::max)())
			return nullptr;
		const UINT expanded_size = static_cast<UINT>(expanded_bytes);
		const UINT unused_bytes = first_slot * SKIN_VTX_SIZE;

		evict(entry);

		// The last vertex needs only the bytes the expansion reads, which vertices_in_buffer kept inside the buffer
		const UINT locked_bytes = (num_verts - 1) * stride + ffp.cur_decl_skin_vertex_bytes();
		unsigned char* src_data = nullptr;
		if (FAILED(src_vb->Lock(first_byte, locked_bytes, reinterpret_cast<void**>(&src_data), D3DLOCK_READONLY)))
			return nullptr;

		ComPtr<IDirect3DVertexBuffer9> exp_vb;
		unsigned char* dst_data = nullptr;
		if (FAILED(dev->CreateVertexBuffer(expanded_size, D3DUSAGE_WRITEONLY, 0, D3DPOOL_DEFAULT, &exp_vb, nullptr)) ||
			FAILED(exp_vb->Lock(0, expanded_size, reinterpret_cast<void**>(&dst_data), 0)))
		{
			src_vb->Unlock();
			return nullptr;
		}

		std::memset(dst_data, 0, unused_bytes);
		BYTE max_blend_index = 0;
		for (UINT v = 0; v < num_verts; v++)
			max_blend_index = (std::max)(max_blend_index, expand_skin_vertex(&dst_data[unused_bytes + v * SKIN_VTX_SIZE], &src_data[v * stride]));

		exp_vb->Unlock();
		src_vb->Unlock();

		// Holding the source buffer and declaration keeps a new object from taking either address
		// while the entry names it
		src_vb->AddRef();
		src_decl->AddRef();
		entry = { src_vb, src_decl, first_byte, num_verts, stride, first_slot, exp_vb.Detach(), max_blend_index };

		return &entry;
	}

	BYTE skinning::expand_skin_vertex(unsigned char* dst, const unsigned char* src)
	{
		auto& ffp = shared::common::ffp_state::get();
		auto* out = reinterpret_cast<float*>(dst);

		// Position (FLOAT3, always at pos_off)
		auto* pos = reinterpret_cast<const float*>(&src[ffp.cur_decl_pos_off()]);
		out[0] = pos[0]; out[1] = pos[1]; out[2] = pos[2];

		// Blend weights (FLOAT3 at offset 12): FLOAT1-4 or UBYTE4N, the formats ffp_state takes as
		// expandable. A fourth weight is left out: fixed-function blending derives the last
		// weight from the others, and last_weight_used says whether that leaves anything.
		const int num_weights = ffp.cur_decl_num_weights();
		const auto bw_off = ffp.cur_decl_blend_weight_off();
		bool last_weight_used = false;

		if (ffp.cur_decl_blend_weight_type() == D3DDECLTYPE_UBYTE4N)
		{
			auto* bw = &src[bw_off];
			out[3] = bw[0] / 255.0f;
			out[4] = bw[1] / 255.0f;
			out[5] = bw[2] / 255.0f;
			last_weight_used = bw[0] + bw[1] + bw[2] != 255;
		}
		else
		{
			auto* bw = reinterpret_cast<const float*>(&src[bw_off]);
			float last_weight = 1.0f;
			for (int i = 0; i < 3; i++)
			{
				out[3 + i] = i < num_weights ? bw[i] : 0.0f;
				last_weight -= out[3 + i];
			}
			last_weight_used = last_weight != 0.0f;
		}

		// Blend indices (UBYTE4 at offset 24). The blend reads one index per stored weight and one
		// for the weight it derives. An index whose weight is 0 moves nothing and may hold
		// anything in the source, as may the bytes past those the blend reads: 0 takes its place.
		const auto* indices = &src[ffp.cur_decl_blend_indices_off()];
		BYTE max_blend_index = 0;
		for (int i = 0; i < 4; i++)
		{
			const bool used = i < num_weights ? out[3 + i] != 0.0f : (i == num_weights && last_weight_used);
			dst[24 + i] = used ? indices[i] : 0;
			max_blend_index = (std::max)(max_blend_index, dst[24 + i]);
		}

		// Normal (FLOAT3 at offset 28)
		if (ffp.cur_decl_has_normal())
		{
			decode_normal(&src[ffp.cur_decl_normal_off()], ffp.cur_decl_normal_type(), &out[7]);
		}
		else
		{
			out[7] = 0.0f; out[8] = 1.0f; out[9] = 0.0f;
		}

		// Texcoord (FLOAT2 at offset 40): FLOAT2-4 or FLOAT16_2, the formats ffp_state takes as expandable
		if (!ffp.cur_decl_has_texcoord())
		{
			out[10] = out[11] = 0.0f;
		}
		else if (ffp.cur_decl_texcoord_type() == D3DDECLTYPE_FLOAT16_2)
		{
			auto* h = reinterpret_cast<const unsigned short*>(&src[ffp.cur_decl_texcoord_off()]);
			out[10] = half_to_float(h[0]);
			out[11] = half_to_float(h[1]);
		}
		else
		{
			auto* tc = reinterpret_cast<const float*>(&src[ffp.cur_decl_texcoord_off()]);
			out[10] = tc[0]; out[11] = tc[1];
		}

		return max_blend_index;
	}

	void skinning::upload_bones(IDirect3DDevice9* dev)
	{
		auto& ffp = shared::common::ffp_state::get();

		const int bone_start = ffp.bone_start_reg();
		const int num_bones = ffp.num_bones();
		const float* vs_const = ffp.vs_const_data();
		const int regs_per_bone = ffp.regs_per_bone();

		for (int i = 0; i < num_bones; i++)
		{
			const float* src = &vs_const[(bone_start + i * regs_per_bone) * 4];
			float bone44[16];

			if (regs_per_bone == 3)
			{
				// Register c holds column c of the row-vector matrix; the fourth column is [0,0,0,1]
				for (int row = 0; row < 4; row++)
				{
					for (int column = 0; column < 3; column++)
						bone44[row * 4 + column] = src[column * 4 + row];
					bone44[row * 4 + 3] = row == 3 ? 1.0f : 0.0f;
				}
			}
			else
			{
				shared::common::ffp_state::mat4_transpose(bone44, src);
			}

			dev->SetTransform(static_cast<D3DTRANSFORMSTATETYPE>(D3DTS_WORLDMATRIX(i)),
				reinterpret_cast<const D3DMATRIX*>(bone44));
		}

		// Enable indexed vertex blending
		D3DVERTEXBLENDFLAGS blend_flag;
		int nw = ffp.cur_decl_num_weights();
		if (nw <= 1)      blend_flag = D3DVBF_1WEIGHTS;
		else if (nw == 2) blend_flag = D3DVBF_2WEIGHTS;
		else              blend_flag = D3DVBF_3WEIGHTS;

		dev->SetRenderState(D3DRS_VERTEXBLEND, blend_flag);
		dev->SetRenderState(D3DRS_INDEXEDVERTEXBLENDENABLE, TRUE);
	}

	void skinning::disable_skinning(IDirect3DDevice9* dev)
	{
		dev->SetRenderState(D3DRS_VERTEXBLEND, D3DVBF_DISABLE);
		dev->SetRenderState(D3DRS_INDEXEDVERTEXBLENDENABLE, FALSE);
	}

	float skinning::half_to_float(unsigned short h)
	{
		unsigned int sign = (h >> 15) & 0x1;
		unsigned int exp = (h >> 10) & 0x1F;
		unsigned int mant = h & 0x3FF;

		if (exp == 0)
		{
			if (mant == 0) {
				unsigned int f = sign << 31;
				float result;
				std::memcpy(&result, &f, sizeof(float));
				return result;
			}
			// Denormalized
			while (!(mant & 0x400)) { mant <<= 1; exp--; }
			exp++; mant &= ~0x400u;
		}
		else if (exp == 31)
		{
			unsigned int f = (sign << 31) | 0x7F800000u | (mant << 13);
			float result;
			std::memcpy(&result, &f, sizeof(float));
			return result;
		}

		exp += (127 - 15);
		unsigned int f = (sign << 31) | (exp << 23) | (mant << 13);
		float result;
		std::memcpy(&result, &f, sizeof(float));
		return result;
	}

	void skinning::decode_normal(const unsigned char* src, int type, float* out)
	{
		switch (type)
		{
		case D3DDECLTYPE_FLOAT3:
		{
			auto* fp = reinterpret_cast<const float*>(src);
			out[0] = fp[0]; out[1] = fp[1]; out[2] = fp[2];
			break;
		}
		case D3DDECLTYPE_DEC3N:
		{
			unsigned int packed = *reinterpret_cast<const unsigned int*>(src);
			int x = static_cast<int>((packed >>  0) & 0x3FF); if (x & 0x200) x |= ~0x3FF;
			int y = static_cast<int>((packed >> 10) & 0x3FF); if (y & 0x200) y |= ~0x3FF;
			int z = static_cast<int>((packed >> 20) & 0x3FF); if (z & 0x200) z |= ~0x3FF;
			out[0] = x / 511.0f;
			out[1] = y / 511.0f;
			out[2] = z / 511.0f;
			break;
		}
		case D3DDECLTYPE_UBYTE4N:
		{
			out[0] = (src[0] / 127.5f) - 1.0f;
			out[1] = (src[1] / 127.5f) - 1.0f;
			out[2] = (src[2] / 127.5f) - 1.0f;
			break;
		}
		}
	}
}
