#include "std_include.hpp"
#include "skinning.hpp"

#include "shared/common/config.hpp"
#include "shared/common/ffp_state.hpp"

namespace comp
{
	skinning::skinning()
	{
		p_this = this;
		initialized_ = true;
		shared::common::log("Skinning", "Module initialized.", shared::common::LOG_TYPE::LOG_TYPE_WARN);
	}

	skinning::~skinning()
	{
		release_cache();
		if (skin_exp_decl_)
		{
			skin_exp_decl_->Release();
			skin_exp_decl_ = nullptr;
		}
		p_this = nullptr;
	}

	HRESULT skinning::draw_skinned_dip(IDirect3DDevice9* dev,
		D3DPRIMITIVETYPE pt, INT base_vtx, UINT min_vtx, UINT num_verts,
		UINT start_idx, UINT prim_count)
	{
		auto& ffp = shared::common::ffp_state::get();

		// Create expanded declaration on first use
		if (!skin_exp_decl_)
			create_expanded_decl(dev);

		// The draw reads num_verts vertices of the stream, from vertex base_vtx + min_vtx on
		auto* src_vb = ffp.stream_vb(0);
		const UINT stride = ffp.stream_stride(0);
		const INT first_vtx = base_vtx + static_cast<INT>(min_vtx);
		const bool convertible = skin_exp_decl_ && ffp.num_bones() > 0 && first_vtx >= 0 &&
			ffp.cur_decl_skin_vertex_bytes() > 0 && stride >= ffp.cur_decl_skin_vertex_bytes();

		const auto source_range = convertible
			? vertices_in_buffer(src_vb, ffp.stream_offset(0) + static_cast<UINT64>(first_vtx) * stride, num_verts, stride)
			: vertex_range{};
		auto* exp_vb = source_range.num_verts ? get_expanded_vb(dev, src_vb, source_range, stride) : nullptr;

		// No bone palette, a layout the expansion cannot read or no vertices inside the buffer:
		// the game's shaders draw it
		if (!exp_vb)
		{
			ffp.disengage(dev);
			return dev->DrawIndexedPrimitive(pt, base_vtx, min_vtx, num_verts, start_idx, prim_count);
		}

		// Engage FFP with skinning
		ffp.engage(dev);
		ffp.setup_albedo_texture(dev);
		upload_bones(dev);

		// Swap in expanded VB and declaration
		IDirect3DVertexDeclaration9* orig_decl = nullptr;
		dev->GetVertexDeclaration(&orig_decl);
		dev->SetVertexDeclaration(skin_exp_decl_);
		dev->SetStreamSource(0, exp_vb, 0, SKIN_VTX_SIZE);

		// Vertex 0 of the expanded buffer is the vertex the index min_vtx names
		auto hr = dev->DrawIndexedPrimitive(pt, -static_cast<INT>(min_vtx), min_vtx, source_range.num_verts, start_idx, prim_count);

		// Restore original state
		dev->SetVertexDeclaration(orig_decl);
		if (orig_decl) orig_decl->Release();
		dev->SetStreamSource(0, src_vb, ffp.stream_offset(0), stride);

		disable_skinning(dev);
		ffp.restore_world(dev);	// bone 0 went to WORLDMATRIX(0), which is D3DTS_WORLD
		ffp.restore_textures(dev);

		return hr;
	}

	void skinning::on_reset()
	{
		release_cache();
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

	void skinning::release_cache()
	{
		for (auto& entry : skin_exp_cache_)
			evict(entry);
	}

	void skinning::evict(expanded_range& entry)
	{
		if (entry.expanded) entry.expanded->Release();
		if (entry.source) entry.source->Release();
		if (entry.source_decl) entry.source_decl->Release();
		entry = {};
	}

	skinning::vertex_range skinning::vertices_in_buffer(IDirect3DVertexBuffer9* src_vb, UINT64 first_byte, UINT num_verts, UINT stride)
	{
		D3DVERTEXBUFFER_DESC desc = {};
		if (!src_vb || FAILED(src_vb->GetDesc(&desc)) || first_byte >= desc.Size)
			return {};

		// A loose NumVertices may run past the end of the buffer; the vertices the indices reach lie inside it
		const UINT64 vertex_bytes = shared::common::ffp_state::get().cur_decl_skin_vertex_bytes();
		const UINT64 room = desc.Size - first_byte;
		const UINT64 fitting = room < vertex_bytes ? 0 : (room - vertex_bytes) / stride + 1;
		return { static_cast<UINT>(first_byte), static_cast<UINT>((std::min)(static_cast<UINT64>(num_verts), fitting)) };
	}

	IDirect3DVertexBuffer9* skinning::get_expanded_vb(IDirect3DDevice9* dev,
		IDirect3DVertexBuffer9* src_vb, const vertex_range& range, UINT stride)
	{
		auto& ffp = shared::common::ffp_state::get();
		auto* src_decl = ffp.last_decl();
		const UINT first_byte = range.first_byte;
		const UINT num_verts = range.num_verts;

		unsigned int hash = static_cast<unsigned int>(reinterpret_cast<uintptr_t>(src_vb));
		hash ^= first_byte * 0x9E3779B9u;
		hash ^= num_verts * 0x517CC1B7u;
		hash ^= stride * 0x6C62272Eu;

		auto& entry = skin_exp_cache_[hash % SKIN_CACHE_SIZE];

		// Cache hit
		if (entry.expanded && entry.source == src_vb && entry.source_decl == src_decl &&
			entry.first_byte == first_byte && entry.num_verts == num_verts && entry.stride == stride)
			return entry.expanded;

		evict(entry);

		// The last vertex needs only the bytes the expansion reads, which vertices_in_buffer kept inside the buffer
		const UINT locked_bytes = (num_verts - 1) * stride + ffp.cur_decl_skin_vertex_bytes();
		unsigned char* src_data = nullptr;
		if (FAILED(src_vb->Lock(first_byte, locked_bytes, reinterpret_cast<void**>(&src_data), D3DLOCK_READONLY)))
			return nullptr;

		// Create expanded VB
		IDirect3DVertexBuffer9* exp_vb = nullptr;
		if (FAILED(dev->CreateVertexBuffer(num_verts * SKIN_VTX_SIZE, D3DUSAGE_WRITEONLY,
			0, D3DPOOL_MANAGED, &exp_vb, nullptr)))
		{
			src_vb->Unlock();
			return nullptr;
		}

		// Lock and expand
		unsigned char* dst_data = nullptr;
		if (FAILED(exp_vb->Lock(0, num_verts * SKIN_VTX_SIZE, reinterpret_cast<void**>(&dst_data), 0)))
		{
			src_vb->Unlock();
			exp_vb->Release();
			return nullptr;
		}

		for (UINT v = 0; v < num_verts; v++)
			expand_skin_vertex(&dst_data[v * SKIN_VTX_SIZE], &src_data[v * stride]);

		exp_vb->Unlock();
		src_vb->Unlock();

		// Holding the source buffer and declaration keeps a new object from taking either address
		// while the entry names it
		src_vb->AddRef();
		if (src_decl) src_decl->AddRef();
		entry = { src_vb, src_decl, first_byte, num_verts, stride, exp_vb };

		return exp_vb;
	}

	void skinning::expand_skin_vertex(unsigned char* dst, const unsigned char* src)
	{
		auto& ffp = shared::common::ffp_state::get();
		auto* out = reinterpret_cast<float*>(dst);

		// Position (FLOAT3, always at pos_off)
		auto* pos = reinterpret_cast<const float*>(&src[ffp.cur_decl_pos_off()]);
		out[0] = pos[0]; out[1] = pos[1]; out[2] = pos[2];

		// Blend weights (FLOAT3 at offset 12)
		int num_weights = ffp.cur_decl_num_weights();
		auto bw_off = ffp.cur_decl_blend_weight_off();
		auto bw_type = ffp.cur_decl_blend_weight_type();

		// A FLOAT4's fourth weight is left out: fixed-function blending derives the last weight from the others
		if (bw_type == D3DDECLTYPE_FLOAT4 || bw_type == D3DDECLTYPE_FLOAT3 ||
			bw_type == D3DDECLTYPE_FLOAT2 || bw_type == D3DDECLTYPE_FLOAT1)
		{
			auto* bw = reinterpret_cast<const float*>(&src[bw_off]);
			out[3] = (num_weights >= 1) ? bw[0] : 0.0f;
			out[4] = (num_weights >= 2) ? bw[1] : 0.0f;
			out[5] = (num_weights >= 3) ? bw[2] : 0.0f;
		}
		else if (bw_type == D3DDECLTYPE_UBYTE4N)
		{
			auto* bw = &src[bw_off];
			out[3] = bw[0] / 255.0f;
			out[4] = bw[1] / 255.0f;
			out[5] = bw[2] / 255.0f;
		}
		else
		{
			out[3] = out[4] = out[5] = 0.0f;
		}

		// Blend indices (UBYTE4 at offset 24)
		std::memcpy(&dst[24], &src[ffp.cur_decl_blend_indices_off()], 4);

		// Normal (FLOAT3 at offset 28)
		if (ffp.cur_decl_has_normal())
		{
			decode_normal(&src[ffp.cur_decl_normal_off()], ffp.cur_decl_normal_type(), &out[7]);
		}
		else
		{
			out[7] = 0.0f; out[8] = 1.0f; out[9] = 0.0f;
		}

		// Texcoord (FLOAT2 at offset 40)
		if (ffp.cur_decl_has_texcoord())
		{
			int tc_type = ffp.cur_decl_texcoord_type();
			int tc_off = ffp.cur_decl_texcoord_off();
			if (tc_type == D3DDECLTYPE_FLOAT2 || tc_type == D3DDECLTYPE_FLOAT3 || tc_type == D3DDECLTYPE_FLOAT4)
			{
				auto* tc = reinterpret_cast<const float*>(&src[tc_off]);
				out[10] = tc[0]; out[11] = tc[1];
			}
			else if (tc_type == D3DDECLTYPE_FLOAT16_2)
			{
				auto* h = reinterpret_cast<const unsigned short*>(&src[tc_off]);
				out[10] = half_to_float(h[0]);
				out[11] = half_to_float(h[1]);
			}
			else
			{
				out[10] = out[11] = 0.0f;
			}
		}
		else
		{
			out[10] = out[11] = 0.0f;
		}
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
		case D3DDECLTYPE_FLOAT16_2:
		{
			auto* h = reinterpret_cast<const unsigned short*>(src);
			out[0] = half_to_float(h[0]);
			out[1] = half_to_float(h[1]);
			out[2] = 0.0f; // reconstruct Z if needed
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
		default:
			out[0] = 0.0f; out[1] = 1.0f; out[2] = 0.0f;
			break;
		}
	}
}
