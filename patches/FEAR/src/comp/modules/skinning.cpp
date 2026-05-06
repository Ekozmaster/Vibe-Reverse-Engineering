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

		if (!skin_exp_decl_)
		{
			// Fallback: passthrough with shaders
			ffp.disengage(dev);
			return dev->DrawIndexedPrimitive(pt, base_vtx, min_vtx, num_verts, start_idx, prim_count);
		}

		// Get expanded vertex buffer from cache or create new
		auto* src_vb = ffp.stream_vb(0);
		UINT stride = ffp.stream_stride(0);
		auto* exp_vb = get_expanded_vb(dev, src_vb, base_vtx, num_verts, stride);

		if (!exp_vb)
		{
			ffp.disengage(dev);
			return dev->DrawIndexedPrimitive(pt, base_vtx, min_vtx, num_verts, start_idx, prim_count);
		}

		// Engage FFP with skinning
		ffp.engage(dev);
		upload_bones(dev);

		// Swap in expanded VB and declaration
		IDirect3DVertexDeclaration9* orig_decl = nullptr;
		dev->GetVertexDeclaration(&orig_decl);
		dev->SetVertexDeclaration(skin_exp_decl_);
		dev->SetStreamSource(0, exp_vb, 0, SKIN_VTX_SIZE);

		auto hr = dev->DrawIndexedPrimitive(pt, 0, 0, num_verts, start_idx, prim_count);

		// Restore original state
		dev->SetVertexDeclaration(orig_decl);
		if (orig_decl) orig_decl->Release();
		dev->SetStreamSource(0, src_vb, ffp.stream_offset(0), stride);

		disable_skinning(dev);
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
		for (int i = 0; i < SKIN_CACHE_SIZE; i++)
		{
			if (skin_exp_vb_[i])
			{
				skin_exp_vb_[i]->Release();
				skin_exp_vb_[i] = nullptr;
			}
			skin_exp_key_[i] = 0;
			skin_exp_nv_[i] = 0;
		}
	}

	IDirect3DVertexBuffer9* skinning::get_expanded_vb(IDirect3DDevice9* dev,
		IDirect3DVertexBuffer9* src_vb, INT base_vtx, UINT num_verts, UINT stride)
	{
		if (!src_vb || stride == 0 || num_verts == 0) return nullptr;

		// Hash: src_vb pointer + base_vtx + num_verts + stride
		unsigned int key = static_cast<unsigned int>(reinterpret_cast<uintptr_t>(src_vb));
		key ^= static_cast<unsigned int>(base_vtx) * 0x9E3779B9u;
		key ^= num_verts * 0x517CC1B7u;
		key ^= stride * 0x6C62272Eu;

		int slot = key % SKIN_CACHE_SIZE;

		// Cache hit
		if (skin_exp_vb_[slot] && skin_exp_key_[slot] == key && skin_exp_nv_[slot] == num_verts)
			return skin_exp_vb_[slot];

		// Cache miss: evict and create
		if (skin_exp_vb_[slot])
		{
			skin_exp_vb_[slot]->Release();
			skin_exp_vb_[slot] = nullptr;
		}

		// Lock source VB
		unsigned char* src_data = nullptr;
		UINT read_off = static_cast<UINT>(base_vtx) * stride;
		if (FAILED(src_vb->Lock(read_off, num_verts * stride, reinterpret_cast<void**>(&src_data), D3DLOCK_READONLY)))
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
			expand_skin_vertex(&dst_data[v * SKIN_VTX_SIZE], &src_data[v * stride], stride);

		exp_vb->Unlock();
		src_vb->Unlock();

		skin_exp_vb_[slot] = exp_vb;
		skin_exp_key_[slot] = key;
		skin_exp_nv_[slot] = num_verts;

		return exp_vb;
	}

	void skinning::expand_skin_vertex(unsigned char* dst, const unsigned char* src, UINT /*stride*/)
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

		if (bw_type == D3DDECLTYPE_FLOAT3 || bw_type == D3DDECLTYPE_FLOAT2 || bw_type == D3DDECLTYPE_FLOAT1)
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

		int bone_start = ffp.bone_start_reg();
		int num_bones = ffp.num_bones();
		if (bone_start < ffp.reg_bone_threshold() || num_bones <= 0) return;

		const float* vs_const = ffp.vs_const_data();
		int regs_per_bone = ffp.regs_per_bone();
		int max_bones = (num_bones > 48) ? 48 : num_bones;

		for (int i = 0; i < max_bones; i++)
		{
			const float* src = &vs_const[(bone_start + i * regs_per_bone) * 4];
			float bone44[16];

			if (regs_per_bone == 3)
			{
				// 4x3 packed -> 4x4 (transpose and expand)
				shared::common::ffp_state::mat4_transpose(bone44, src);
				// The 4th column of a 4x3 is implicitly [0,0,0,1]
				bone44[3] = 0.0f; bone44[7] = 0.0f; bone44[11] = 0.0f; bone44[15] = 1.0f;
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
