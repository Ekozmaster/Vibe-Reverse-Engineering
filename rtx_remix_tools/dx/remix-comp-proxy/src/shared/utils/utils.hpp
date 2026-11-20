#pragma once
#include "vector.hpp"

namespace shared::utils
{
	const char* va(const char* fmt, ...);
	
	std::string str_to_lower(std::string input);
	std::string convert_wstring(const std::wstring& wstr);

	void transpose_float3x4_to_d3dmatrix(const float3x4& src, D3DMATRIX& dest);
	void transpose_d3dmatrix(const D3DMATRIX* input, D3DMATRIX* output, std::uint32_t count);

	/// A DirectXMath matrix in the layout SetTransform takes.
	inline D3DMATRIX XM_CALLCONV to_d3dmatrix(DirectX::FXMMATRIX matrix)
	{
		static_assert(sizeof(D3DMATRIX) == sizeof(DirectX::XMFLOAT4X4));
		DirectX::XMFLOAT4X4 stored;
		DirectX::XMStoreFloat4x4(&stored, matrix);
		D3DMATRIX out;
		std::memcpy(&out, &stored, sizeof(out));
		return out;
	}

	/// Decodes an image file (PNG, JPEG, BMP, ...) into a new A8R8G8B8 texture with one mip level.
	/// @param texture	receives the texture; the caller releases it
	HRESULT create_texture_from_file(IDirect3DDevice9* device, const char* path, IDirect3DTexture9** texture);
	void transpose_float4x4(const float* row_major, float* column_major);
	bool float_equal(float a, float b, float eps = 1.e-6f);
	
	bool open_file_homepath(const std::string& sub_dir, const std::string& file_name, std::ifstream& file);

	uint32_t data_hash32(const void* data, size_t size);
	std::uint64_t string_hash64(const std::string_view& str);
	std::uint32_t string_hash32(const std::string_view& str);

	uint32_t hash32_combine(uint32_t seed, const char* str);
	uint32_t hash32_combine(uint32_t seed, int val);
	uint32_t hash32_combine(uint32_t seed, float val);

	void lookat_vertex_decl(IDirect3DDevice9* dev);
}
