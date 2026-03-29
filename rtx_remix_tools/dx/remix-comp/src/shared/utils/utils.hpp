#pragma once
#include "vector.hpp"

namespace shared::utils
{
	const char* va(const char* fmt, ...);
	
	std::string str_to_lower(std::string input);
	std::string convert_wstring(const std::wstring& wstr);

	void transpose_float3x4_to_d3dxmatrix(const float3x4& src, D3DXMATRIX& dest);
	void transpose_d3dxmatrix(const D3DXMATRIX* input, D3DXMATRIX* output, std::uint32_t count);
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
