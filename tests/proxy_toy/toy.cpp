// A Direct3D 9 program that draws a fixed scene through vertex shaders and saves the last frame.
//
// It stands in for a game when checking a d3d9.dll proxy: run it once against the system
// d3d9.dll and once with the proxy beside it, then compare the two pictures. Every shape is
// drawn red by the pixel shader, and a green texture is bound that only a fixed-function draw
// samples, so the colour of a shape says which pipeline drew it.
//
// The scene is a 3x3 grid of cells with one shape per cell (see draw_scene).
//
// toy.exe --out FILE [--view N] [--proj N] [--world N] [--bones N] [--albedo-stage N]
//   --view, --proj, --world   first constant register of each 4x4 matrix
//   --bones                   first register of the bone palette (3 registers per bone)
//   --albedo-stage            texture stage that holds the green texture; when it is not 0,
//                             stage 0 holds a blue one
// Other arguments are ignored: the proxy reads its own from the same command line.
//
// FILE receives the width and height as two little-endian uint32 values, then the BGRX rows.

#include <windows.h>
#include <d3d9.h>
#include <d3dcompiler.h>
#include <DirectXMath.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace DirectX;

namespace
{
	constexpr int FRAME_SIZE = 256;
	constexpr int REGISTERS_PER_BONE = 3;
	constexpr int BONES_PER_STRIP = 3;

	// One strip uses the last three bones of a palette this large.
	constexpr int LARGE_PALETTE = 60;

	// A proxy loads its modules on another thread once it finds the window. The saved frame
	// comes after about a second of drawing, by when they are in place.
	constexpr int FRAMES = 90;
	constexpr DWORD FRAME_PAUSE_MS = 10;

	// The proxy template waits for a window whose class name contains this placeholder.
	constexpr char WINDOW_CLASS[] = "YOUR_WINDOW_CLASS_NAME";

	struct options
	{
		std::string out;
		int view = 0;
		int proj = 4;
		int world = 16;
		int bones = 20;
		int albedo_stage = 0;
	};

	[[noreturn]] void fail(const char* what, HRESULT hr = E_FAIL)
	{
		std::fprintf(stderr, "toy: %s failed (0x%08lX)\n", what, static_cast<unsigned long>(hr));
		std::exit(2);
	}

	void check(HRESULT hr, const char* what)
	{
		if (FAILED(hr)) fail(what, hr);
	}

	options parse_options(int argc, char** argv)
	{
		options opt;
		for (int i = 1; i < argc; i++)
		{
			const std::string arg = argv[i];
			const auto value = [&]() -> const char* { return i + 1 < argc ? argv[++i] : "0"; };

			if (arg == "--out") opt.out = value();
			else if (arg == "--view") opt.view = std::atoi(value());
			else if (arg == "--proj") opt.proj = std::atoi(value());
			else if (arg == "--world") opt.world = std::atoi(value());
			else if (arg == "--bones") opt.bones = std::atoi(value());
			else if (arg == "--albedo-stage") opt.albedo_stage = std::atoi(value());
		}
		if (opt.out.empty()) fail("reading --out");
		return opt;
	}

	// ---- vertex layouts ----
	// The skinned layouts order their elements differently from one another, so a proxy that
	// rebuilds skinned vertices has to follow the declaration.

	struct rigid_vertex { float pos[3]; float normal[3]; float uv[2]; };
	struct flat_vertex { float pos[3]; float uv[2]; };
	struct skin3_vertex { float pos[3]; float normal[3]; float uv[2]; BYTE indices[4]; float weights[3]; };
	struct skin4_vertex { float pos[3]; float weights[4]; BYTE indices[4]; float normal[3]; float uv[2]; };

	const D3DVERTEXELEMENT9 RIGID_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		D3DDECL_END()
	};
	const D3DVERTEXELEMENT9 FLAT_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		D3DDECL_END()
	};
	const D3DVERTEXELEMENT9 SKIN3_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		{ 0, 32, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		{ 0, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
		D3DDECL_END()
	};
	const D3DVERTEXELEMENT9 SKIN4_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
		{ 0, 28, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		{ 0, 32, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 44, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		D3DDECL_END()
	};

	// ---- geometry ----

	constexpr float QUAD = 0.4f;
	const rigid_vertex RIGID_VERTICES[] = {
		// quad, vertices 0-3
		{ { -QUAD, -QUAD, 0 }, { 0, 0, -1 }, { 0, 1 } },
		{ { -QUAD,  QUAD, 0 }, { 0, 0, -1 }, { 0, 0 } },
		{ {  QUAD, -QUAD, 0 }, { 0, 0, -1 }, { 1, 1 } },
		{ {  QUAD,  QUAD, 0 }, { 0, 0, -1 }, { 1, 0 } },
		// triangle, vertices 4-6
		{ { -0.5f, -0.4f, 0 }, { 0, 0, -1 }, { 0, 1 } },
		{ {  0.0f,  0.5f, 0 }, { 0, 0, -1 }, { 0.5f, 0 } },
		{ {  0.5f, -0.4f, 0 }, { 0, 0, -1 }, { 1, 1 } },
	};
	const flat_vertex FLAT_VERTICES[] = {
		{ { -QUAD, -QUAD, 0 }, { 0, 1 } },
		{ { -QUAD,  QUAD, 0 }, { 0, 0 } },
		{ {  QUAD, -QUAD, 0 }, { 1, 1 } },
		{ {  QUAD,  QUAD, 0 }, { 1, 0 } },
	};

	// A strip of two quads: three rows of two vertices. The bottom row follows bone 0, the
	// middle row is shared between bones 0 and 1, and the top row mostly follows the bone its
	// fourth index names, through the weight the first three leave over.
	struct strip_point { float x, y; float weights[3]; BYTE indices[4]; };
	const strip_point STRIP[] = {
		{ -0.25f, -0.4f, { 1.0f, 0.0f, 0.0f }, { 0, 1, 2, 0 } },
		{  0.25f, -0.4f, { 1.0f, 0.0f, 0.0f }, { 0, 1, 2, 0 } },
		{ -0.25f,  0.0f, { 0.5f, 0.5f, 0.0f }, { 0, 1, 2, 0 } },
		{  0.25f,  0.0f, { 0.5f, 0.5f, 0.0f }, { 0, 1, 2, 0 } },
		{ -0.25f,  0.4f, { 0.0f, 0.2f, 0.0f }, { 0, 1, 0, 2 } },
		{  0.25f,  0.4f, { 0.0f, 0.2f, 0.0f }, { 0, 1, 0, 2 } },
	};
	constexpr UINT STRIP_VERTICES = 6;
	constexpr UINT STRIP_TRIANGLES = 4;

	// The offset strip sits behind vertices no draw should read. Reaching it takes the stream
	// offset, the base vertex index and the minimum index together.
	constexpr UINT OFFSET_STREAM_VERTICES = 2;
	constexpr INT OFFSET_BASE_VERTEX = 3;
	constexpr UINT OFFSET_MIN_INDEX = 5;
	constexpr UINT OFFSET_FILLER = OFFSET_STREAM_VERTICES + OFFSET_BASE_VERTEX + OFFSET_MIN_INDEX;

	const WORD INDICES[] = {
		// quad, from index 0
		0, 1, 2, 2, 1, 3,
		// strip, from index 6
		0, 1, 2, 2, 1, 3, 2, 3, 4, 4, 3, 5,
		// strip whose indices start at OFFSET_MIN_INDEX, from index 18
		5, 6, 7, 7, 6, 8, 7, 8, 9, 9, 8, 10,
	};
	constexpr UINT QUAD_FIRST_INDEX = 0;
	constexpr UINT STRIP_FIRST_INDEX = 6;
	constexpr UINT OFFSET_STRIP_FIRST_INDEX = 18;

	skin3_vertex skin3_from(const strip_point& p)
	{
		skin3_vertex v = { { p.x, p.y, 0 }, { 0, 0, -1 }, { 0, 0 }, {}, {} };
		std::memcpy(v.indices, p.indices, sizeof(v.indices));
		std::memcpy(v.weights, p.weights, sizeof(v.weights));
		return v;
	}

	skin4_vertex skin4_from(const strip_point& p)
	{
		skin4_vertex v = { { p.x, p.y, 0 }, {}, {}, { 0, 0, -1 }, { 0, 0 } };
		std::memcpy(v.weights, p.weights, sizeof(p.weights));
		v.weights[3] = 1.0f - p.weights[0] - p.weights[1] - p.weights[2];
		std::memcpy(v.indices, p.indices, sizeof(v.indices));
		return v;
	}

	// ---- shaders ----

	const char SHADER_SOURCE[] = R"(
float4 view_rows[4]  : register(c%d);
float4 proj_rows[4]  : register(c%d);
float4 world_rows[4] : register(c%d);
float4 bone_rows[%d] : register(c%d);

float4 to_clip(float4 world)
{
	float4 view = float4(dot(view_rows[0], world), dot(view_rows[1], world), dot(view_rows[2], world), dot(view_rows[3], world));
	return float4(dot(proj_rows[0], view), dot(proj_rows[1], view), dot(proj_rows[2], view), dot(proj_rows[3], view));
}

float4 vs_rigid(float3 pos : POSITION) : POSITION
{
	float4 p = float4(pos, 1);
	return to_clip(float4(dot(world_rows[0], p), dot(world_rows[1], p), dot(world_rows[2], p), dot(world_rows[3], p)));
}

float3 by_bone(float4 p, float bone)
{
	float first = bone * 3;
	return float3(dot(bone_rows[first], p), dot(bone_rows[first + 1], p), dot(bone_rows[first + 2], p));
}

float4 vs_skinned(float3 pos : POSITION, float4 weights : BLENDWEIGHT, float4 indices : BLENDINDICES) : POSITION
{
	float4 p = float4(pos, 1);
	float last = 1 - weights.x - weights.y - weights.z;
	float3 world = weights.x * by_bone(p, indices.x) + weights.y * by_bone(p, indices.y)
		+ weights.z * by_bone(p, indices.z) + last * by_bone(p, indices.w);
	return to_clip(float4(world, 1));
}

float4 ps_red() : COLOR
{
	return float4(1, 0, 0, 1);
}
)";

	ID3DBlob* compile(const std::string& source, const char* entry, const char* target)
	{
		ID3DBlob* code = nullptr;
		ID3DBlob* errors = nullptr;
		const HRESULT hr = D3DCompile(source.data(), source.size(), "toy", nullptr, nullptr, entry, target, 0, 0, &code, &errors);
		if (FAILED(hr))
		{
			if (errors) std::fprintf(stderr, "%s\n", static_cast<const char*>(errors->GetBufferPointer()));
			fail(entry, hr);
		}
		if (errors) errors->Release();
		return code;
	}

	// ---- scene ----

	struct scene
	{
		options opt;
		IDirect3DDevice9* dev = nullptr;

		IDirect3DVertexShader9* vs_rigid = nullptr;
		IDirect3DVertexShader9* vs_skinned = nullptr;
		IDirect3DPixelShader9* ps_red = nullptr;

		IDirect3DVertexDeclaration9* rigid_decl = nullptr;
		IDirect3DVertexDeclaration9* flat_decl = nullptr;
		IDirect3DVertexDeclaration9* skin3_decl = nullptr;
		IDirect3DVertexDeclaration9* skin4_decl = nullptr;

		IDirect3DVertexBuffer9* rigid_vb = nullptr;
		IDirect3DVertexBuffer9* flat_vb = nullptr;
		IDirect3DVertexBuffer9* skin3_vb = nullptr;
		IDirect3DVertexBuffer9* skin3_offset_vb = nullptr;
		IDirect3DVertexBuffer9* skin3_high_vb = nullptr;
		IDirect3DVertexBuffer9* skin4_vb = nullptr;
		IDirect3DIndexBuffer9* ib = nullptr;

		IDirect3DTexture9* green = nullptr;
		IDirect3DTexture9* blue = nullptr;
	};

	// A matrix made for row vectors (v * M), stored so that register i holds column i:
	// the shader then gets component i of v * M as dot(register i, v).
	void set_matrix(const scene& s, int first_register, FXMMATRIX m)
	{
		XMFLOAT4X4 columns;
		XMStoreFloat4x4(&columns, XMMatrixTranspose(m));
		check(s.dev->SetVertexShaderConstantF(first_register, &columns.m[0][0], 4), "SetVertexShaderConstantF");
	}

	// View and Projection go up in one call when their registers are adjacent, the way an
	// engine uploads a block of transforms, and one at a time otherwise.
	void set_view_and_projection(const scene& s, FXMMATRIX view, CXMMATRIX proj)
	{
		const int first = s.opt.view < s.opt.proj ? s.opt.view : s.opt.proj;
		const int second = s.opt.view < s.opt.proj ? s.opt.proj : s.opt.view;
		if (second - first != 4)
		{
			set_matrix(s, s.opt.view, view);
			set_matrix(s, s.opt.proj, proj);
			return;
		}

		XMFLOAT4X4 block[2];
		XMStoreFloat4x4(&block[s.opt.view < s.opt.proj ? 0 : 1], XMMatrixTranspose(view));
		XMStoreFloat4x4(&block[s.opt.view < s.opt.proj ? 1 : 0], XMMatrixTranspose(proj));
		check(s.dev->SetVertexShaderConstantF(first, &block[0].m[0][0], 8), "SetVertexShaderConstantF");
	}

	// Uploads a palette whose last three bones put a strip in the cell centred on (x, y) and
	// bend it. The bones in front of them, if any, lead far out of the picture.
	void set_strip_bones(const scene& s, float x, float y, float bend_degrees, int palette_size = BONES_PER_STRIP)
	{
		std::vector<XMFLOAT4X4> bones(palette_size - BONES_PER_STRIP);
		for (auto& bone : bones)
			XMStoreFloat4x4(&bone, XMMatrixTranslation(50, 50, 0));

		const XMMATRIX strip_bones[BONES_PER_STRIP] = {
			XMMatrixTranslation(x, y, 0),
			XMMatrixRotationZ(XMConvertToRadians(bend_degrees)) * XMMatrixTranslation(x + 0.1f, y + 0.05f, 0),
			XMMatrixRotationZ(XMConvertToRadians(-bend_degrees)) * XMMatrixTranslation(x - 0.15f, y, 0),
		};
		for (const auto& bone : strip_bones)
			XMStoreFloat4x4(&bones.emplace_back(), bone);

		// Per bone, registers 0-2 hold columns 0-2 of the row-vector matrix
		std::vector<float> registers;
		for (const auto& bone : bones)
			for (int column = 0; column < REGISTERS_PER_BONE; column++)
				for (int row = 0; row < 4; row++)
					registers.push_back(bone.m[row][column]);

		check(s.dev->SetVertexShaderConstantF(s.opt.bones, registers.data(), palette_size * REGISTERS_PER_BONE), "SetVertexShaderConstantF");
	}

	void bind(const scene& s, IDirect3DVertexDeclaration9* decl, IDirect3DVertexBuffer9* vb, UINT offset, UINT stride, IDirect3DVertexShader9* vs)
	{
		check(s.dev->SetVertexDeclaration(decl), "SetVertexDeclaration");
		check(s.dev->SetStreamSource(0, vb, offset, stride), "SetStreamSource");
		check(s.dev->SetIndices(s.ib), "SetIndices");
		check(s.dev->SetVertexShader(vs), "SetVertexShader");
		check(s.dev->SetPixelShader(s.ps_red), "SetPixelShader");
	}

	// Cells, left to right and top to bottom:
	//   rigid quad, indexed            rigid triangle, not indexed     quad without a normal
	//   skinned strip                  skinned strip behind offsets    skinned strip, four weights
	//   rigid quad whose world matrix  skinned strip on the last       (empty)
	//     was set before the strips      bones of a large palette
	void draw_scene(const scene& s)
	{
		const auto dev = s.dev;
		const XMMATRIX view = XMMatrixLookAtLH(XMVectorSet(0.2f, 0.15f, -7.5f, 1), XMVectorSet(0.2f, 0.15f, 0, 1), XMVectorSet(0, 1, 0, 0));
		const XMMATRIX proj = XMMatrixPerspectiveFovLH(XMConvertToRadians(50), 1.0f, 0.5f, 50.0f);
		set_view_and_projection(s, view, proj);

		check(dev->SetTexture(s.opt.albedo_stage, s.green), "SetTexture");
		if (s.opt.albedo_stage != 0)
			check(dev->SetTexture(0, s.blue), "SetTexture");

		bind(s, s.rigid_decl, s.rigid_vb, 0, sizeof(rigid_vertex), s.vs_rigid);
		set_matrix(s, s.opt.world, XMMatrixRotationZ(XMConvertToRadians(20)) * XMMatrixTranslation(-2, 2, 0));
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");

		set_matrix(s, s.opt.world, XMMatrixTranslation(0, 2, 0));
		check(dev->DrawPrimitive(D3DPT_TRIANGLELIST, 4, 1), "DrawPrimitive");

		bind(s, s.flat_decl, s.flat_vb, 0, sizeof(flat_vertex), s.vs_rigid);
		set_matrix(s, s.opt.world, XMMatrixRotationZ(XMConvertToRadians(-15)) * XMMatrixTranslation(2, 2, 0));
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");

		// For the last quad; the strips in between do not use it.
		set_matrix(s, s.opt.world, XMMatrixRotationZ(XMConvertToRadians(45)) * XMMatrixTranslation(-2, -2, 0));

		bind(s, s.skin3_decl, s.skin3_vb, 0, sizeof(skin3_vertex), s.vs_skinned);
		set_strip_bones(s, -2, 0, 25);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, STRIP_VERTICES, STRIP_FIRST_INDEX, STRIP_TRIANGLES), "DrawIndexedPrimitive");

		bind(s, s.skin3_decl, s.skin3_offset_vb, OFFSET_STREAM_VERTICES * sizeof(skin3_vertex), sizeof(skin3_vertex), s.vs_skinned);
		set_strip_bones(s, 0, 0, -30);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, OFFSET_BASE_VERTEX, OFFSET_MIN_INDEX, STRIP_VERTICES, OFFSET_STRIP_FIRST_INDEX, STRIP_TRIANGLES), "DrawIndexedPrimitive");

		bind(s, s.skin4_decl, s.skin4_vb, 0, sizeof(skin4_vertex), s.vs_skinned);
		set_strip_bones(s, 2, 0, 40);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, STRIP_VERTICES, STRIP_FIRST_INDEX, STRIP_TRIANGLES), "DrawIndexedPrimitive");

		bind(s, s.skin3_decl, s.skin3_high_vb, 0, sizeof(skin3_vertex), s.vs_skinned);
		set_strip_bones(s, 0, -2, 35, LARGE_PALETTE);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, STRIP_VERTICES, STRIP_FIRST_INDEX, STRIP_TRIANGLES), "DrawIndexedPrimitive");

		bind(s, s.rigid_decl, s.rigid_vb, 0, sizeof(rigid_vertex), s.vs_rigid);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");
	}

	template <typename T>
	IDirect3DVertexBuffer9* make_vertex_buffer(IDirect3DDevice9* dev, const std::vector<T>& vertices)
	{
		const UINT bytes = static_cast<UINT>(vertices.size() * sizeof(T));
		IDirect3DVertexBuffer9* vb = nullptr;
		check(dev->CreateVertexBuffer(bytes, 0, 0, D3DPOOL_MANAGED, &vb, nullptr), "CreateVertexBuffer");
		void* data = nullptr;
		check(vb->Lock(0, bytes, &data, 0), "IDirect3DVertexBuffer9::Lock");
		std::memcpy(data, vertices.data(), bytes);
		vb->Unlock();
		return vb;
	}

	IDirect3DTexture9* make_texture(IDirect3DDevice9* dev, D3DCOLOR color)
	{
		IDirect3DTexture9* tex = nullptr;
		check(dev->CreateTexture(2, 2, 1, 0, D3DFMT_X8R8G8B8, D3DPOOL_MANAGED, &tex, nullptr), "CreateTexture");
		D3DLOCKED_RECT rect;
		check(tex->LockRect(0, &rect, nullptr, 0), "IDirect3DTexture9::LockRect");
		for (int y = 0; y < 2; y++)
		{
			auto* row = reinterpret_cast<D3DCOLOR*>(static_cast<BYTE*>(rect.pBits) + y * rect.Pitch);
			row[0] = row[1] = color;
		}
		tex->UnlockRect(0);
		return tex;
	}

	void create_resources(scene& s)
	{
		const auto dev = s.dev;

		char source[sizeof(SHADER_SOURCE) + 64];
		std::snprintf(source, sizeof(source), SHADER_SOURCE, s.opt.view, s.opt.proj, s.opt.world,
			LARGE_PALETTE * REGISTERS_PER_BONE, s.opt.bones);

		auto* code = compile(source, "vs_rigid", "vs_2_0");
		check(dev->CreateVertexShader(static_cast<const DWORD*>(code->GetBufferPointer()), &s.vs_rigid), "CreateVertexShader");
		code->Release();
		code = compile(source, "vs_skinned", "vs_2_0");
		check(dev->CreateVertexShader(static_cast<const DWORD*>(code->GetBufferPointer()), &s.vs_skinned), "CreateVertexShader");
		code->Release();
		code = compile(source, "ps_red", "ps_2_0");
		check(dev->CreatePixelShader(static_cast<const DWORD*>(code->GetBufferPointer()), &s.ps_red), "CreatePixelShader");
		code->Release();

		check(dev->CreateVertexDeclaration(RIGID_DECL, &s.rigid_decl), "CreateVertexDeclaration");
		check(dev->CreateVertexDeclaration(FLAT_DECL, &s.flat_decl), "CreateVertexDeclaration");
		check(dev->CreateVertexDeclaration(SKIN3_DECL, &s.skin3_decl), "CreateVertexDeclaration");
		check(dev->CreateVertexDeclaration(SKIN4_DECL, &s.skin4_decl), "CreateVertexDeclaration");

		s.rigid_vb = make_vertex_buffer(dev, std::vector<rigid_vertex>(std::begin(RIGID_VERTICES), std::end(RIGID_VERTICES)));
		s.flat_vb = make_vertex_buffer(dev, std::vector<flat_vertex>(std::begin(FLAT_VERTICES), std::end(FLAT_VERTICES)));

		std::vector<skin3_vertex> skin3;
		std::vector<skin4_vertex> skin4;
		for (const auto& p : STRIP)
		{
			skin3.push_back(skin3_from(p));
			skin4.push_back(skin4_from(p));
		}
		s.skin3_vb = make_vertex_buffer(dev, skin3);
		s.skin4_vb = make_vertex_buffer(dev, skin4);

		std::vector<skin3_vertex> skin3_high = skin3;
		for (auto& vertex : skin3_high)
			for (auto& index : vertex.indices)
				index = static_cast<BYTE>(index + LARGE_PALETTE - BONES_PER_STRIP);
		s.skin3_high_vb = make_vertex_buffer(dev, skin3_high);

		// Filler a correct draw never reads: one point far outside the cell, following bone 0.
		const strip_point filler = { 9.0f, 9.0f, { 1.0f, 0.0f, 0.0f }, { 0, 0, 0, 0 } };
		std::vector<skin3_vertex> skin3_offset(OFFSET_FILLER, skin3_from(filler));
		skin3_offset.insert(skin3_offset.end(), skin3.begin(), skin3.end());
		s.skin3_offset_vb = make_vertex_buffer(dev, skin3_offset);

		check(dev->CreateIndexBuffer(sizeof(INDICES), 0, D3DFMT_INDEX16, D3DPOOL_MANAGED, &s.ib, nullptr), "CreateIndexBuffer");
		void* data = nullptr;
		check(s.ib->Lock(0, sizeof(INDICES), &data, 0), "IDirect3DIndexBuffer9::Lock");
		std::memcpy(data, INDICES, sizeof(INDICES));
		s.ib->Unlock();

		s.green = make_texture(dev, D3DCOLOR_XRGB(0, 255, 0));
		s.blue = make_texture(dev, D3DCOLOR_XRGB(0, 0, 255));
	}

	void save_back_buffer(IDirect3DDevice9* dev, const std::string& path)
	{
		IDirect3DSurface9* back = nullptr;
		IDirect3DSurface9* copy = nullptr;
		check(dev->GetBackBuffer(0, 0, D3DBACKBUFFER_TYPE_MONO, &back), "GetBackBuffer");
		check(dev->CreateOffscreenPlainSurface(FRAME_SIZE, FRAME_SIZE, D3DFMT_X8R8G8B8, D3DPOOL_SYSTEMMEM, &copy, nullptr), "CreateOffscreenPlainSurface");
		check(dev->GetRenderTargetData(back, copy), "GetRenderTargetData");

		D3DLOCKED_RECT rect;
		check(copy->LockRect(&rect, nullptr, D3DLOCK_READONLY), "IDirect3DSurface9::LockRect");

		FILE* file = nullptr;
		if (fopen_s(&file, path.c_str(), "wb") != 0 || !file) fail("opening the output file");
		const UINT32 header[2] = { FRAME_SIZE, FRAME_SIZE };
		std::fwrite(header, sizeof(header), 1, file);
		for (int y = 0; y < FRAME_SIZE; y++)
			std::fwrite(static_cast<const BYTE*>(rect.pBits) + y * rect.Pitch, 4, FRAME_SIZE, file);
		std::fclose(file);

		copy->UnlockRect();
		copy->Release();
		back->Release();
	}

	void pump_messages()
	{
		MSG msg;
		while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessageA(&msg);
		}
	}

	// The proxy only looks at visible windows, so the window is shown, but beyond the desktop
	// and without taking the focus.
	HWND create_window()
	{
		WNDCLASSA wc = {};
		wc.lpfnWndProc = DefWindowProcA;
		wc.hInstance = GetModuleHandleA(nullptr);
		wc.lpszClassName = WINDOW_CLASS;
		if (!RegisterClassA(&wc)) fail("RegisterClass");

		const HWND hwnd = CreateWindowExA(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, WINDOW_CLASS, "proxy toy", WS_POPUP,
			0, 0, FRAME_SIZE, FRAME_SIZE, nullptr, nullptr, wc.hInstance, nullptr);
		if (!hwnd) fail("CreateWindow");

		const int beyond_desktop = GetSystemMetrics(SM_XVIRTUALSCREEN) + GetSystemMetrics(SM_CXVIRTUALSCREEN) + FRAME_SIZE;
		SetWindowPos(hwnd, nullptr, beyond_desktop, 0, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
		return hwnd;
	}
}

int main(int argc, char** argv)
{
	scene s;
	s.opt = parse_options(argc, argv);

	const HWND hwnd = create_window();

	IDirect3D9* d3d = Direct3DCreate9(D3D_SDK_VERSION);
	if (!d3d) fail("Direct3DCreate9");

	D3DPRESENT_PARAMETERS pp = {};
	pp.Windowed = TRUE;
	pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
	pp.BackBufferFormat = D3DFMT_X8R8G8B8;
	pp.BackBufferWidth = FRAME_SIZE;
	pp.BackBufferHeight = FRAME_SIZE;
	pp.hDeviceWindow = hwnd;
	pp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;

	// Software vertex processing: fixed-function indexed vertex blending then takes 256
	// matrices on every adapter, where a hardware device may offer none.
	check(d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &s.dev), "CreateDevice");

	create_resources(s);

	const auto dev = s.dev;
	dev->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
	dev->SetRenderState(D3DRS_ZENABLE, D3DZB_FALSE);

	for (int frame = 0; frame < FRAMES; frame++)
	{
		pump_messages();
		check(dev->BeginScene(), "BeginScene");
		check(dev->Clear(0, nullptr, D3DCLEAR_TARGET, D3DCOLOR_XRGB(0, 0, 64), 1.0f, 0), "Clear");
		draw_scene(s);
		check(dev->EndScene(), "EndScene");

		if (frame == FRAMES - 1)
			save_back_buffer(dev, s.opt.out);

		dev->Present(nullptr, nullptr, nullptr, nullptr);
		Sleep(FRAME_PAUSE_MS);
	}

	return 0;
}
