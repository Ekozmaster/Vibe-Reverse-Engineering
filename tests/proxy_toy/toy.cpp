// A Direct3D 9 program that draws a fixed scene through vertex shaders and saves the last frame.
//
// It stands in for a game when checking a d3d9.dll proxy: run it once against the system
// d3d9.dll and once with the proxy beside it, then compare the two pictures. Every vertex
// shader hands the pixel shader the colour to draw: red, or blue from the one shader some
// variants draw their last cell with. A green texture is bound that only a fixed-function
// draw samples, so the colour of a shape says which pipeline drew it, and with which shader.
//
// The scene is a 3x3 grid of cells with one shape per cell (see draw_scene).
//
// toy.exe --out FILE [--view N] [--proj N] [--world N] [--bones N] [--albedo-stage N] [--extra-vertices N]
//         [--variant NAME] [--d3d9ex]
//   --view, --proj, --world   first constant register of each 4x4 matrix
//   --bones                   first register of the bone palette (3 registers per bone)
//   --albedo-stage            texture stage that holds the green texture; when it is not 0,
//                             stage 0 holds a blue one
//   --extra-vertices          added to the NumVertices of every skinned draw, running it past
//                             the end of the vertex buffer. Only for a run with a proxy that
//                             converts those draws: Direct3D itself may read the whole range.
//   --variant                 how the strip in the last cell is drawn (see VARIANTS); a plain
//                             skinned strip without it
//   --d3d9ex                  create the device through Direct3DCreate9Ex, whose devices have
//                             no managed pool, and keep every resource out of that pool
// Other arguments are ignored: the proxy reads its own from the same command line.
//
// FILE receives the width and height as two little-endian uint32 values, then the BGRX rows.
// A variant that draws with two devices saves the frame of the second to FILE.second-device.

#include <windows.h>
#include <d3d9.h>
#include <d3dcompiler.h>
#include <DirectXMath.h>

#include <algorithm>
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
		UINT extra_vertices = 0;
		std::string variant;
		bool d3d9ex = false;
	};

	// Variants of the strip in the last cell. Each draws the same picture through the toy's shaders.
	//   color-indices    blend indices in a D3DCOLOR element, decoded with D3DCOLORtoUBYTE4
	//   ushort-weights   blend weights in a USHORT4N element
	//   partial-palette  after the palette, bone 0 alone is uploaded again in an upload of its own
	//   fvf-zero         SetFVF(0), which Direct3D ignores, between setting the strip's declaration
	//                    and drawing it
	//   dynamic-rewritten  the strip's buffer is D3DUSAGE_DYNAMIC and holds the strip moved aside
	//                    in every frame but the saved one. The draw names one vertex more than
	//                    the other strips' draws, so a copy a proxy keeps per buffer range
	//                    stays apart from its copies of those.
	//   writeonly        the strip's buffer is D3DUSAGE_WRITEONLY
	//   writeonly-default  the strip's buffer is D3DUSAGE_WRITEONLY in the default pool, which
	//                    Direct3D does not promise to read back
	//   short-texcoord   the strip's texture coordinate is declared SHORT4
	//   half-normal      the strip's normal is declared FLOAT16_4
	//   junk-unused-index  every vertex stores weights that add up to 1 and, as the index of
	//                    the weight left over, a bone the palette does not hold
	//   negative-base    the strip lies behind other vertices and is drawn with a negative
	//                    BaseVertexIndex, which its indices make up for
	//   state-block-stream  the strip's buffer is bound, a state block captures the device,
	//                    another buffer that holds the strip moved aside is bound, and applying
	//                    the block brings the strip's buffer back for the draw
	//   state-block-declaration  the strip's declaration is set, a state block captures the
	//                    device, a declaration that places the blend elements elsewhere in the
	//                    same vertex is set, and applying the block brings the strip's back
	//   vs-constants-out-of-range, ps-constants-out-of-range
	//                    after View and Projection are uploaded, a shader constant upload starts
	//                    at a register near UINT_MAX. Direct3D refuses the call.
	//   reset            two thirds into the run every resource is released, the device is
	//                    Reset with the parameters it was created with, and the resources are
	//                    created again
	//   second-device    two thirds into the run every resource and the device are released,
	//                    the device's last Release has to return 0, and a new device takes over
	//   overlapping-devices  two thirds into the run every resource is released and a new device
	//                    takes over while the first is still there. The first is released some
	//                    frames later and the new one at the end of the run; the last Release
	//                    of each has to return 0.
	//   normal-on-stream-1, texcoord-on-stream-1
	//                    the strip's declaration reads its normal, or its texture coordinate,
	//                    from a second vertex buffer on stream 1
	// Some variants draw a quad in place of the strip:
	//   fvf-after-skinned  the strip's declaration is set, then the quad is drawn through SetFVF.
	//                    Read with the strip's declaration, each of its vertices is a skinned
	//                    vertex that follows bone 0.
	//   up-after-converted, indexed-up-after-converted
	//                    the quad is drawn from its vertex buffer and then, with no shader set
	//                    in between, once more on top through DrawPrimitiveUP or
	//                    DrawIndexedPrimitiveUP
	//   rigid-normal-on-stream-1  the quad's declaration reads its normal from a second vertex
	//                    buffer on stream 1
	// The rest draw the quad from its vertex buffer, set the blue vertex shader, and draw the quad
	// once more on top, in blue:
	//   new-vs-after-converted, new-vs-up-after-converted
	//                    no pixel shader is set with the blue vertex shader, and the second draw
	//                    is from a vertex buffer without normals, or through DrawPrimitiveUP
	//   get-shaders-after-converted  the pixel shader is set again too, both shaders are read
	//                    back with GetVertexShader and GetPixelShader, the device's shaders are
	//                    cleared, and the ones read back are set for the second draw
	//   state-block-created-after-converted  a state block captures the device, the red vertex
	//                    shader is set, and applying the block brings the blue one back
	//   state-block-recorded-after-converted  the blue vertex shader is set between
	//                    BeginStateBlock and EndStateBlock instead, the red one after them, and
	//                    applying the recorded block sets the blue one
	//   process-vertices-after-converted  ProcessVertices runs the quad through the blue shader
	//                    into a buffer of transformed vertices, which the second draw draws
	//   rect-patch-after-converted, tri-patch-after-converted
	//                    DrawRectPatch or DrawTriPatch is called, which few devices draw, and the
	//                    second draw goes straight to the device the vertex buffer names as its
	//                    own, past any wrapper the toy was handed, without setting a shader
	// Two variants create a second device while the first is in use. The second device draws the
	// scene too in every frame from then on. At the end the first device is released, then the
	// second, and the last Release of each has to return 0:
	//   first-device-drawn-on  the second device is created two thirds into the run, between two
	//                    frames, and the first goes on drawing to the end
	//   second-device-mid-frame  the second device is created in the last frame, after the first
	//                    drew its scene. The first then repeats its last draw, the quad after the
	//                    strips, with no call in between.
	const char* const VARIANTS[] = { "color-indices", "ushort-weights", "partial-palette", "fvf-zero",
		"dynamic-rewritten", "writeonly", "writeonly-default", "short-texcoord", "half-normal",
		"junk-unused-index", "negative-base", "state-block-stream", "state-block-declaration",
		"vs-constants-out-of-range",
		"ps-constants-out-of-range", "reset", "second-device", "overlapping-devices",
		"normal-on-stream-1", "texcoord-on-stream-1", "fvf-after-skinned",
		"up-after-converted", "indexed-up-after-converted",
		"new-vs-after-converted", "new-vs-up-after-converted", "rigid-normal-on-stream-1",
		"get-shaders-after-converted", "state-block-created-after-converted", "state-block-recorded-after-converted",
		"process-vertices-after-converted", "rect-patch-after-converted", "tri-patch-after-converted",
		"first-device-drawn-on", "second-device-mid-frame",
		"read-only-trigger", "read-only-trigger-until-replacement" };

	// The variants that draw what the plain toy draws, with the trigger file of the proxy's
	// tracer made read-only before the device is created: the tracer can read it and not delete it
	const char* const READ_ONLY_TRIGGER_VARIANTS[] = { "read-only-trigger", "read-only-trigger-until-replacement" };
	const char* const TRACER_TRIGGER_FILE = "dxtrace_capture.trigger";

	// The variants that draw a quad, set the blue vertex shader and draw the quad again
	const char* const BLUE_SECOND_DRAW_VARIANTS[] = { "new-vs-after-converted", "new-vs-up-after-converted",
		"get-shaders-after-converted", "state-block-created-after-converted", "state-block-recorded-after-converted",
		"process-vertices-after-converted", "rect-patch-after-converted", "tri-patch-after-converted" };

	// The variants that release every device they created before the toy ends
	const char* const RELEASING_VARIANTS[] = { "overlapping-devices", "first-device-drawn-on", "second-device-mid-frame" };

	// The frame in which the reset, second-device and overlapping-devices variants replace
	// what they draw with
	constexpr int REPLACEMENT_FRAME = 60;

	// The frame in which the overlapping-devices variant releases its first device
	constexpr int FIRST_DEVICE_RELEASE_FRAME = 75;

	[[noreturn]] void fail(const char* what, HRESULT hr = E_FAIL)
	{
		std::fprintf(stderr, "toy: %s failed (0x%08lX)\n", what, static_cast<unsigned long>(hr));
		std::exit(2);
	}

	void check(HRESULT hr, const char* what)
	{
		if (FAILED(hr)) fail(what, hr);
	}

	[[noreturn]] void fail_with_count(const char* what, unsigned long count)
	{
		std::fprintf(stderr, "toy: %s (%lu)\n", what, count);
		std::exit(2);
	}

	template <size_t N>
	bool is_one_of(const std::string& variant, const char* const (&names)[N])
	{
		return std::find(std::begin(names), std::end(names), variant) != std::end(names);
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
			else if (arg == "--extra-vertices") opt.extra_vertices = static_cast<UINT>(std::atoi(value()));
			else if (arg == "--variant") opt.variant = value();
			else if (arg == "--d3d9ex") opt.d3d9ex = true;
		}
		if (opt.out.empty()) fail("reading --out");
		if (!opt.variant.empty() && !is_one_of(opt.variant, VARIANTS))
			fail("reading --variant");
		return opt;
	}

	// ---- vertex layouts ----
	// The skinned layouts order their elements differently from one another, so a proxy that
	// rebuilds skinned vertices has to follow the declaration.

	struct rigid_vertex { float pos[3]; float normal[3]; float uv[2]; };
	struct flat_vertex { float pos[3]; float uv[2]; };
	struct skin3_vertex { float pos[3]; float normal[3]; float uv[2]; BYTE indices[4]; float weights[3]; };
	struct skin4_vertex { float pos[3]; float weights[4]; BYTE indices[4]; float normal[3]; float uv[2]; };
	struct skin_ushort_vertex { float pos[3]; float normal[3]; float uv[2]; BYTE indices[4]; USHORT weights[4]; };

	// What stream 1 holds per vertex: a normal, whose first two floats also pass for a texture coordinate
	struct second_stream_vertex { float normal[3]; };

	// As wide as skin3_vertex. Its second and third texture coordinates lie where skin3_vertex
	// keeps its blend indices and weights.
	struct fvf_vertex { float pos[3]; float normal[3]; float uv[3][2]; };
	constexpr DWORD FVF_VERTEX_FORMAT = D3DFVF_XYZ | D3DFVF_NORMAL | D3DFVF_TEX3;
	static_assert(sizeof(fvf_vertex) == sizeof(skin3_vertex), "the FVF quad has to pass for skinned vertices");

	// What ProcessVertices writes: a position on the screen and the colour the vertex shader gave
	struct processed_vertex { float pos[4]; D3DCOLOR colour; };
	constexpr DWORD PROCESSED_VERTEX_FORMAT = D3DFVF_XYZRHW | D3DFVF_DIFFUSE;

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
	const D3DVERTEXELEMENT9 SKIN3_COLOR_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3,   D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT3,   D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 24, D3DDECLTYPE_FLOAT2,   D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		{ 0, 32, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		{ 0, 36, D3DDECLTYPE_FLOAT3,   D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
		D3DDECL_END()
	};
	// As wide as SKIN3_DECL, with the weights where that keeps its indices and the indices
	// in the last four bytes of its weights
	const D3DVERTEXELEMENT9 SKIN3_MOVED_BLEND_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		{ 0, 32, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
		{ 0, 44, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		D3DDECL_END()
	};
	const D3DVERTEXELEMENT9 SKIN3_SHORT_TEXCOORD_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 24, D3DDECLTYPE_SHORT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		{ 0, 32, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		{ 0, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
		D3DDECL_END()
	};
	const D3DVERTEXELEMENT9 SKIN3_HALF_NORMAL_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3,    D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 24, D3DDECLTYPE_FLOAT2,    D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		{ 0, 32, D3DDECLTYPE_UBYTE4,    D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		{ 0, 36, D3DDECLTYPE_FLOAT3,    D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
		D3DDECL_END()
	};
	const D3DVERTEXELEMENT9 SKIN3_NORMAL_ON_STREAM_1_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		{ 0, 32, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		{ 0, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
		{ 1,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		D3DDECL_END()
	};
	const D3DVERTEXELEMENT9 SKIN3_TEXCOORD_ON_STREAM_1_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 32, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		{ 0, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
		{ 1,  0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		D3DDECL_END()
	};
	// FLAT_DECL with a normal from stream 1
	const D3DVERTEXELEMENT9 RIGID_NORMAL_ON_STREAM_1_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		{ 1,  0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		D3DDECL_END()
	};
	const D3DVERTEXELEMENT9 SKIN_USHORT_DECL[] = {
		{ 0,  0, D3DDECLTYPE_FLOAT3,   D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
		{ 0, 12, D3DDECLTYPE_FLOAT3,   D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 },
		{ 0, 24, D3DDECLTYPE_FLOAT2,   D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
		{ 0, 32, D3DDECLTYPE_UBYTE4,   D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0 },
		{ 0, 36, D3DDECLTYPE_USHORT4N, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDWEIGHT, 0 },
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

	// Bytes 32-35 are zero, four blend indices of 0, and the three floats behind them are the weights 1, 0, 0
	const fvf_vertex FVF_VERTICES[] = {
		{ { -QUAD, -QUAD, 0 }, { 0, 0, -1 }, { { 0, 1 }, { 0, 1 }, { 0, 0 } } },
		{ { -QUAD,  QUAD, 0 }, { 0, 0, -1 }, { { 0, 0 }, { 0, 1 }, { 0, 0 } } },
		{ {  QUAD, -QUAD, 0 }, { 0, 0, -1 }, { { 1, 1 }, { 0, 1 }, { 0, 0 } } },
		{ {  QUAD,  QUAD, 0 }, { 0, 0, -1 }, { { 1, 0 }, { 0, 1 }, { 0, 0 } } },
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

	// The strip with weights that add up to exactly 1 in every vertex, so the weight left for
	// the fourth index is 0. That index names a bone inside the shader's array and outside
	// the three bones uploaded for the strip.
	constexpr BYTE UNUSED_BONE = 50;
	const strip_point FULLY_WEIGHTED_STRIP[] = {
		{ -0.25f, -0.4f, { 1.0f, 0.0f,  0.0f  }, { 0, 1, 2, UNUSED_BONE } },
		{  0.25f, -0.4f, { 1.0f, 0.0f,  0.0f  }, { 0, 1, 2, UNUSED_BONE } },
		{ -0.25f,  0.0f, { 0.5f, 0.5f,  0.0f  }, { 0, 1, 2, UNUSED_BONE } },
		{  0.25f,  0.0f, { 0.5f, 0.5f,  0.0f  }, { 0, 1, 2, UNUSED_BONE } },
		{ -0.25f,  0.4f, { 0.0f, 0.25f, 0.75f }, { 0, 1, 2, UNUSED_BONE } },
		{  0.25f,  0.4f, { 0.0f, 0.25f, 0.75f }, { 0, 1, 2, UNUSED_BONE } },
	};
	constexpr UINT STRIP_TRIANGLES = 4;

	// The offset strip sits behind vertices no draw should read. Reaching it takes the stream
	// offset, the base vertex index and the minimum index together.
	constexpr UINT OFFSET_STREAM_VERTICES = 2;
	constexpr INT OFFSET_BASE_VERTEX = 3;
	constexpr UINT OFFSET_MIN_INDEX = 5;
	constexpr UINT OFFSET_FILLER = OFFSET_STREAM_VERTICES + OFFSET_BASE_VERTEX + OFFSET_MIN_INDEX;

	// The same strip reached with a base vertex index below zero
	constexpr INT NEGATIVE_BASE_VERTEX = -3;
	constexpr UINT NEGATIVE_BASE_MIN_INDEX = 11;
	static_assert(static_cast<INT>(OFFSET_STREAM_VERTICES + NEGATIVE_BASE_MIN_INDEX) + NEGATIVE_BASE_VERTEX == static_cast<INT>(OFFSET_FILLER),
		"the negative base has to lead to the strip");

	const WORD INDICES[] = {
		// quad, from index 0
		0, 1, 2, 2, 1, 3,
		// strip, from index 6
		0, 1, 2, 2, 1, 3, 2, 3, 4, 4, 3, 5,
		// strip whose indices start at OFFSET_MIN_INDEX, from index 18
		5, 6, 7, 7, 6, 8, 7, 8, 9, 9, 8, 10,
		// strip whose indices start at NEGATIVE_BASE_MIN_INDEX, from index 30
		11, 12, 13, 13, 12, 14, 13, 14, 15, 15, 14, 16,
	};
	constexpr UINT QUAD_FIRST_INDEX = 0;
	constexpr UINT STRIP_FIRST_INDEX = 6;
	constexpr UINT OFFSET_STRIP_FIRST_INDEX = 18;
	constexpr UINT NEGATIVE_BASE_STRIP_FIRST_INDEX = 30;

	skin3_vertex skin3_from(const strip_point& p)
	{
		skin3_vertex v = { { p.x, p.y, 0 }, { 0, 0, -1 }, { 0, 0 }, {}, {} };
		std::memcpy(v.indices, p.indices, sizeof(v.indices));
		std::memcpy(v.weights, p.weights, sizeof(v.weights));
		return v;
	}

	// The strip's weights are multiples of 1/5, which USHORT4N holds exactly
	skin_ushort_vertex skin_ushort_from(const strip_point& p)
	{
		skin_ushort_vertex v = { { p.x, p.y, 0 }, { 0, 0, -1 }, { 0, 0 }, {}, {} };
		std::memcpy(v.indices, p.indices, sizeof(v.indices));
		for (int i = 0; i < 3; i++)
			v.weights[i] = static_cast<USHORT>(p.weights[i] * 65535.0f + 0.5f);
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

struct coloured
{
	float4 pos : POSITION;
	float4 colour : COLOR0;
};

coloured in_colour(float4 pos, float4 colour)
{
	coloured vertex;
	vertex.pos = pos;
	vertex.colour = colour;
	return vertex;
}

float4 rigid_to_clip(float3 pos)
{
	float4 p = float4(pos, 1);
	return to_clip(float4(dot(world_rows[0], p), dot(world_rows[1], p), dot(world_rows[2], p), dot(world_rows[3], p)));
}

coloured vs_rigid(float3 pos : POSITION)
{
	return in_colour(rigid_to_clip(pos), float4(1, 0, 0, 1));
}

coloured vs_rigid_blue(float3 pos : POSITION)
{
	return in_colour(rigid_to_clip(pos), float4(0, 0, 1, 1));
}

float3 by_bone(float4 p, float bone)
{
	float first = bone * 3;
	return float3(dot(bone_rows[first], p), dot(bone_rows[first + 1], p), dot(bone_rows[first + 2], p));
}

coloured vs_skinned(float3 pos : POSITION, float4 weights : BLENDWEIGHT, float4 indices : BLENDINDICES)
{
	float4 p = float4(pos, 1);
	float last = 1 - weights.x - weights.y - weights.z;
	float3 world = weights.x * by_bone(p, indices.x) + weights.y * by_bone(p, indices.y)
		+ weights.z * by_bone(p, indices.z) + last * by_bone(p, indices.w);
	return in_colour(to_clip(float4(world, 1)), float4(1, 0, 0, 1));
}

coloured vs_skinned_color(float3 pos : POSITION, float4 weights : BLENDWEIGHT, float4 indices : BLENDINDICES)
{
	return vs_skinned(pos, weights, D3DCOLORtoUBYTE4(indices));
}

float4 ps_vertex_colour(float4 colour : COLOR0) : COLOR
{
	return colour;
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
		IDirect3DVertexShader9* vs_rigid_blue = nullptr;
		IDirect3DVertexShader9* vs_skinned = nullptr;
		IDirect3DVertexShader9* vs_skinned_color = nullptr;
		IDirect3DPixelShader9* ps_vertex_colour = nullptr;

		IDirect3DVertexDeclaration9* rigid_decl = nullptr;
		IDirect3DVertexDeclaration9* flat_decl = nullptr;
		IDirect3DVertexDeclaration9* skin3_decl = nullptr;
		IDirect3DVertexDeclaration9* skin4_decl = nullptr;
		IDirect3DVertexDeclaration9* variant_decl = nullptr;
		IDirect3DVertexDeclaration9* moved_blend_decl = nullptr;
		IDirect3DVertexDeclaration9* rigid_normal_on_stream_1_decl = nullptr;

		IDirect3DVertexBuffer9* rigid_vb = nullptr;
		IDirect3DVertexBuffer9* flat_vb = nullptr;
		IDirect3DVertexBuffer9* skin3_vb = nullptr;
		IDirect3DVertexBuffer9* skin3_offset_vb = nullptr;
		IDirect3DVertexBuffer9* skin3_high_vb = nullptr;
		IDirect3DVertexBuffer9* skin4_vb = nullptr;
		IDirect3DVertexBuffer9* variant_vb = nullptr;
		IDirect3DVertexBuffer9* aside_vb = nullptr;
		IDirect3DVertexBuffer9* fvf_vb = nullptr;
		IDirect3DVertexBuffer9* second_stream_vb = nullptr;
		IDirect3DVertexBuffer9* processed_vb = nullptr;
		UINT variant_stride = 0;
		UINT variant_vertices = STRIP_VERTICES;
		UINT variant_stream_offset = 0;
		INT variant_base_vertex = 0;
		UINT variant_min_index = 0;
		UINT variant_first_index = STRIP_FIRST_INDEX;
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
	// bend it. The bones in front of them, if any, lead far out of the picture. Returns the
	// registers uploaded.
	std::vector<float> set_strip_bones(const scene& s, float x, float y, float bend_degrees, int palette_size = BONES_PER_STRIP)
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
		return registers;
	}

	void bind(const scene& s, IDirect3DVertexDeclaration9* decl, IDirect3DVertexBuffer9* vb, UINT offset, UINT stride, IDirect3DVertexShader9* vs)
	{
		check(s.dev->SetVertexDeclaration(decl), "SetVertexDeclaration");
		check(s.dev->SetStreamSource(0, vb, offset, stride), "SetStreamSource");
		check(s.dev->SetIndices(s.ib), "SetIndices");
		check(s.dev->SetVertexShader(vs), "SetVertexShader");
		check(s.dev->SetPixelShader(s.ps_vertex_colour), "SetPixelShader");
	}

	void draw_flat_quad(const scene& s, IDirect3DDevice9* dev)
	{
		check(dev->SetVertexDeclaration(s.flat_decl), "SetVertexDeclaration");
		check(dev->SetStreamSource(0, s.flat_vb, 0, sizeof(flat_vertex)), "SetStreamSource");
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");
	}

	// The second draw of a BLUE_SECOND_DRAW_VARIANTS variant, and what the variant does ahead of
	// it. The quad was drawn from its vertex buffer just before, and no shader was set since.
	void draw_quad_again_in_blue(const scene& s)
	{
		const auto dev = s.dev;
		const std::string& variant = s.opt.variant;

		if (variant == "state-block-recorded-after-converted")
			check(dev->BeginStateBlock(), "BeginStateBlock");
		check(dev->SetVertexShader(s.vs_rigid_blue), "SetVertexShader");
		if (variant != "new-vs-after-converted" && variant != "new-vs-up-after-converted")
			check(dev->SetPixelShader(s.ps_vertex_colour), "SetPixelShader");

		if (variant == "new-vs-up-after-converted")
		{
			check(dev->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, RIGID_VERTICES, sizeof(rigid_vertex)), "DrawPrimitiveUP");
		}
		else if (variant == "new-vs-after-converted")
		{
			draw_flat_quad(s, dev);
		}
		else if (variant == "get-shaders-after-converted")
		{
			IDirect3DVertexShader9* vs = nullptr;
			IDirect3DPixelShader9* ps = nullptr;
			check(dev->GetVertexShader(&vs), "GetVertexShader");
			check(dev->GetPixelShader(&ps), "GetPixelShader");
			check(dev->SetVertexShader(nullptr), "SetVertexShader");
			check(dev->SetPixelShader(nullptr), "SetPixelShader");
			check(dev->SetVertexShader(vs), "SetVertexShader");
			check(dev->SetPixelShader(ps), "SetPixelShader");
			if (vs) vs->Release();
			if (ps) ps->Release();
			draw_flat_quad(s, dev);
		}
		else if (variant == "state-block-created-after-converted" || variant == "state-block-recorded-after-converted")
		{
			IDirect3DStateBlock9* blue_bound = nullptr;
			if (variant == "state-block-created-after-converted")
				check(dev->CreateStateBlock(D3DSBT_ALL, &blue_bound), "CreateStateBlock");
			else
				check(dev->EndStateBlock(&blue_bound), "EndStateBlock");
			check(dev->SetVertexShader(s.vs_rigid), "SetVertexShader");
			check(blue_bound->Apply(), "IDirect3DStateBlock9::Apply");
			blue_bound->Release();
			draw_flat_quad(s, dev);
		}
		else if (variant == "process-vertices-after-converted")
		{
			check(dev->ProcessVertices(0, 0, 4, s.processed_vb, nullptr, 0), "ProcessVertices");
			check(dev->SetFVF(PROCESSED_VERTEX_FORMAT), "SetFVF");
			check(dev->SetStreamSource(0, s.processed_vb, 0, sizeof(processed_vertex)), "SetStreamSource");
			check(dev->DrawPrimitive(D3DPT_TRIANGLESTRIP, 0, 2), "DrawPrimitive");
		}
		else
		{
			// A device that does not draw patches refuses the call, so its result is not checked
			const float segments[4] = { 1, 1, 1, 1 };
			if (variant == "rect-patch-after-converted")
			{
				const D3DRECTPATCH_INFO quad = { 0, 0, 2, 2, 2, D3DBASIS_BEZIER, D3DDEGREE_LINEAR };
				dev->DrawRectPatch(0, segments, &quad);
			}
			else
			{
				const D3DTRIPATCH_INFO triangle = { 0, 3, D3DBASIS_BEZIER, D3DDEGREE_LINEAR };
				dev->DrawTriPatch(0, segments, &triangle);
			}

			IDirect3DDevice9* owner = nullptr;
			check(s.flat_vb->GetDevice(&owner), "IDirect3DVertexBuffer9::GetDevice");
			draw_flat_quad(s, owner);
			owner->Release();
		}
	}

	// Cells, left to right and top to bottom:
	//   rigid quad, indexed            rigid triangle, not indexed     quad without a normal
	//   skinned strip                  skinned strip behind offsets    skinned strip, four weights
	//   rigid quad whose world matrix  skinned strip on the last       skinned strip, drawn as
	//     was set before the strips      bones of a large palette        --variant says
	void draw_scene(const scene& s)
	{
		const auto dev = s.dev;
		const UINT strip_vertices = STRIP_VERTICES + s.opt.extra_vertices;
		const XMMATRIX view = XMMatrixLookAtLH(XMVectorSet(0.2f, 0.15f, -7.5f, 1), XMVectorSet(0.2f, 0.15f, 0, 1), XMVectorSet(0, 1, 0, 0));
		const XMMATRIX proj = XMMatrixPerspectiveFovLH(XMConvertToRadians(50), 1.0f, 0.5f, 50.0f);
		set_view_and_projection(s, view, proj);

		// Direct3D refuses both uploads, so their results are not checked
		static const float zeros[32 * 4] = {};
		if (s.opt.variant == "vs-constants-out-of-range")
			dev->SetVertexShaderConstantF(0xFFFFFFF0u, zeros, 32);
		if (s.opt.variant == "ps-constants-out-of-range")
			dev->SetPixelShaderConstantF(0xFFFFFFF8u, zeros, 16);

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
		const XMMATRIX last_quad_world = XMMatrixRotationZ(XMConvertToRadians(45)) * XMMatrixTranslation(-2, -2, 0);
		set_matrix(s, s.opt.world, last_quad_world);

		bind(s, s.skin3_decl, s.skin3_vb, 0, sizeof(skin3_vertex), s.vs_skinned);
		set_strip_bones(s, -2, 0, 25);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, strip_vertices, STRIP_FIRST_INDEX, STRIP_TRIANGLES), "DrawIndexedPrimitive");

		bind(s, s.skin3_decl, s.skin3_offset_vb, OFFSET_STREAM_VERTICES * sizeof(skin3_vertex), sizeof(skin3_vertex), s.vs_skinned);
		set_strip_bones(s, 0, 0, -30);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, OFFSET_BASE_VERTEX, OFFSET_MIN_INDEX, strip_vertices, OFFSET_STRIP_FIRST_INDEX, STRIP_TRIANGLES), "DrawIndexedPrimitive");

		bind(s, s.skin4_decl, s.skin4_vb, 0, sizeof(skin4_vertex), s.vs_skinned);
		set_strip_bones(s, 2, 0, 40);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, strip_vertices, STRIP_FIRST_INDEX, STRIP_TRIANGLES), "DrawIndexedPrimitive");

		bind(s, s.skin3_decl, s.skin3_high_vb, 0, sizeof(skin3_vertex), s.vs_skinned);
		set_strip_bones(s, 0, -2, 35, LARGE_PALETTE);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, strip_vertices, STRIP_FIRST_INDEX, STRIP_TRIANGLES), "DrawIndexedPrimitive");

		const XMMATRIX variant_quad_world = XMMatrixRotationZ(XMConvertToRadians(30)) * XMMatrixTranslation(2, -2, 0);
		bind(s, s.variant_decl, s.variant_vb, s.variant_stream_offset, s.variant_stride, s.opt.variant == "color-indices" ? s.vs_skinned_color : s.vs_skinned);
		const auto variant_bones = set_strip_bones(s, 2, -2, -20);
		const bool reads_stream_1 = s.opt.variant == "normal-on-stream-1" || s.opt.variant == "texcoord-on-stream-1" ||
			s.opt.variant == "rigid-normal-on-stream-1";
		if (s.opt.variant == "partial-palette")
			check(dev->SetVertexShaderConstantF(s.opt.bones, variant_bones.data(), REGISTERS_PER_BONE), "SetVertexShaderConstantF");
		if (s.opt.variant == "fvf-zero")
			check(dev->SetFVF(0), "SetFVF");
		if (s.opt.variant == "fvf-after-skinned")
		{
			check(dev->SetFVF(FVF_VERTEX_FORMAT), "SetFVF");
			check(dev->SetStreamSource(0, s.fvf_vb, 0, sizeof(fvf_vertex)), "SetStreamSource");
			check(dev->SetVertexShader(s.vs_rigid), "SetVertexShader");
			set_matrix(s, s.opt.world, variant_quad_world);
			check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");
			set_matrix(s, s.opt.world, last_quad_world);
		}
		else if (s.opt.variant == "up-after-converted" || s.opt.variant == "indexed-up-after-converted" ||
			is_one_of(s.opt.variant, BLUE_SECOND_DRAW_VARIANTS))
		{
			bind(s, s.rigid_decl, s.rigid_vb, 0, sizeof(rigid_vertex), s.vs_rigid);
			set_matrix(s, s.opt.world, variant_quad_world);
			check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");

			if (s.opt.variant == "up-after-converted")
				check(dev->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, RIGID_VERTICES, sizeof(rigid_vertex)), "DrawPrimitiveUP");
			else if (s.opt.variant == "indexed-up-after-converted")
				check(dev->DrawIndexedPrimitiveUP(D3DPT_TRIANGLELIST, 0, 4, 2, INDICES, D3DFMT_INDEX16, RIGID_VERTICES, sizeof(rigid_vertex)), "DrawIndexedPrimitiveUP");
			else
				draw_quad_again_in_blue(s);
			set_matrix(s, s.opt.world, last_quad_world);
		}
		else if (s.opt.variant == "rigid-normal-on-stream-1")
		{
			bind(s, s.rigid_normal_on_stream_1_decl, s.flat_vb, 0, sizeof(flat_vertex), s.vs_rigid);
			check(dev->SetStreamSource(1, s.second_stream_vb, 0, sizeof(second_stream_vertex)), "SetStreamSource");
			set_matrix(s, s.opt.world, variant_quad_world);
			check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");
			set_matrix(s, s.opt.world, last_quad_world);
		}
		else
		{
			if (reads_stream_1)
				check(dev->SetStreamSource(1, s.second_stream_vb, 0, sizeof(second_stream_vertex)), "SetStreamSource");
			if (s.opt.variant == "state-block-stream" || s.opt.variant == "state-block-declaration")
			{
				IDirect3DStateBlock9* strip_bound = nullptr;
				check(dev->CreateStateBlock(D3DSBT_ALL, &strip_bound), "CreateStateBlock");
				if (s.opt.variant == "state-block-stream")
					check(dev->SetStreamSource(0, s.aside_vb, 0, s.variant_stride), "SetStreamSource");
				else
					check(dev->SetVertexDeclaration(s.moved_blend_decl), "SetVertexDeclaration");
				check(strip_bound->Apply(), "IDirect3DStateBlock9::Apply");
				strip_bound->Release();
			}
			check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, s.variant_base_vertex, s.variant_min_index,
				s.variant_vertices + s.opt.extra_vertices, s.variant_first_index, STRIP_TRIANGLES), "DrawIndexedPrimitive");
		}
		if (reads_stream_1)
			check(dev->SetStreamSource(1, nullptr, 0, 0), "SetStreamSource");

		bind(s, s.rigid_decl, s.rigid_vb, 0, sizeof(rigid_vertex), s.vs_rigid);
		check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");
	}

	// A device created through Direct3DCreate9Ex has no managed pool
	D3DPOOL buffer_pool(const scene& s)
	{
		return s.opt.d3d9ex ? D3DPOOL_DEFAULT : D3DPOOL_MANAGED;
	}

	template <typename T>
	void fill_vertex_buffer(IDirect3DVertexBuffer9* vb, const std::vector<T>& vertices, DWORD lock_flags = 0)
	{
		const UINT bytes = static_cast<UINT>(vertices.size() * sizeof(T));
		void* data = nullptr;
		check(vb->Lock(0, bytes, &data, lock_flags), "IDirect3DVertexBuffer9::Lock");
		std::memcpy(data, vertices.data(), bytes);
		vb->Unlock();
	}

	// A dynamic buffer goes to the default pool: the managed pool takes none
	template <typename T>
	IDirect3DVertexBuffer9* make_vertex_buffer(const scene& s, const std::vector<T>& vertices, DWORD usage = 0, bool default_pool = false)
	{
		const UINT bytes = static_cast<UINT>(vertices.size() * sizeof(T));
		const D3DPOOL pool = (default_pool || (usage & D3DUSAGE_DYNAMIC)) ? D3DPOOL_DEFAULT : buffer_pool(s);
		IDirect3DVertexBuffer9* vb = nullptr;
		check(s.dev->CreateVertexBuffer(bytes, usage, 0, pool, &vb, nullptr), "CreateVertexBuffer");
		fill_vertex_buffer(vb, vertices);
		return vb;
	}

	std::vector<skin3_vertex> skin3_strip()
	{
		std::vector<skin3_vertex> strip;
		for (const auto& p : STRIP)
			strip.push_back(skin3_from(p));
		return strip;
	}

	// The strip and one vertex no index names. It is in its place only in the frame that is saved.
	std::vector<skin3_vertex> dynamic_strip(bool saved_frame)
	{
		std::vector<skin3_vertex> strip = skin3_strip();
		strip.push_back(strip.back());
		for (auto& vertex : strip)
			vertex.pos[0] += saved_frame ? 0.0f : 0.3f;
		return strip;
	}

	// Filled in system memory and copied into the default pool, which every device has
	IDirect3DTexture9* make_texture(IDirect3DDevice9* dev, D3DCOLOR color)
	{
		IDirect3DTexture9* staging = nullptr;
		check(dev->CreateTexture(2, 2, 1, 0, D3DFMT_X8R8G8B8, D3DPOOL_SYSTEMMEM, &staging, nullptr), "CreateTexture");
		D3DLOCKED_RECT rect;
		check(staging->LockRect(0, &rect, nullptr, 0), "IDirect3DTexture9::LockRect");
		for (int y = 0; y < 2; y++)
		{
			auto* row = reinterpret_cast<D3DCOLOR*>(static_cast<BYTE*>(rect.pBits) + y * rect.Pitch);
			row[0] = row[1] = color;
		}
		staging->UnlockRect(0);

		IDirect3DTexture9* tex = nullptr;
		check(dev->CreateTexture(2, 2, 1, 0, D3DFMT_X8R8G8B8, D3DPOOL_DEFAULT, &tex, nullptr), "CreateTexture");
		check(dev->UpdateTexture(staging, tex), "UpdateTexture");
		staging->Release();
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
		code = compile(source, "vs_rigid_blue", "vs_2_0");
		check(dev->CreateVertexShader(static_cast<const DWORD*>(code->GetBufferPointer()), &s.vs_rigid_blue), "CreateVertexShader");
		code->Release();
		code = compile(source, "vs_skinned", "vs_2_0");
		check(dev->CreateVertexShader(static_cast<const DWORD*>(code->GetBufferPointer()), &s.vs_skinned), "CreateVertexShader");
		code->Release();
		code = compile(source, "vs_skinned_color", "vs_2_0");
		check(dev->CreateVertexShader(static_cast<const DWORD*>(code->GetBufferPointer()), &s.vs_skinned_color), "CreateVertexShader");
		code->Release();
		code = compile(source, "ps_vertex_colour", "ps_2_0");
		check(dev->CreatePixelShader(static_cast<const DWORD*>(code->GetBufferPointer()), &s.ps_vertex_colour), "CreatePixelShader");
		code->Release();

		check(dev->CreateVertexDeclaration(RIGID_DECL, &s.rigid_decl), "CreateVertexDeclaration");
		check(dev->CreateVertexDeclaration(FLAT_DECL, &s.flat_decl), "CreateVertexDeclaration");
		check(dev->CreateVertexDeclaration(SKIN3_DECL, &s.skin3_decl), "CreateVertexDeclaration");
		check(dev->CreateVertexDeclaration(SKIN4_DECL, &s.skin4_decl), "CreateVertexDeclaration");
		const D3DVERTEXELEMENT9* variant_elements = s.opt.variant == "color-indices" ? SKIN3_COLOR_DECL
			: s.opt.variant == "ushort-weights" ? SKIN_USHORT_DECL
			: s.opt.variant == "short-texcoord" ? SKIN3_SHORT_TEXCOORD_DECL
			: s.opt.variant == "half-normal" ? SKIN3_HALF_NORMAL_DECL
			: s.opt.variant == "normal-on-stream-1" ? SKIN3_NORMAL_ON_STREAM_1_DECL
			: s.opt.variant == "texcoord-on-stream-1" ? SKIN3_TEXCOORD_ON_STREAM_1_DECL : SKIN3_DECL;
		check(dev->CreateVertexDeclaration(variant_elements, &s.variant_decl), "CreateVertexDeclaration");
		check(dev->CreateVertexDeclaration(SKIN3_MOVED_BLEND_DECL, &s.moved_blend_decl), "CreateVertexDeclaration");
		check(dev->CreateVertexDeclaration(RIGID_NORMAL_ON_STREAM_1_DECL, &s.rigid_normal_on_stream_1_decl), "CreateVertexDeclaration");

		s.rigid_vb = make_vertex_buffer(s, std::vector<rigid_vertex>(std::begin(RIGID_VERTICES), std::end(RIGID_VERTICES)));
		s.flat_vb = make_vertex_buffer(s, std::vector<flat_vertex>(std::begin(FLAT_VERTICES), std::end(FLAT_VERTICES)));

		const std::vector<skin3_vertex> skin3 = skin3_strip();
		std::vector<skin4_vertex> skin4;
		for (const auto& p : STRIP)
			skin4.push_back(skin4_from(p));
		s.skin3_vb = make_vertex_buffer(s, skin3);
		s.skin4_vb = make_vertex_buffer(s, skin4);

		std::vector<skin3_vertex> skin3_high = skin3;
		for (auto& vertex : skin3_high)
			for (auto& index : vertex.indices)
				index = static_cast<BYTE>(index + LARGE_PALETTE - BONES_PER_STRIP);
		s.skin3_high_vb = make_vertex_buffer(s, skin3_high);

		// Filler a correct draw never reads: one point far outside the cell, following bone 0.
		const strip_point filler = { 9.0f, 9.0f, { 1.0f, 0.0f, 0.0f }, { 0, 0, 0, 0 } };
		std::vector<skin3_vertex> skin3_offset(OFFSET_FILLER, skin3_from(filler));
		skin3_offset.insert(skin3_offset.end(), skin3.begin(), skin3.end());
		s.skin3_offset_vb = make_vertex_buffer(s, skin3_offset);

		std::vector<skin3_vertex> aside = skin3;
		for (auto& vertex : aside)
			vertex.pos[0] += 0.3f;
		s.aside_vb = make_vertex_buffer(s, aside);

		// The D3DCOLOR variant keeps index i in byte i, as data for a shader that decodes its
		// indices with D3DCOLORtoUBYTE4 does
		if (s.opt.variant == "ushort-weights")
		{
			std::vector<skin_ushort_vertex> skin_ushort;
			for (const auto& p : STRIP)
				skin_ushort.push_back(skin_ushort_from(p));
			s.variant_vb = make_vertex_buffer(s, skin_ushort);
			s.variant_stride = sizeof(skin_ushort_vertex);
		}
		else if (s.opt.variant == "dynamic-rewritten")
		{
			const auto strip = dynamic_strip(false);
			s.variant_vb = make_vertex_buffer(s, strip, D3DUSAGE_DYNAMIC);
			s.variant_stride = sizeof(skin3_vertex);
			s.variant_vertices = static_cast<UINT>(strip.size());
		}
		else if (s.opt.variant == "junk-unused-index")
		{
			std::vector<skin3_vertex> fully_weighted;
			for (const auto& p : FULLY_WEIGHTED_STRIP)
				fully_weighted.push_back(skin3_from(p));
			s.variant_vb = make_vertex_buffer(s, fully_weighted);
			s.variant_stride = sizeof(skin3_vertex);
		}
		else if (s.opt.variant == "negative-base")
		{
			s.variant_vb = make_vertex_buffer(s, skin3_offset);
			s.variant_stride = sizeof(skin3_vertex);
			s.variant_stream_offset = OFFSET_STREAM_VERTICES * sizeof(skin3_vertex);
			s.variant_base_vertex = NEGATIVE_BASE_VERTEX;
			s.variant_min_index = NEGATIVE_BASE_MIN_INDEX;
			s.variant_first_index = NEGATIVE_BASE_STRIP_FIRST_INDEX;
		}
		else
		{
			const bool write_only = s.opt.variant == "writeonly" || s.opt.variant == "writeonly-default";
			s.variant_vb = make_vertex_buffer(s, skin3, write_only ? D3DUSAGE_WRITEONLY : 0, s.opt.variant == "writeonly-default");
			s.variant_stride = sizeof(skin3_vertex);
		}
		s.fvf_vb = make_vertex_buffer(s, std::vector<fvf_vertex>(std::begin(FVF_VERTICES), std::end(FVF_VERTICES)));
		s.second_stream_vb = make_vertex_buffer(s, std::vector<second_stream_vertex>(STRIP_VERTICES, second_stream_vertex{ { 0, 0, -1 } }));
		check(dev->CreateVertexBuffer(4 * sizeof(processed_vertex), 0, PROCESSED_VERTEX_FORMAT, D3DPOOL_SYSTEMMEM, &s.processed_vb, nullptr), "CreateVertexBuffer");

		check(dev->CreateIndexBuffer(sizeof(INDICES), 0, D3DFMT_INDEX16, buffer_pool(s), &s.ib, nullptr), "CreateIndexBuffer");
		void* data = nullptr;
		check(s.ib->Lock(0, sizeof(INDICES), &data, 0), "IDirect3DIndexBuffer9::Lock");
		std::memcpy(data, INDICES, sizeof(INDICES));
		s.ib->Unlock();

		s.green = make_texture(dev, D3DCOLOR_XRGB(0, 255, 0));
		s.blue = make_texture(dev, D3DCOLOR_XRGB(0, 0, 255));
	}

	template <typename T>
	void release(T*& object)
	{
		object->Release();
		object = nullptr;
	}

	void release_resources(scene& s)
	{
		for (DWORD stage = 0; stage < 2; stage++)
			check(s.dev->SetTexture(stage, nullptr), "SetTexture");

		release(s.vs_rigid); release(s.vs_rigid_blue); release(s.vs_skinned); release(s.vs_skinned_color); release(s.ps_vertex_colour);
		release(s.rigid_decl); release(s.flat_decl); release(s.skin3_decl); release(s.skin4_decl); release(s.variant_decl);
		release(s.moved_blend_decl); release(s.rigid_normal_on_stream_1_decl);
		release(s.rigid_vb); release(s.flat_vb); release(s.skin3_vb); release(s.skin3_offset_vb); release(s.skin3_high_vb);
		release(s.skin4_vb); release(s.variant_vb); release(s.aside_vb); release(s.fvf_vb); release(s.second_stream_vb);
		release(s.processed_vb);
		release(s.ib);
		release(s.green); release(s.blue);
	}

	// Software vertex processing: fixed-function indexed vertex blending then takes 256
	// matrices on every adapter, where a hardware device may offer none.
	void create_device(scene& s, IDirect3D9* d3d, D3DPRESENT_PARAMETERS pp)
	{
		check(d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, pp.hDeviceWindow, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &s.dev), "CreateDevice");
	}

	void release_last_reference(IDirect3DDevice9*& dev)
	{
		if (const ULONG left = dev->Release())
			fail_with_count("the device's last Release left references", left);
		dev = nullptr;
	}

	void start_drawing(scene& s)
	{
		create_resources(s);
		s.dev->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
		s.dev->SetRenderState(D3DRS_ZENABLE, D3DZB_FALSE);
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

	if (is_one_of(s.opt.variant, READ_ONLY_TRIGGER_VARIANTS) && !SetFileAttributesA(TRACER_TRIGGER_FILE, FILE_ATTRIBUTE_READONLY))
		fail("making the trigger file read-only");

	IDirect3D9* d3d = nullptr;
	if (s.opt.d3d9ex)
	{
		IDirect3D9Ex* d3d_ex = nullptr;
		check(Direct3DCreate9Ex(D3D_SDK_VERSION, &d3d_ex), "Direct3DCreate9Ex");
		d3d = d3d_ex;
	}
	else
	{
		d3d = Direct3DCreate9(D3D_SDK_VERSION);
	}
	if (!d3d) fail("Direct3DCreate9");

	D3DPRESENT_PARAMETERS pp = {};
	pp.Windowed = TRUE;
	pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
	pp.BackBufferFormat = D3DFMT_X8R8G8B8;
	pp.BackBufferWidth = FRAME_SIZE;
	pp.BackBufferHeight = FRAME_SIZE;
	pp.hDeviceWindow = hwnd;
	pp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;

	create_device(s, d3d, pp);
	start_drawing(s);

	// The device the overlapping-devices variant drew with first, until it releases it
	IDirect3DDevice9* first_device = nullptr;

	// What the first-device-drawn-on and second-device-mid-frame variants draw with their second device
	scene second;
	second.opt = s.opt;
	const auto create_second_device = [&]
	{
		create_device(second, d3d, pp);
		start_drawing(second);
	};

	for (int frame = 0; frame < FRAMES; frame++)
	{
		pump_messages();
		if (frame == REPLACEMENT_FRAME && s.opt.variant == "reset")
		{
			release_resources(s);
			D3DPRESENT_PARAMETERS same = pp;
			check(s.dev->Reset(&same), "Reset");
			start_drawing(s);
		}
		if (frame == REPLACEMENT_FRAME && s.opt.variant == "second-device")
		{
			release_resources(s);
			release_last_reference(s.dev);
			create_device(s, d3d, pp);
			start_drawing(s);
		}
		if (frame == REPLACEMENT_FRAME && s.opt.variant == "overlapping-devices")
		{
			release_resources(s);
			first_device = s.dev;
			create_device(s, d3d, pp);
			start_drawing(s);
		}
		if (frame == FIRST_DEVICE_RELEASE_FRAME && first_device)
			release_last_reference(first_device);
		if (frame == REPLACEMENT_FRAME && s.opt.variant == "first-device-drawn-on")
			create_second_device();
		if (frame == REPLACEMENT_FRAME && s.opt.variant == "read-only-trigger-until-replacement"
			&& !SetFileAttributesA(TRACER_TRIGGER_FILE, FILE_ATTRIBUTE_NORMAL))
			fail("making the trigger file writable");
		const auto dev = s.dev;
		if (s.opt.variant == "dynamic-rewritten")
			fill_vertex_buffer(s.variant_vb, dynamic_strip(frame == FRAMES - 1), D3DLOCK_DISCARD);
		check(dev->BeginScene(), "BeginScene");
		check(dev->Clear(0, nullptr, D3DCLEAR_TARGET, D3DCOLOR_XRGB(0, 0, 64), 1.0f, 0), "Clear");
		draw_scene(s);
		if (frame == FRAMES - 1 && s.opt.variant == "second-device-mid-frame")
		{
			create_second_device();
			check(dev->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, 0, 0, 4, QUAD_FIRST_INDEX, 2), "DrawIndexedPrimitive");
		}

		// One object is created in every frame, so that a call trace of any frame holds a Create call
		IDirect3DVertexDeclaration9* created = nullptr;
		check(dev->CreateVertexDeclaration(FLAT_DECL, &created), "CreateVertexDeclaration");
		created->Release();

		check(dev->EndScene(), "EndScene");

		if (frame == FRAMES - 1)
			save_back_buffer(dev, s.opt.out);

		dev->Present(nullptr, nullptr, nullptr, nullptr);

		if (second.dev)
		{
			check(second.dev->BeginScene(), "BeginScene");
			check(second.dev->Clear(0, nullptr, D3DCLEAR_TARGET, D3DCOLOR_XRGB(0, 0, 64), 1.0f, 0), "Clear");
			draw_scene(second);
			check(second.dev->EndScene(), "EndScene");
			if (frame == FRAMES - 1)
				save_back_buffer(second.dev, s.opt.out + ".second-device");
			second.dev->Present(nullptr, nullptr, nullptr, nullptr);
		}
		Sleep(FRAME_PAUSE_MS);
	}

	if (is_one_of(s.opt.variant, RELEASING_VARIANTS))
	{
		release_resources(s);
		release_last_reference(s.dev);
	}
	if (second.dev)
	{
		release_resources(second);
		release_last_reference(second.dev);
	}

	return 0;
}
