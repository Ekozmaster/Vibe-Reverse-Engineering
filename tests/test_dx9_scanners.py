"""The DX scanner scripts, run on a binary whose D3D9 calls are known.

``known_calls`` assembles one function per call. Each test names the arguments
a call was given and reads the script's report for exactly those.
"""

import contextlib
import importlib
import io
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "scripts"))

from d3d9_calls import (
    DEVICE_GLOBAL, PUSH_EAX, PUSH_ECX, TEXT_VA, Code, call_method, load_config, load_device, push, push32, write_pe32,
    write_pe32_plus,
)
import dx9_calls
import find_matrix_registers
from proxy_template import ini_section_in, keys_of, keys_the_proxy_reads

# IDirect3DDevice9 vtable offsets
PRESENT, CREATE_TEXTURE, SET_TRANSFORM, SET_RENDER_STATE = 0x44, 0x5C, 0xB0, 0xE4
CREATE_RENDER_TARGET, BEGIN_SCENE = 0x70, 0xA4
CREATE_STATE_BLOCK, SET_TEXTURE, SET_TEXTURE_STAGE_STATE, SET_SAMPLER_STATE = 0xEC, 0x104, 0x10C, 0x114
DRAW_PRIMITIVE, CREATE_VERTEX_DECLARATION, SET_FVF, CREATE_VERTEX_SHADER = 0x144, 0x158, 0x164, 0x16C
SET_VS_CONSTANT_F, CREATE_PIXEL_SHADER, SET_PS_CONSTANT_F = 0x178, 0x1A8, 0x1B4
CREATE_OFFSCREEN_PLAIN_SURFACE = 0x90

# D3DRENDERSTATETYPE
D3DRS_SRCBLEND, D3DRS_CULLMODE, D3DRS_ZFUNC, D3DRS_ALPHAREF = 19, 22, 23, 24
D3DRS_VERTEXBLEND, D3DRS_INDEXEDVERTEXBLENDENABLE = 151, 167

_VS_3_0 = struct.pack("<II", 0xFFFE0300, 0x0000FFFF)
_SKINNED_DECLARATION = b"".join(struct.pack("<HHBBBB", *element) for element in [
    (0, 0, 2, 0, 0, 0),         # FLOAT3 POSITION
    (0, 12, 2, 0, 1, 0),        # FLOAT3 BLENDWEIGHT
    (0, 24, 5, 0, 2, 0),        # UBYTE4 BLENDINDICES
    (0, 28, 2, 0, 3, 0),        # FLOAT3 NORMAL
    (0, 40, 1, 0, 5, 0),        # FLOAT2 TEXCOORD
    (0xFF, 0, 17, 0, 0, 0),     # D3DDECL_END
])


@pytest.fixture(scope="module")
def known_calls(tmp_path_factory):
    """(path of the binary, Code it was built from)."""
    code = Code()
    shader_va = code.add_data("vs_bytecode", _VS_3_0)
    declaration_va = code.add_data("declaration", _SKINNED_DECLARATION)
    load_local = bytes([0x8B, 0x45, 0x68])                                   # mov eax, [ebp+0x68]
    read_field = bytes([0x8B, 0x86]) + struct.pack("<I", SET_VS_CONSTANT_F)  # mov eax, [esi+0x178]
    call_near = bytes([0xE8, 0, 0, 0, 0])
    load_render_target = bytes([0x8B, 0x42, CREATE_RENDER_TARGET])          # mov eax, [edx+0x70]
    call_eax = bytes([0xFF, 0xD0])
    device = load_device()                          # the device and its vtable, from a global

    def state(name, state_id, value):
        code.add(name, device, value, push(state_id), PUSH_ECX, call_method(SET_RENDER_STATE))

    code.add("matrix", device, push(4), PUSH_EAX, push(8), PUSH_ECX, call_method(SET_VS_CONSTANT_F))
    code.add("vec4", device, push(1), PUSH_EAX, push(4), PUSH_ECX, call_method(SET_VS_CONSTANT_F))
    code.add("palette", device, push(60), PUSH_EAX, push(20), PUSH_ECX, call_method(SET_VS_CONSTANT_F))
    code.add("field", push(16), push(32), call_near, read_field)
    state("zfunc", D3DRS_ZFUNC, push(8))
    state("srcblend", D3DRS_SRCBLEND, push(5))
    state("alpharef", D3DRS_ALPHAREF, push32(128))
    state("cull", D3DRS_CULLMODE, load_local + PUSH_EAX)
    state("vertexblend", D3DRS_VERTEXBLEND, push(3))
    state("indexed", D3DRS_INDEXEDVERTEXBLENDENABLE, push(1))
    code.add("stage_state", device, push(4), push(1), push(2), PUSH_ECX, call_method(SET_TEXTURE_STAGE_STATE))
    code.add("sampler", device, push(2), push(6), push(0), PUSH_ECX, call_method(SET_SAMPLER_STATE))
    code.add("texture", device, PUSH_EAX, push(1), PUSH_ECX, call_method(SET_TEXTURE))
    code.add("ps_constants", device, push(2), PUSH_EAX, push(10), PUSH_ECX, call_method(SET_PS_CONSTANT_F))
    code.add("fvf", device, push32(0x112), PUSH_ECX, call_method(SET_FVF))
    code.add("skinned_fvf", device, push(0x1A), PUSH_ECX, call_method(SET_FVF))
    code.add("view", device, PUSH_EAX, push(2), PUSH_ECX, call_method(SET_TRANSFORM))
    code.add("bone_matrix", device, PUSH_EAX, push32(256 + 3), PUSH_ECX, call_method(SET_TRANSFORM))
    code.add("state_block", device, PUSH_EAX, push(1), PUSH_ECX, call_method(CREATE_STATE_BLOCK))
    code.add("create_texture", device, push(0), PUSH_EAX, push(1), push(21), push(0), push(1),
             push32(128), push32(256), PUSH_ECX, call_method(CREATE_TEXTURE, short=True))
    code.add("present", device, push(0), push(0), push(0), push(0), PUSH_ECX, call_method(PRESENT, short=True))
    code.add("render_target", device, push(0), PUSH_EAX, push(0), push(0), push(0), push(21), push32(480),
             push32(640), load_render_target, PUSH_ECX, call_eax)
    code.add("vertex_shader", device, PUSH_EAX, push32(shader_va), PUSH_ECX, call_method(CREATE_VERTEX_SHADER))
    code.add("begin_scene", device, PUSH_ECX, call_method(BEGIN_SCENE))
    code.add("draw", device, push(2), push(0), push(4), PUSH_ECX, call_method(DRAW_PRIMITIVE))
    code.add("vertex_declaration", device, PUSH_EAX, push32(declaration_va), PUSH_ECX,
             call_method(CREATE_VERTEX_DECLARATION))
    path = write_pe32(tmp_path_factory.mktemp("dx") / "known_calls.exe", code.data)
    return path, code


def report(script: str, binary: Path, *options: str) -> str:
    """What *script* prints for *binary*."""
    module = importlib.import_module(script)
    with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()) as out:
        patch.setattr(sys, "argv", [script, str(binary), *options])
        module.main()
    return out.getvalue()


def lines_with(text: str, word: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if word in line]


class TestMatrixRegisters:
    @pytest.fixture(scope="class")
    @classmethod
    def text(cls, known_calls):
        return report("find_matrix_registers", known_calls[0])

    def test_four_registers_from_c8_are_a_matrix(self, text):
        assert re.search(r"^\s+c8-c11\s+1\s", text, re.MULTILINE)

    def test_one_register_at_c4_is_not_a_matrix(self, text):
        assert "c4-c7" not in text and "c1-c4" not in text

    def test_sixty_registers_from_c20_are_a_bone_palette_candidate(self, text):
        assert "c20-c79 (count=60): 1 sites" in text

    def test_field_read_at_the_method_offset_reports_no_registers(self, text):
        assert "c16-c47" not in text and "c32-" not in text

    def test_function_start_is_an_address_in_the_section_that_holds_it(self):
        # an incrementally linked image: .textbss, with nothing stored, comes before .text
        image_base = 0x400000
        sections = [
            {"name": ".textbss", "va": 0x1000, "vsz": 0x10000, "raw": 0, "rawsz": 0, "chars": 0xE00000A0},
            {"name": ".text", "va": 0x11000, "vsz": 0x200, "raw": 0x400, "rawsz": 0x200, "chars": 0x60000020},
        ]
        frame = bytes([0x55, 0x8B, 0xEC])                                   # push ebp / mov ebp, esp
        data = bytes(0x400) + bytes([0xCC]) * 0x10 + frame + bytes([0x90]) * 0x1ED

        function = find_matrix_registers.find_containing_function(data, sections, image_base, 0x411020)

        assert function == 0x411010

    def test_function_start_is_not_sought_in_front_of_the_section(self):
        # frames in .rdata and in the unmapped bytes between it and .text, both within reach of the address
        image_base = 0x400000
        sections = [
            {"name": ".rdata", "va": 0x1000, "vsz": 0x180, "raw": 0x400, "rawsz": 0x180, "chars": 0x40000040},
            {"name": ".text", "va": 0x11000, "vsz": 0x200, "raw": 0x600, "rawsz": 0x200, "chars": 0x60000020},
        ]
        frame = bytes([0x55, 0x8B, 0xEC])
        data = (bytes(0x400) + bytes(0x170) + frame + bytes(0xD) + bytes(0x40) + frame + bytes(0x3D)
                + bytes([0x90]) * 0x200)

        assert find_matrix_registers.find_containing_function(data, sections, image_base, 0x411010) is None

    def test_suggested_layout_is_an_ini_section_the_proxy_reads(self, text):
        layout = ini_section_in(text, "FFP.Registers")
        assert dict(layout["FFP.Registers"]) == {"WorldStart": "8", "WorldEnd": "12"}
        assert keys_of(layout) <= keys_the_proxy_reads()


class TestRenderStates:
    @pytest.fixture(scope="class")
    @classmethod
    def text(cls, known_calls):
        return report("find_render_states", known_calls[0], "--all")

    @pytest.mark.parametrize("state, value", [
        ("ZFUNC", "ALWAYS"), ("SRCBLEND", "SRCALPHA"), ("ALPHAREF", "128"),
        ("VERTEXBLEND", "3WEIGHTS"), ("INDEXEDVERTEXBLENDENABLE", "TRUE"),
    ])
    def test_state_is_reported_with_the_value_it_was_given(self, text, state, value):
        assert re.search(rf"^\s+{state}\s+\[\s*1 sites\]\s+values: {value}$", text, re.MULTILINE)

    def test_value_from_a_register_is_reported_as_that_register(self, text):
        assert re.search(r"^\s+CULLMODE\s+\[\s*1 sites\]\s+values: <eax>$", text, re.MULTILINE)

    def test_no_state_is_invented_from_a_value(self, text):
        assert "FILLMODE" not in text and "WRAP0" not in text

    def test_a_call_whose_state_is_a_constant_is_not_listed_as_undecoded(self, text):
        assert "not decoded" not in text


class TestPixelShaderConstants:
    def test_start_register_and_count(self, known_calls):
        text = report("find_ps_constants", known_calls[0])

        assert "StartReg=10, Count=2  (c10-c11)" in text


class TestTextureOps:
    @pytest.fixture(scope="class")
    @classmethod
    def text(cls, known_calls):
        return report("find_texture_ops", known_calls[0], "--all")

    def test_texture_stage(self, text):
        assert "Stage 1: 1 call sites" in text

    def test_stage_state(self, text):
        stage_2 = text.split("Stage 2:")[1]
        assert lines_with(stage_2, "COLOROP")[0].split() == ["COLOROP", "=", "MODULATE"]
        assert "Stage 4:" not in text

    def test_sampler_state(self, text):
        sampler_0 = text.split("Sampler 0:")[1]
        assert lines_with(sampler_0, "MINFILTER")[0].split() == ["MINFILTER", "=", "LINEAR"]
        assert "Sampler 2:" not in text


class TestSkinning:
    @pytest.fixture(scope="class")
    @classmethod
    def text(cls, known_calls):
        return report("find_skinning", known_calls[0])

    def test_bone_palette_upload(self, text):
        assert "count=60 -> 20 bones x 3 regs" in text
        assert lines_with(text, "regs_per_bone=3")[0].startswith("start_reg=20,")

    def test_vertex_blend_states(self, text):
        assert "D3DRS_VERTEXBLEND: 1 site(s), values: 3WEIGHTS" in text
        assert "D3DRS_INDEXEDVERTEXBLENDENABLE: 1 site(s), values: TRUE" in text

    def test_skinned_vertex_declaration_is_found(self, text, known_calls):
        declaration_va = known_calls[1].calls["declaration"]
        assert f"0x{declaration_va:08X}" in text

    def test_bone_matrix_transform(self, text):
        assert "SetTransform(WORLDMATRIX(n)): 1 call(s), indices 0..3 (4 bones)" in text

    def test_skinned_fvf(self, text):
        assert "0x0000001A" in text

    def test_suggested_configuration_is_an_ini_section_the_proxy_reads(self, text):
        suggestion = ini_section_in(text, "Skinning")
        assert dict(suggestion["Skinning"]) == {"Enabled": "1", "BoneThreshold": "20", "RegsPerBone": "3"}
        assert keys_of(suggestion) <= keys_the_proxy_reads()


class TestBlendStates:
    @pytest.fixture(scope="class")
    @classmethod
    def text(cls, known_calls):
        return report("find_blend_states", known_calls[0], "--all")

    def test_vertex_blend_states(self, text):
        assert "D3DRS_VERTEXBLEND: 1 site(s), values: 3WEIGHTS" in text
        assert "D3DRS_INDEXEDVERTEXBLENDENABLE: 1 site(s), values: TRUE" in text

    def test_bone_matrix_transform(self, text):
        assert "1 call(s) with WORLDMATRIX indices" in text
        assert "Index range: 0..3 (4 bone slots)" in text


class TestOtherDecoders:
    def test_fvf(self, known_calls):
        text = report("decode_fvf", known_calls[0])

        assert "FVF 0x00000112:" in text and "XYZ | NORMAL | TEX1" in text

    def test_transform_type(self, known_calls):
        text = report("find_transforms", known_calls[0], "--all")
        view_call, bone_call = (known_calls[1].calls[name] for name in ("view", "bone_matrix"))

        assert f"0x{view_call:08X}: VIEW" in text
        assert f"0x{bone_call:08X}: WORLDMATRIX(3)" in text

    def test_state_block_type(self, known_calls):
        text = report("find_stateblocks", known_calls[0])

        assert f"0x{known_calls[1].calls['state_block']:08X}: type=ALL" in text

    def test_texture_creation_through_a_short_call(self, known_calls):
        text = report("find_surface_formats", known_calls[0], "--all")
        created = lines_with(text, f"0x{known_calls[1].calls['create_texture']:08X}:")[0]

        assert "256x128" in created and "fmt=A8R8G8B8" in created and "pool=MANAGED" in created

    def test_render_target_through_a_short_method_pointer_load(self, known_calls):
        text = report("find_surface_formats", known_calls[0])

        assert "640x480 fmt=A8R8G8B8" in text

    def test_present_through_a_short_call(self, known_calls):
        text = report("find_device_calls", known_calls[0])

        assert "Present (vtable+0x044): 1 sites" in text

    def test_vs_constant_arguments_are_named(self, known_calls):
        text = report("find_vs_constants", known_calls[0])
        matrix = text.split(f"0x{known_calls[1].calls['matrix']:08X}: call [edx+0x178]")[2]

        assert matrix.splitlines()[1].split() == ["StartRegister=8", "pConstantData=<eax>", "Vector4fCount=4"]

    def test_vertex_declaration_is_decoded(self, known_calls):
        text = report("decode_vtx_decls", known_calls[0], "--scan")

        assert f"0x{known_calls[1].calls['declaration']:08X}" in text
        assert "BLENDWEIGHT" in text and "BLENDINDICES" in text

    def test_vertex_shader_bytecode_is_found(self, known_calls):
        text = report("find_shader_bytecode", known_calls[0])

        assert f"0x{known_calls[1].calls['vs_bytecode']:08X}" in text and "vs_3_0" in text


class TestControlFlowGuardedImage:
    """A script passes the Control Flow Guard check that the load configuration of its binary names."""

    _GUARD_CHECK_POINTER = 0x564790

    @pytest.fixture(scope="class")
    @classmethod
    def guarded(cls, tmp_path_factory):
        """(path of the binary, Code it was built from): one checked SetRenderState and one CreateVertexDeclaration."""
        code = Code()
        declaration_va = code.add_data("declaration", _SKINNED_DECLARATION)
        load_device_and_vtable = bytes([0xA1]) + struct.pack("<I", DEVICE_GLOBAL) + bytes([0x8B, 0x08])
        call_guard_check = bytes([0xFF, 0x15]) + struct.pack("<I", cls._GUARD_CHECK_POINTER)

        def checked_call(label, offset, *arguments):
            # mov eax, [device] / mov ecx, [eax] / pushes / mov esi, [ecx+offset] / mov ecx, esi / check / call esi
            load_method = bytes([0x8B, 0xB1]) + struct.pack("<I", offset)
            code.add(label, load_device_and_vtable, *arguments, PUSH_EAX, load_method, bytes([0x8B, 0xCE]),
                     call_guard_check, bytes([0xFF, 0xD6]))

        checked_call("zfunc", SET_RENDER_STATE, push(8), push(D3DRS_ZFUNC))
        checked_call("vertex_declaration", CREATE_VERTEX_DECLARATION, PUSH_ECX, push32(declaration_va))
        path = write_pe32(tmp_path_factory.mktemp("dx") / "guarded.exe", code.data,
                          load_config(cls._GUARD_CHECK_POINTER))
        return path, code

    def test_arguments_pushed_before_the_check_are_decoded(self, guarded):
        text = report("find_render_states", guarded[0], "--all")

        assert re.search(r"^\s+ZFUNC\s+\[\s*1 sites\]\s+values: ALWAYS$", text, re.MULTILINE)

    def test_device_calls_are_listed(self, guarded):
        assert "SetRenderState (vtable+0x0E4): 1 sites" in report("find_device_calls", guarded[0])

    def test_a_region_scan_finds_the_checked_calls(self, guarded):
        binary, code = guarded

        text = report("scan_d3d_region", binary, f"0x{TEXT_VA:X}", f"0x{TEXT_VA + len(code.data):X}")

        assert "SetRenderState (offset 0xE4): 1 refs" in text

    def test_vertex_declaration_of_a_checked_call_is_decoded(self, guarded):
        text = report("decode_vtx_decls", guarded[0], "--scan")

        assert f"0x{guarded[1].calls['declaration']:08X}" in text and "BLENDWEIGHT" in text

    def test_without_the_load_configuration_the_checked_calls_are_not_reported(self, guarded, tmp_path):
        binary = write_pe32(tmp_path / "unnamed.exe", guarded[1].data)

        assert "SetRenderState (vtable+0x0E4): 0 sites" in report("find_device_calls", binary)


@pytest.fixture(scope="module")
def unsettled_calls(tmp_path_factory):
    """(path of a binary whose calls each have an argument that is not a constant, Code it was built from)."""
    code = Code()
    device = load_device()
    call_near = bytes([0xE8, 0, 0, 0, 0])
    code.add("fvf_register", device, PUSH_EAX, PUSH_ECX, call_method(SET_FVF))
    code.add("fvf_hidden", device, push32(0x112), call_near, PUSH_ECX, call_method(SET_FVF))
    code.add("texture", device, PUSH_EAX, PUSH_EAX, PUSH_ECX, call_method(SET_TEXTURE))
    code.add("stage_state", device, push(4), PUSH_EAX, push(2), PUSH_ECX, call_method(SET_TEXTURE_STAGE_STATE))
    code.add("sampler", device, PUSH_EAX, push(6), push(0), PUSH_ECX, call_method(SET_SAMPLER_STATE))
    code.add("vertex_shader", device, PUSH_EAX, PUSH_EAX, PUSH_ECX, call_method(CREATE_VERTEX_SHADER))
    code.add("pixel_shader", device, PUSH_EAX, push32(0x6F3500), call_near, PUSH_ECX,
             call_method(CREATE_PIXEL_SHADER))
    code.add("declaration", device, PUSH_EAX, PUSH_EAX, PUSH_ECX, call_method(CREATE_VERTEX_DECLARATION))
    code.add("constants", device, push(4), PUSH_EAX, PUSH_EAX, PUSH_ECX, call_method(SET_VS_CONSTANT_F))
    code.add("state", device, push(1), PUSH_EAX, PUSH_ECX, call_method(SET_RENDER_STATE))
    code.add("vertexblend", device, PUSH_EAX, push32(D3DRS_VERTEXBLEND), PUSH_ECX, call_method(SET_RENDER_STATE))
    code.add("cull", device, PUSH_EAX, push(D3DRS_CULLMODE), PUSH_ECX, call_method(SET_RENDER_STATE))
    code.add("transform", device, PUSH_EAX, PUSH_EAX, PUSH_ECX, call_method(SET_TRANSFORM))
    code.add("surface", device, push(0), PUSH_EAX, push(3), PUSH_EAX, push32(480), push32(640), PUSH_ECX,
             call_method(CREATE_OFFSCREEN_PLAIN_SURFACE))
    path = write_pe32(tmp_path_factory.mktemp("dx") / "unsettled_calls.exe", code.data)
    return path, code


class TestCallsWhoseArgumentsAreNotConstants:
    """A call the summaries cannot use is listed with what the code shows of its arguments."""

    @pytest.mark.parametrize("script, options, label, arguments", [
        ("decode_fvf", (), "fvf_register", "FVF=<eax>"),
        ("decode_fvf", (), "fvf_hidden", "FVF=<unknown>"),
        ("decode_vtx_decls", ("--scan",), "declaration", "pVertexElements=<eax>  ppDecl=<eax>"),
        ("find_blend_states", (), "state", "State=<eax>  Value=1"),
        ("find_blend_states", (), "vertexblend", "State=151  Value=<eax>"),
        ("find_blend_states", (), "transform", "State=<eax>  pMatrix=<eax>"),
        ("find_matrix_registers", (), "constants", "StartRegister=<eax>  pConstantData=<eax>  Vector4fCount=4"),
        ("find_matrix_registers", (), "vertex_shader", "pFunction=<eax>  ppShader=<eax>"),
        ("find_render_states", (), "state", "State=<eax>  Value=1"),
        ("find_shader_bytecode", (), "vertex_shader", "pFunction=<eax>  ppShader=<eax>"),
        ("find_shader_bytecode", (), "pixel_shader", "pFunction=<unknown>  ppShader=<unknown>"),
        ("find_skinning", (), "declaration", "pVertexElements=<eax>  ppDecl=<eax>"),
        ("find_skinning", (), "fvf_register", "FVF=<eax>"),
        ("find_skinning", (), "constants", "StartRegister=<eax>  pConstantData=<eax>  Vector4fCount=4"),
        ("find_skinning", (), "vertexblend", "State=151  Value=<eax>"),
        ("find_skinning", (), "transform", "State=<eax>  pMatrix=<eax>"),
        ("find_surface_formats", (), "surface",
         "Width=640  Height=480  Format=<eax>  Pool=3  ppSurface=<eax>  pSharedHandle=0"),
        ("find_texture_ops", (), "texture", "Stage=<eax>  pTexture=<eax>"),
        ("find_texture_ops", (), "stage_state", "Stage=2  Type=<eax>  Value=4"),
        ("find_texture_ops", (), "sampler", "Sampler=0  Type=6  Value=<eax>"),
    ])
    def test_call_is_listed_with_its_arguments(self, unsettled_calls, script, options, label, arguments):
        binary, code = unsettled_calls

        text = report(script, binary, *options)

        assert f"0x{code.calls[label]:08X}: {arguments}" in text

    @pytest.mark.parametrize("script", ["find_blend_states", "find_skinning"])
    def test_render_state_that_is_not_a_blend_state_is_not_listed(self, unsettled_calls, script):
        binary, code = unsettled_calls

        assert f"0x{code.calls['cull']:08X}" not in report(script, binary)

    @pytest.mark.parametrize("script, options", [
        ("decode_fvf", ()), ("decode_vtx_decls", ("--scan",)), ("find_blend_states", ()),
        ("find_matrix_registers", ()), ("find_shader_bytecode", ()), ("find_skinning", ()),
        ("find_surface_formats", ()), ("find_texture_ops", ()),
    ])
    def test_calls_with_constant_arguments_are_not_listed(self, known_calls, script, options):
        assert "not decoded" not in report(script, known_calls[0], *options)


@pytest.fixture(scope="module")
def many_unsettled_calls(tmp_path_factory):
    """(path of a binary with 11 calls of each method whose arguments are registers, Code it was built from).

    The calls of a method are labelled with its vtable offset and their index: (SET_FVF, 10) is the last.
    """
    code = Code()
    device = load_device()
    for offset, param_count in [(SET_FVF, 1), (CREATE_VERTEX_DECLARATION, 2), (SET_RENDER_STATE, 2),
                                (SET_VS_CONSTANT_F, 3), (CREATE_VERTEX_SHADER, 2),
                                (CREATE_OFFSCREEN_PLAIN_SURFACE, 6), (SET_TEXTURE, 2)]:
        for index in range(11):
            code.add((offset, index), device, *[PUSH_EAX] * param_count, PUSH_ECX, call_method(offset))
    path = write_pe32(tmp_path_factory.mktemp("dx") / "many_unsettled_calls.exe", code.data)
    return path, code


_SCRIPTS_LISTING_UNDECODED_CALLS = [
    ("decode_fvf", (), SET_FVF), ("decode_vtx_decls", ("--scan",), CREATE_VERTEX_DECLARATION),
    ("find_blend_states", (), SET_RENDER_STATE), ("find_render_states", (), SET_RENDER_STATE),
    ("find_matrix_registers", (), SET_VS_CONSTANT_F),
    ("find_matrix_registers", (), CREATE_VERTEX_SHADER), ("find_shader_bytecode", (), CREATE_VERTEX_SHADER),
    ("find_skinning", (), SET_FVF), ("find_surface_formats", (), CREATE_OFFSCREEN_PLAIN_SURFACE),
    ("find_texture_ops", (), SET_TEXTURE),
]


class TestLongListsOfUndecodedCalls:
    @pytest.mark.parametrize("script, options, method", _SCRIPTS_LISTING_UNDECODED_CALLS)
    def test_list_stops_after_ten_calls(self, many_unsettled_calls, script, options, method):
        binary, code = many_unsettled_calls

        text = report(script, binary, *options)

        assert f"    0x{code.calls[method, 9]:08X}: " in text
        assert f"0x{code.calls[method, 10]:08X}" not in text
        assert "    ... and 1 more" in text

    @pytest.mark.parametrize("script, options, method", _SCRIPTS_LISTING_UNDECODED_CALLS)
    def test_all_lists_every_call(self, many_unsettled_calls, script, options, method):
        binary, code = many_unsettled_calls

        text = report(script, binary, *options, "--all")

        assert f"    0x{code.calls[method, 10]:08X}: " in text
        assert "    ... and 1 more" not in text

    def test_call_of_a_method_without_parameters_is_listed_by_its_address_alone(self, capsys):
        dx9_calls.print_undecoded_calls("BeginScene", [(TEXT_VA, {"this": None})], show_all=False)

        assert capsys.readouterr().out.splitlines()[-1] == f"    0x{TEXT_VA:08X}"


class TestMatrixRegisterReport:
    def test_undecoded_uploads_are_reported_once(self, unsettled_calls):
        text = report("find_matrix_registers", unsettled_calls[0])

        assert len(lines_with(text, "not decoded")) == 2      # SetVertexShaderConstantF and CreateVertexShader
        assert "register-loaded arguments" not in text


class TestRegionScan:
    @pytest.fixture(scope="class")
    @classmethod
    def text(cls, known_calls):
        binary, code = known_calls
        return report("scan_d3d_region", binary, f"0x{TEXT_VA:X}", f"0x{TEXT_VA + len(code.data):X}")

    def test_call_through_a_one_byte_displacement_is_found(self, text, known_calls):
        present = text.split("Present (offset 0x44): 1 refs")[1]

        assert present.splitlines()[1].split() == [f"0x{known_calls[1].calls['present']:08X}", "(call)"]
        assert lines_with(text.split("Key method summary")[1], "Present")[0].split() == ["Present", "1", "refs"]

    def test_method_pointer_load_through_a_one_byte_displacement_is_found(self, text):
        assert "CreateRenderTarget (offset 0x70): 1 refs" in text

    def test_field_read_at_a_method_offset_is_not_a_reference(self, text, known_calls):
        assert f"0x{known_calls[1].calls['field']:08X}" not in text
        assert "SetVertexShaderConstantF (offset 0x178): 3 refs" in text

    def test_only_the_region_is_reported(self, known_calls):
        binary, code = known_calls
        start, end = code.calls["zfunc"], code.calls["alpharef"]

        text = report("scan_d3d_region", binary, f"0x{start:X}", f"0x{end:X}")

        assert "SetRenderState (offset 0xE4): 2 refs" in text
        assert "Total: 2 vtable reference sites" in text

    def test_a_region_without_references_below_0x80_names_no_device_location(self, known_calls):
        binary, code = known_calls

        text = report("scan_d3d_region", binary, f"0x{code.calls['zfunc']:X}", f"0x{code.calls['alpharef']:X}")

        assert "Device location" not in text and "unconfirmed" not in text

    def test_region_outside_every_section_is_refused(self, known_calls):
        with pytest.raises(SystemExit):
            report("scan_d3d_region", known_calls[0], "0x900000", "0x900100")


class TestDrawClassification:
    def test_state_set_through_ebp_before_a_draw_is_seen(self, tmp_path):
        set_fvf_through_ebp = bytes([0xFF, 0x95]) + struct.pack("<I", SET_FVF)     # call [ebp+0x164]
        code = Code().add("draw", push32(0x112), PUSH_ECX, set_fvf_through_ebp,
                          push(2), push(0), push(4), PUSH_ECX, call_method(DRAW_PRIMITIVE))
        binary = write_pe32(tmp_path / "game.exe", code.data)

        text = report("classify_draws", binary, "--all")

        assert lines_with(text, f"0x{code.calls['draw']:08X}:")[-1].split()[2:] == ["[ffp", "]", "SetFVF"]

    def test_state_bytes_inside_another_instruction_are_not_state(self, tmp_path):
        # mov eax, 0x016492FF holds FF 92 64 01, the start of call [edx+0x164]
        mov_with_call_bytes = bytes([0xB8, 0xFF, 0x92, 0x64, 0x01]) + bytes([0x00, 0x00])
        code = Code().add("draw", mov_with_call_bytes, push(2), push(0), push(4), PUSH_ECX,
                          call_method(DRAW_PRIMITIVE))
        binary = write_pe32(tmp_path / "game.exe", code.data)

        text = report("classify_draws", binary, "--all")

        assert lines_with(text, f"0x{code.calls['draw']:08X}:")[-1].split()[2:] == ["[minimal]", "<none>"]

    def test_state_set_after_the_draw_or_before_the_window_is_not_its_context(self, tmp_path):
        set_fvf = (push32(0x112), PUSH_ECX, call_method(SET_FVF))
        draw = (push(2), push(0), push(4), PUSH_ECX, call_method(DRAW_PRIMITIVE))
        code = Code().add("far", *set_fvf, bytes([0x90]) * 64, *draw).add("after", *draw, *set_fvf[:-1], set_fvf[-1])
        binary = write_pe32(tmp_path / "game.exe", code.data)
        draw_after = code.calls["after"] - len(b"".join(set_fvf[:-1])) - len(draw[-1])

        text = report("classify_draws", binary, "--all", "--window", "32")

        assert lines_with(text, f"0x{code.calls['far'] :08X}:")[-1].split()[2:] == ["[minimal]", "<none>"]
        assert lines_with(text, f"0x{draw_after:08X}:")[-1].split()[2:] == ["[minimal]", "<none>"]


def _texture_creation(object_and_vtable: bytes, fmt: int) -> tuple[bytes, ...]:
    """CreateTexture(256, 128, 1, 0, fmt, MANAGED, eax, NULL) on the object *object_and_vtable* loads."""
    return (object_and_vtable, push(0), PUSH_EAX, push(1), push(fmt), push(0), push(1),
            push32(128), push32(256), PUSH_ECX, call_method(CREATE_TEXTURE))


class TestDeviceProvenanceReport:
    """Calls below vtable+0x80 count only on an object read from where the device was seen to live."""

    _OTHER_GLOBAL = 0x9D9200
    # BeginScene, EndScene, Clear, SetTransform, SetViewport, SetRenderState, SetTexture,
    # SetTextureStageState, SetSamplerState, DrawPrimitive, SetFVF, SetStreamSource
    _DEVICE_METHODS = {offset: dx9_calls.DEVICE[offset] for offset in (
        0xA4, 0xA8, 0xAC, 0xB0, 0xBC, 0xE4, 0x104, 0x10C, 0x114, 0x144, 0x164, 0x190)}

    @staticmethod
    def _binary(tmp_path, object_and_vtable: bytes) -> tuple[Path, Code]:
        """Twelve device methods from vtable+0x80 on and a CreateTexture on the object
        *object_and_vtable* loads, and a CreateTexture on an object read from another global."""
        code = Code()
        code.add_com_calls(object_and_vtable, TestDeviceProvenanceReport._DEVICE_METHODS)
        code.add("device_texture", *_texture_creation(object_and_vtable, fmt=21))
        code.add("other_texture", *_texture_creation(load_device(TestDeviceProvenanceReport._OTHER_GLOBAL), fmt=40))
        return write_pe32(tmp_path / "game.exe", code.data), code

    def test_only_the_device_objects_formats_reach_the_summary(self, tmp_path):
        binary, code = self._binary(tmp_path, load_device())

        text = report("find_surface_formats", binary, "--unconfirmed")

        assert "Device location, learned from the calls at vtable+0x80 and above: [0x009D915C]" in text
        summary = text.split("Surface Format Summary")[1]
        assert "A8R8G8B8" in summary and "A8P8" not in summary
        assert "Unconfirmed (object not shown to be the device): 1" in text
        assert f"0x{code.calls['other_texture']:08X}" in text

    def test_a_device_held_in_a_field_of_this_leaves_every_low_slot_call_unconfirmed(self, tmp_path):
        load_field_of_this = bytes([0x8B, 0x49, 0x3C, 0x8B, 0x11])          # mov ecx, [ecx+0x3C] / mov edx, [ecx]
        binary, _code = self._binary(tmp_path, load_field_of_this)

        text = report("find_surface_formats", binary)

        assert "Device location: none learned" in text
        assert "Unconfirmed (object not shown to be the device): 2" in text
        assert "No format arguments decoded" in text

    def test_region_scan_labels_the_call_on_another_object(self, tmp_path):
        binary, code = self._binary(tmp_path, load_device())

        text = report("scan_d3d_region", binary, f"0x{TEXT_VA:X}", f"0x{TEXT_VA + len(code.data):X}")

        assert "Device location, learned from the calls at vtable+0x80 and above: [0x009D915C]" in text
        assert "CreateTexture (offset 0x5C): 1 refs, 1 unconfirmed (object not shown to be the device)" in text
        assert lines_with(text, f"0x{code.calls['device_texture']:08X}") == [
            f"0x{code.calls['device_texture']:08X}  (call)"]
        assert lines_with(text, f"0x{code.calls['other_texture']:08X}") == [
            f"0x{code.calls['other_texture']:08X}  (call)  unconfirmed"]
        assert "Total: 13 vtable reference sites, 1 unconfirmed" in text
        assert lines_with(text, "SetTexture  ") == ["SetTexture                     1 refs"]

    def test_region_scan_counts_no_low_slot_call_as_a_device_reference_when_no_device_is_learned(self, tmp_path):
        load_field_of_this = bytes([0x8B, 0x49, 0x3C, 0x8B, 0x11])          # mov ecx, [ecx+0x3C] / mov edx, [ecx]
        binary, code = self._binary(tmp_path, load_field_of_this)

        text = report("scan_d3d_region", binary, f"0x{TEXT_VA:X}", f"0x{TEXT_VA + len(code.data):X}")

        assert "Device location: none learned" in text
        assert "CreateTexture (offset 0x5C): 0 refs, 2 unconfirmed (object not shown to be the device)" in text
        assert "Total: 12 vtable reference sites, 2 unconfirmed" in text
        assert "Unique methods referenced: 12" in text


class TestInputTheScannersCannotRead:
    @pytest.mark.parametrize("script", [
        "classify_draws", "decode_fvf", "find_blend_states", "find_device_calls",
        "find_matrix_registers", "find_ps_constants", "find_render_states",
        "find_shader_bytecode", "find_skinning", "find_stateblocks", "find_surface_formats",
        "find_texture_ops", "find_transforms", "find_vs_constants", "find_vtable_calls",
    ])
    def test_64_bit_binary_is_refused(self, script, tmp_path):
        binary = write_pe32_plus(tmp_path / "game64.exe", Code().data)

        with pytest.raises(SystemExit) as refusal:
            report(script, binary)

        assert "64-bit" in str(refusal.value)

    @pytest.mark.parametrize("script", [
        "classify_draws", "decode_fvf", "find_blend_states", "find_d3d_calls", "find_device_calls",
        "find_matrix_registers", "find_ps_constants", "find_render_states",
        "find_shader_bytecode", "find_skinning", "find_stateblocks", "find_surface_formats",
        "find_texture_ops", "find_transforms", "find_vs_constants", "find_vtable_calls",
    ])
    def test_a_file_that_is_not_a_pe_is_refused(self, script, tmp_path):
        text_file = tmp_path / "notes.txt"
        text_file.write_text("not a program\n")

        with pytest.raises(SystemExit) as refusal:
            report(script, text_file)

        assert "notes.txt" in str(refusal.value)


_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "scripts"


class TestRunAsAScript:
    """Each script finds its sibling modules itself, not through the directory Python was started in."""

    @pytest.mark.parametrize("script", sorted(
        path.name for path in _SCRIPTS_DIR.glob("*.py") if not path.name.startswith("dx9_")))
    def test_help_runs_from_another_directory_by_path(self, script, tmp_path):
        # runpy, unlike "python script.py", leaves the script's own directory off sys.path
        run_by_path = "import runpy, sys; path = sys.argv[1]; sys.argv = [path, '--help']; runpy.run_path(path, run_name='__main__')"
        result = subprocess.run([sys.executable, "-c", run_by_path, str(_SCRIPTS_DIR / script)],
                                cwd=tmp_path, capture_output=True, text=True, errors="replace", timeout=60)

        assert result.returncode == 0, result.stderr
