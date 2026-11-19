"""The DX scanner scripts, run on a binary whose D3D9 calls are known.

``known_calls`` assembles one function per call. Each test names the arguments
a call was given and reads the script's report for exactly those.
"""

import contextlib
import importlib
import io
import re
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "scripts"))

from d3d9_calls import PUSH_EAX, PUSH_ECX, Code, call_method, push, push32, write_pe32, write_pe32_plus
from proxy_template import ini_section_in, keys_of, keys_the_proxy_reads

# IDirect3DDevice9 vtable offsets
PRESENT, CREATE_TEXTURE, SET_TRANSFORM, SET_RENDER_STATE = 0x44, 0x5C, 0xB0, 0xE4
CREATE_STATE_BLOCK, SET_TEXTURE, SET_TEXTURE_STAGE_STATE, SET_SAMPLER_STATE = 0xEC, 0x104, 0x10C, 0x114
CREATE_VERTEX_DECLARATION, SET_FVF, CREATE_VERTEX_SHADER = 0x158, 0x164, 0x16C
SET_VS_CONSTANT_F, SET_PS_CONSTANT_F = 0x178, 0x1B4

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

    def state(name, state_id, value):
        code.add(name, value, push(state_id), PUSH_ECX, call_method(SET_RENDER_STATE))

    code.add("matrix", push(4), PUSH_EAX, push(8), PUSH_ECX, call_method(SET_VS_CONSTANT_F))
    code.add("vec4", push(1), PUSH_EAX, push(4), PUSH_ECX, call_method(SET_VS_CONSTANT_F))
    code.add("palette", push(60), PUSH_EAX, push(20), PUSH_ECX, call_method(SET_VS_CONSTANT_F))
    code.add("field", push(16), push(32), call_near, read_field)
    state("zfunc", D3DRS_ZFUNC, push(8))
    state("srcblend", D3DRS_SRCBLEND, push(5))
    state("alpharef", D3DRS_ALPHAREF, push32(128))
    state("cull", D3DRS_CULLMODE, load_local + PUSH_EAX)
    state("vertexblend", D3DRS_VERTEXBLEND, push(3))
    state("indexed", D3DRS_INDEXEDVERTEXBLENDENABLE, push(1))
    code.add("stage_state", push(4), push(1), push(2), PUSH_ECX, call_method(SET_TEXTURE_STAGE_STATE))
    code.add("sampler", push(2), push(6), push(0), PUSH_ECX, call_method(SET_SAMPLER_STATE))
    code.add("texture", PUSH_EAX, push(1), PUSH_ECX, call_method(SET_TEXTURE))
    code.add("ps_constants", push(2), PUSH_EAX, push(10), PUSH_ECX, call_method(SET_PS_CONSTANT_F))
    code.add("fvf", push32(0x112), PUSH_ECX, call_method(SET_FVF))
    code.add("skinned_fvf", push(0x1A), PUSH_ECX, call_method(SET_FVF))
    code.add("view", PUSH_EAX, push(2), PUSH_ECX, call_method(SET_TRANSFORM))
    code.add("bone_matrix", PUSH_EAX, push32(256 + 3), PUSH_ECX, call_method(SET_TRANSFORM))
    code.add("state_block", PUSH_EAX, push(1), PUSH_ECX, call_method(CREATE_STATE_BLOCK))
    code.add("create_texture", push(0), PUSH_EAX, push(1), push(21), push(0), push(1),
             push32(128), push32(256), PUSH_ECX, call_method(CREATE_TEXTURE, short=True))
    code.add("present", push(0), push(0), push(0), push(0), PUSH_ECX, call_method(PRESENT, short=True))
    code.add("vertex_shader", PUSH_EAX, push32(shader_va), PUSH_ECX, call_method(CREATE_VERTEX_SHADER))
    code.add("vertex_declaration", PUSH_EAX, push32(declaration_va), PUSH_ECX,
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
    def text(self, known_calls):
        return report("find_matrix_registers", known_calls[0])

    def test_four_registers_from_c8_are_a_matrix(self, text):
        assert re.search(r"^\s+c8-c11\s+1\s", text, re.MULTILINE)

    def test_one_register_at_c4_is_not_a_matrix(self, text):
        assert "c4-c7" not in text and "c1-c4" not in text

    def test_sixty_registers_from_c20_are_a_bone_palette_candidate(self, text):
        assert "c20-c79 (count=60): 1 sites" in text

    def test_field_read_at_the_method_offset_reports_no_registers(self, text):
        assert "c16-c47" not in text and "c32-" not in text

    def test_suggested_layout_is_an_ini_section_the_proxy_reads(self, text):
        layout = ini_section_in(text, "FFP.Registers")
        assert dict(layout["FFP.Registers"]) == {"WorldStart": "8", "WorldEnd": "12"}
        assert keys_of(layout) <= keys_the_proxy_reads()


class TestRenderStates:
    @pytest.fixture(scope="class")
    def text(self, known_calls):
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


class TestPixelShaderConstants:
    def test_start_register_and_count(self, known_calls):
        text = report("find_ps_constants", known_calls[0])

        assert "StartReg=10, Count=2  (c10-c11)" in text


class TestTextureOps:
    @pytest.fixture(scope="class")
    def text(self, known_calls):
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
    def text(self, known_calls):
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
    def text(self, known_calls):
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
