"""Golden checks for the D3D9 tables behind the DX scanner scripts.

Expected values come from the DirectX headers: ``D3DRENDERSTATETYPE`` in
``d3d9types.h`` and ``ID3DXConstantTable`` in ``d3dx9shader.h``.
"""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "scripts"))

import dx9_calls as calls
import dx9_enums as enums
import dx9_shader as shader_code
import find_matrix_registers
import find_render_states
import find_vtable_calls


class TestRenderStateValueDecoding:
    @pytest.mark.parametrize("state_id, value, expected", [
        (19, 5, "SRCALPHA"),       # D3DRS_SRCBLEND
        (20, 6, "INVSRCALPHA"),    # D3DRS_DESTBLEND
        (53, 3, "REPLACE"),        # D3DRS_STENCILFAIL
        (54, 7, "INCR"),           # D3DRS_STENCILZFAIL
        (55, 1, "KEEP"),           # D3DRS_STENCILPASS
        (56, 8, "ALWAYS"),         # D3DRS_STENCILFUNC
        (140, 3, "LINEAR"),        # D3DRS_FOGVERTEXMODE
        (145, 1, "COLOR1"),        # D3DRS_DIFFUSEMATERIALSOURCE
        (148, 0, "MATERIAL"),      # D3DRS_EMISSIVEMATERIALSOURCE
        (151, 3, "3WEIGHTS"),      # D3DRS_VERTEXBLEND
        (171, 1, "ADD"),           # D3DRS_BLENDOP
        (186, 1, "KEEP"),          # D3DRS_CCW_STENCILFAIL
        (189, 8, "ALWAYS"),        # D3DRS_CCW_STENCILFUNC
        (207, 5, "SRCALPHA"),      # D3DRS_SRCBLENDALPHA
        (208, 6, "INVSRCALPHA"),   # D3DRS_DESTBLENDALPHA
        (209, 1, "ADD"),           # D3DRS_BLENDOPALPHA
    ])
    def test_enum_valued_states(self, state_id, value, expected):
        assert enums.decode_rs_value(state_id, value) == expected

    @pytest.mark.parametrize("state_id", [
        14,    # ZWRITEENABLE
        15,    # ALPHATESTENABLE
        27,    # ALPHABLENDENABLE
        52,    # STENCILENABLE
        136,   # CLIPPING
        137,   # LIGHTING
        167,   # INDEXEDVERTEXBLENDENABLE
        174,   # SCISSORTESTENABLE
        206,   # SEPARATEALPHABLENDENABLE
    ])
    def test_boolean_states(self, state_id):
        assert enums.decode_rs_value(state_id, 1) == "TRUE"
        assert enums.decode_rs_value(state_id, 0) == "FALSE"

    @pytest.mark.parametrize("state_id", [
        34,    # FOGCOLOR
        60,    # TEXTUREFACTOR
        139,   # AMBIENT
    ])
    def test_colour_states(self, state_id):
        assert enums.decode_rs_value(state_id, 0xFF102030) == "ARGB(0xFF102030)"

    def test_decoder_tables_only_reference_defined_states(self):
        assert set(enums.RS_VALUE_DECODERS) <= set(enums.D3DRS)
        assert enums.RS_BOOL_STATES <= set(enums.D3DRS)
        assert not (set(enums.RS_VALUE_DECODERS) & enums.RS_BOOL_STATES)

    def test_float_state_is_not_reported_as_boolean(self):
        point_size = 154
        assert enums.decode_rs_value(point_size, 0x3F800000) not in ("TRUE", "FALSE")


class TestRenderStateCategories:
    @pytest.mark.parametrize("category, state_id", [
        ("Alpha Blending", 19),      # SRCBLEND
        ("Depth/Stencil", 53),       # STENCILFAIL
        ("Texture Factor", 60),      # TEXTUREFACTOR
        ("Vertex Processing", 136),  # CLIPPING
        ("Lighting/Material", 137),  # LIGHTING
    ])
    def test_state_is_listed_under_its_category(self, category, state_id):
        assert state_id in find_render_states.RS_CATEGORIES[category]

    def test_no_state_is_listed_twice(self):
        listed = [
            state_id
            for state_ids in find_render_states.RS_CATEGORIES.values()
            for state_id in state_ids
        ]
        assert len(listed) == len(set(listed))


class TestD3dxConstantTableOffsets:
    @pytest.mark.parametrize("offset, method", [
        (0x24, "GetConstantByName"),
        (0x30, "SetValue"),
        (0x4C, "SetVector"),
        (0x54, "SetMatrix"),
        (0x58, "SetMatrixArray"),
        (0x60, "SetMatrixTranspose"),
        (0x68, "SetMatrixTransposePointerArray"),
    ])
    def test_x86_vtable_offsets(self, offset, method):
        assert find_vtable_calls.D3DX_CONST_TABLE[offset] == method

    def test_inherited_buffer_methods_precede_constant_table_methods(self):
        methods = [name for name, _param_count in calls.D3DX_CONSTANT_TABLE_METHODS]
        assert methods[:5] == ["QueryInterface", "AddRef", "Release", "GetBufferPointer", "GetBufferSize"]
        assert methods.index("GetDesc") == 5


class TestDeviceVtable:
    @pytest.mark.parametrize("offset, method", [
        (0x00, "QueryInterface"),
        (0x44, "Present"),
        (0xE4, "SetRenderState"),
        (0x148, "DrawIndexedPrimitive"),
        (0x178, "SetVertexShaderConstantF"),
        (0x1D8, "CreateQuery"),
    ])
    def test_x86_vtable_offsets(self, offset, method):
        assert enums.D3D9_DEVICE_VTABLE[offset] == method

    def test_every_method_the_scans_know_has_a_name(self):
        assert set(enums.D3D9_DEVICE_VTABLE) == set(calls.DEVICE)
        assert len(enums.D3D9_DEVICE_VTABLE) == 119


class TestTextureFilterDecoding:
    """D3DTEXTUREFILTERTYPE in d3d9types.h."""

    @pytest.mark.parametrize("value, expected", [
        (0, "NONE"), (1, "POINT"), (2, "LINEAR"), (3, "ANISOTROPIC"),
        (6, "PYRAMIDALQUAD"), (7, "GAUSSIANQUAD"), (8, "CONVOLUTIONMONO"),
    ])
    def test_filter_values(self, value, expected):
        min_filter = 6
        assert enums.decode_samp_value(min_filter, value) == expected

    @pytest.mark.parametrize("value", [4, 5])
    def test_values_the_header_does_not_define_are_not_named(self, value):
        mag_filter = 5
        assert enums.decode_samp_value(mag_filter, value) == f"0x{value:X}"


class TestFormatDecoding:
    def test_intz_is_the_fourcc_of_its_letters(self):
        intz = int.from_bytes(b"INTZ", "little")
        assert enums.decode_format(intz) == "INTZ"

    @pytest.mark.parametrize("letters", [b"IN24", b"R11F"])
    def test_a_fourcc_without_a_name_reads_as_its_letters(self, letters):
        assert enums.decode_format(int.from_bytes(letters, "little")) == f"FourCC('{letters.decode()}')"

    def test_named_fourcc(self):
        assert enums.decode_format(int.from_bytes(b"DXT5", "little")) == "DXT5"

    def test_a_value_wider_than_a_dword_is_no_fourcc(self):
        assert enums.decode_format(0x1_4458_5435) == "UNKNOWN(0x144585435)"


def _vertex_element(stream, decl_type, usage):
    return struct.pack("<HHBBBB", stream, 0, decl_type, 0, usage, 0)


class TestVertexElement:
    def test_position_element_of_stream_0(self):
        assert enums.is_vertex_element(_vertex_element(0, 2, 0))

    @pytest.mark.parametrize("element", [
        _vertex_element(5, 2, 0),       # stream past the few a game binds
        _vertex_element(0, 18, 0),      # past D3DDECLTYPE_UNUSED
        _vertex_element(0, 2, 14),      # past D3DDECLUSAGE_SAMPLE
        _vertex_element(0, 2, 0)[:7],   # cut short by the end of the file
    ])
    def test_other_data(self, element):
        assert not enums.is_vertex_element(element)


_CTAB_HEADER_SIZE = 28
_FLOAT_REGISTERS, _SAMPLER_REGISTERS = 2, 3


def _constant_table(constant_count, constant_info_offset, body=b""):
    """A CTAB comment: the tag, then a D3DXSHADER_CONSTANTTABLE and *body*. Offsets count from the table."""
    header = struct.pack("<IIIIIII", _CTAB_HEADER_SIZE, 0, 0xFFFE0300, constant_count, constant_info_offset, 0, 0)
    payload = b"CTAB" + header + body
    payload += bytes(-len(payload) % 4)
    return struct.pack("<I", (len(payload) // 4) << 16 | 0xFFFE) + payload


def _shader_with_ctab(constant_count, constant_info_offset, body=b""):
    return (struct.pack("<I", 0xFFFE0300) + _constant_table(constant_count, constant_info_offset, body)
            + struct.pack("<I", 0x0000FFFF))


def _constants(*constants):
    """The body of a table holding *constants*: (name, register set, first register, register count, rows, columns)."""
    infos_size = 20 * len(constants)
    infos, blobs = b"", b""
    for name, register_set, register, count, rows, columns in constants:
        name_offset = _CTAB_HEADER_SIZE + infos_size + len(blobs)
        blobs += name.encode() + b"\0"
        blobs += bytes(-len(blobs) % 4)
        type_offset = _CTAB_HEADER_SIZE + infos_size + len(blobs)
        blobs += struct.pack("<HHHHHHI", 3, 3, rows, columns, 1, 0, 0)
        infos += struct.pack("<IHHHHII", name_offset, register_set, register, count, 0, type_offset, 0)
    return infos + blobs


class TestConstantTable:
    def test_float_constants_come_back_with_their_registers_and_shape(self):
        body = _constants(("matViewProj", _FLOAT_REGISTERS, 47, 4, 4, 4),
                          ("diffuse_texture", _SAMPLER_REGISTERS, 0, 1, 1, 1),
                          ("fFogDensity", _FLOAT_REGISTERS, 54, 1, 1, 1))
        shader = _shader_with_ctab(3, _CTAB_HEADER_SIZE, body)

        assert find_matrix_registers.parse_ctab(shader, 0, len(shader)) == [
            ("matViewProj", 47, 4, 4, 4), ("fFogDensity", 54, 1, 1, 1)]

    @pytest.mark.parametrize("constant_info_offset", [28, 0x1000, 0xFFFFFFF0])
    def test_table_whose_offsets_leave_the_comment_has_no_constants(self, constant_info_offset):
        shader = _shader_with_ctab(1, constant_info_offset)

        assert find_matrix_registers.parse_ctab(shader, 0, len(shader)) == []


_END_TOKEN = 0x0000FFFF


def _dwords(*tokens):
    return struct.pack(f"<{len(tokens)}I", *tokens)


def _comment(*payload):
    return _dwords(len(payload) << 16 | 0xFFFE, *payload)


class TestShaderEnd:
    _VS_3_0, _VS_1_1 = 0xFFFE0300, 0xFFFE0101
    _MOV_SM3 = _dwords(0x02000001, 0x800F0000, 0x90E40000)      # mov r0, v0: two operand tokens, counted in the opcode
    _MOV_SM1 = _dwords(0x00000001, 0x800F0000, 0x90E40000)      # shader model 1 opcodes carry no length

    def test_shader_without_comments(self):
        shader = _dwords(self._VS_3_0) + self._MOV_SM3 + _dwords(_END_TOKEN)

        assert shader_code.find_shader_end(shader + bytes(16), 0) == len(shader)

    def test_end_token_value_inside_a_comment_does_not_end_the_shader(self):
        shader = _dwords(self._VS_3_0) + _comment(0x42415443, _END_TOKEN, 7) + self._MOV_SM3 + _dwords(_END_TOKEN)

        assert shader_code.find_shader_end(shader + bytes(16), 0) == len(shader)

    def test_float_constant_is_not_read_as_a_comment_or_as_the_end(self):
        almost_one = 0x3F7FFFFE                                 # low word reads as the comment opcode
        define = _dwords(0x05000051, 0xA00F0000, almost_one, _END_TOKEN, 0, 0)          # def c0, ...
        shader = _dwords(self._VS_3_0) + define + self._MOV_SM3 + _dwords(_END_TOKEN)

        assert shader_code.find_shader_end(shader + bytes(16), 0) == len(shader)

    def test_shader_model_1_float_constant(self):
        almost_one = 0x3F7FFFFE
        define = _dwords(0x00000051, 0xA00F0000, almost_one, _END_TOKEN, 0, 0)
        shader = _dwords(self._VS_1_1) + define + self._MOV_SM1 + _dwords(_END_TOKEN)

        assert shader_code.find_shader_end(shader + bytes(16), 0) == len(shader)

    def test_shader_that_runs_off_the_data_has_no_end(self):
        shader = _dwords(self._VS_3_0) + _comment(1, 2, 3)[:8]

        assert shader_code.find_shader_end(shader, 0) is None

    def test_constant_table_after_a_float_constant_is_found(self):
        define = _dwords(0x05000051, 0xA00F0000, 0x3F7FFFFE, 0, 0, 0)
        table = _constant_table(1, _CTAB_HEADER_SIZE)
        shader = _dwords(self._VS_3_0) + define + table + _dwords(_END_TOKEN)

        assert list(shader_code.comments(shader, 0, len(shader))) == [(len(shader) - 4 - len(table) + 4, len(shader) - 4)]
