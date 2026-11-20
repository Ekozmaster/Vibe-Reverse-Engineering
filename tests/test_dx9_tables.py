"""Golden checks for the D3D9 tables behind the DX scanner scripts.

Expected values come from the DirectX headers: ``D3DRENDERSTATETYPE`` in
``d3d9types.h`` and ``ID3DXConstantTable`` in ``d3dx9shader.h``.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "scripts"))

import dx9_calls as calls
import dx9_enums as enums
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
