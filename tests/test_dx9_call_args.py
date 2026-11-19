"""What the DX scanners read out of the code in front of a D3D9 device call.

A stdcall method call pushes its arguments last to first, then ``this``. The
scanners must hand each pushed value back under the parameter it was pushed
for, count a pushed register as an argument, and say nothing about an argument
the code in front of the call does not settle.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "scripts"))

import dx9_common as dx
from d3d9_calls import (
    PUSH_EAX, PUSH_ECX, PUSH_ESI, TEXT_VA, Code, call_method, push, push32,
    write_pe32, write_pe32_plus,
)

SET_RENDER_STATE = 0xE4
SET_TRANSFORM = 0xB0
SET_VS_CONSTANT_F = 0x178
CREATE_TEXTURE = 0x5C
PRESENT = 0x44

_CALL_NEAR = bytes([0xE8, 0, 0, 0, 0])
_CALL_EAX = bytes([0xFF, 0xD0])


def _immediates(code: Code, label: str, method: str) -> dict:
    return dx.method_immediates(code.data, TEXT_VA, code.calls[label], method)


class TestArgumentsByName:
    def test_each_immediate_comes_back_under_its_parameter(self):
        code = Code().add("palette", push(60), PUSH_EAX, push(20), PUSH_ECX,
                          call_method(SET_VS_CONSTANT_F))

        assert _immediates(code, "palette", "SetVertexShaderConstantF") == {
            "this": None, "StartRegister": 20, "pConstantData": None, "Vector4fCount": 60}

    def test_pushed_register_is_reported_by_name(self):
        code = Code().add("view", PUSH_EAX, push(2), PUSH_ECX, call_method(SET_TRANSFORM))

        args = dx.method_args(code.data, TEXT_VA, code.calls["view"], "SetTransform")

        assert args["this"].source == "ecx"
        assert args["State"].value == 2
        assert args["pMatrix"].value is None and args["pMatrix"].source == "eax"

    def test_imm32_push(self):
        code = Code().add("alpharef", push32(128), push(24), PUSH_ECX, call_method(SET_RENDER_STATE))

        assert _immediates(code, "alpharef", "SetRenderState") == {
            "this": None, "State": 24, "Value": 128}

    def test_displacement_byte_0x68_is_not_a_push(self):
        load_local = bytes([0x8B, 0x45, 0x68])          # mov eax, [ebp+0x68]
        code = Code().add("cull", load_local, PUSH_EAX, push(22), PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "cull", "SetRenderState") == {
            "this": None, "State": 22, "Value": None}

    def test_short_form_call_with_eight_arguments(self):
        code = Code().add("texture", push(0), PUSH_EAX, push(1), push(21), push(0), push(1),
                          push32(128), push32(256), PUSH_ECX, call_method(CREATE_TEXTURE, short=True))

        assert _immediates(code, "texture", "CreateTexture") == {
            "this": None, "Width": 256, "Height": 128, "Levels": 1, "Usage": 0,
            "Format": 21, "Pool": 1, "ppTexture": None, "pSharedHandle": 0}


class TestWhereTheWalkStops:
    def test_an_earlier_call_hides_what_was_pushed_before_it(self):
        code = Code().add("after_call", push(5), _CALL_NEAR, push(19), PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "after_call", "SetRenderState") == {
            "this": None, "State": 19, "Value": None}

    def test_a_stack_adjustment_hides_what_was_pushed_before_it(self):
        add_esp_4 = bytes([0x83, 0xC4, 0x04])
        code = Code().add("adjusted", push(7), add_esp_4, push(22), PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "adjusted", "SetRenderState") == {
            "this": None, "State": 22, "Value": None}

    def test_a_push_reached_by_two_paths_is_not_reported(self):
        # jne +4 / push 5 / jmp +2 / push 8 / (join) push 23 / push ecx / call
        either_value = bytes([0x75, 0x04]) + push(5) + bytes([0xEB, 0x02]) + push(8)
        code = Code().add("joined", either_value, push(23), PUSH_ECX, call_method(SET_RENDER_STATE))

        assert _immediates(code, "joined", "SetRenderState") == {
            "this": None, "State": 23, "Value": None}

    def test_a_join_is_seen_however_far_back_the_jump_to_it_is(self):
        # jmp over 96 bytes of register moves and the push 5 / push 5 / (join) push 23 / push ecx / call
        far_jump = bytes([0xE9]) + (96 + 2).to_bytes(4, "little")
        filler = bytes([0x8B, 0xC0]) * 48                # mov eax, eax
        code = Code().add("far_join", far_jump, filler, push(5), push(23), PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "far_join", "SetRenderState") == {
            "this": None, "State": 23, "Value": None}

    def test_a_join_is_seen_when_the_jump_to_it_comes_after_the_call(self):
        # push 5 / (join) push 23 / push ecx / call / jmp back to the join
        body = push(5) + push(23) + PUSH_ECX + call_method(SET_RENDER_STATE)
        jump_back = bytes([0xEB, 256 - (len(body) - len(push(5))) - 2])
        code = Code().add("loop_join", push(5), push(23), PUSH_ECX,
                          call_method(SET_RENDER_STATE) + jump_back)

        assert _immediates(code, "loop_join", "SetRenderState") == {
            "this": None, "State": 23, "Value": None}


class TestSitesThatAreNotCalls:
    def test_method_pointer_loaded_then_called_through_the_register(self):
        load_method = bytes([0x8B, 0x82]) + (SET_VS_CONSTANT_F).to_bytes(4, "little")  # mov eax, [edx+0x178]
        code = Code().add("indirect", load_method, push(4), PUSH_ESI, push(8), PUSH_ECX, _CALL_EAX)
        mov_va = code.calls["indirect"] - len(push(4) + PUSH_ESI + push(8) + PUSH_ECX) - len(load_method)

        assert dx.method_immediates(code.data, TEXT_VA, mov_va, "SetVertexShaderConstantF") == {
            "this": None, "StartRegister": 8, "pConstantData": None, "Vector4fCount": 4}

    def test_field_read_at_a_method_offset_has_no_arguments(self):
        read_field = bytes([0x8B, 0x86]) + (SET_VS_CONSTANT_F).to_bytes(4, "little")   # mov eax, [esi+0x178]
        code = Code().add("field", push(16), push(32), _CALL_NEAR, read_field)

        assert dx.method_immediates(code.data, TEXT_VA, code.calls["field"], "SetVertexShaderConstantF") == {
            "this": None, "StartRegister": None, "pConstantData": None, "Vector4fCount": None}

    def test_call_bytes_inside_another_instruction_have_no_arguments(self):
        # mov eax, 0x017892FF holds FF 92 78 01, the start of call [edx+0x178]
        mov_with_call_bytes = bytes([0xB8, 0xFF, 0x92, 0x78, 0x01]) + bytes([0x00, 0x00])
        code = Code().add("embedded", push(4), push(8), mov_with_call_bytes)
        inside = code.calls["embedded"] + 1

        assert dx.method_immediates(code.data, TEXT_VA, inside, "SetVertexShaderConstantF") == {
            "this": None, "StartRegister": None, "pConstantData": None, "Vector4fCount": None}


class TestCallScan:
    def test_finds_the_short_and_the_long_form(self):
        code = (Code().add("short", PUSH_ECX, call_method(PRESENT, short=True))
                .add("long", PUSH_ECX, call_method(PRESENT)))

        found = dx.scan_vtable_calls(code.data, TEXT_VA, PRESENT)

        assert found == [(code.calls["short"], "edx"), (code.calls["long"], "edx")]

    def test_finds_a_call_through_ebp(self):
        through_ebp = bytes([0xFF, 0x95]) + (SET_RENDER_STATE).to_bytes(4, "little")   # call [ebp+0xE4]
        code = Code().add("ebp", PUSH_ECX, through_ebp)

        assert dx.scan_vtable_calls(code.data, TEXT_VA, SET_RENDER_STATE) == [(code.calls["ebp"], "ebp")]


class TestLoadBinary:
    def test_pe32_loads(self, tmp_path):
        path = write_pe32(tmp_path / "game.exe", Code().data)

        data, image_base, sections = dx.load_binary(path)

        assert image_base == 0x400000 and sections[0]["name"] == ".text"

    def test_64_bit_binary_is_refused(self, tmp_path):
        path = write_pe32_plus(tmp_path / "game64.exe", Code().data)

        with pytest.raises(SystemExit) as refusal:
            dx.load_binary(path)

        assert "64-bit" in str(refusal.value)

    def test_file_that_is_not_a_pe_is_refused(self, tmp_path):
        path = tmp_path / "notes.txt"
        path.write_text("not a program")

        with pytest.raises(SystemExit) as refusal:
            dx.load_binary(path)

        assert "not a PE" in str(refusal.value)
