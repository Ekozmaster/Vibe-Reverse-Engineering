"""What the DX scanners read out of the code in front of a D3D9 device call.

A stdcall method call pushes its arguments last to first, then ``this``. The
scanners must hand each pushed value back under the parameter it was pushed
for, count a pushed register as an argument, and say nothing about an argument
the code in front of the call does not settle.
"""

import struct
import sys
from pathlib import Path
from random import Random

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "scripts"))

import dx9_calls as calls
import dx9_pe
from d3d9_calls import (
    DEVICE_GLOBAL, PUSH_EAX, PUSH_ECX, PUSH_ESI, TEXT_VA, Code, call_method, load_device, push, push32,
    write_pe32, write_pe32_plus,
)

SET_RENDER_STATE = 0xE4
BEGIN_SCENE = 0xA4
SET_TRANSFORM = 0xB0
SET_VS_CONSTANT_F = 0x178
CREATE_TEXTURE = 0x5C
PRESENT = 0x44
QUERY_INTERFACE = 0x00
RELEASE = 0x08

_CALL_NEAR = bytes([0xE8, 0, 0, 0, 0])
_NO_PRESENT_ARGUMENTS = (push(0), push(0), push(0), push(0))
_CALL_EAX = bytes([0xFF, 0xD0])
_TEST_EAX = bytes([0x85, 0xC0])
_STORE_ECX_AT_ESP = bytes([0x89, 0x0C, 0x24])           # mov [esp], ecx
_ADD_ESP_4 = bytes([0x83, 0xC4, 0x04])
_RET = bytes([0xC3])
_PADDING = bytes([0xCC]) * 16
# More code than the walk back trusts a decoding across, so decodings from before it fall into step
_REAL_CODE = bytes([
    0x8B, 0x45, 0x08,               # mov eax, [ebp+8]
    0x85, 0xC0,                     # test eax, eax
    0x56,                           # push esi
    0x8B, 0xF1,                     # mov esi, ecx
    0x33, 0xD2,                     # xor edx, edx
    0x89, 0x55, 0xF8,               # mov [ebp-8], edx
    0x83, 0xC0, 0x04,               # add eax, 4
    0x5E,                           # pop esi
    0x90,                           # nop
]) * 4


def _store(disp: int, value: int) -> bytes:
    """``mov dword ptr [esp+disp], imm32``."""
    return bytes([0xC7, 0x44, 0x24, disp]) + value.to_bytes(4, "little")


def _jump_if_equal_over(*chunks: bytes) -> bytes:
    """``je`` to the first byte after *chunks*, then *chunks*."""
    skipped = b"".join(chunks)
    return bytes([0x74, len(skipped)]) + skipped


def _immediates_at(code: Code, site_va: int, method: str) -> dict:
    return calls.immediates(calls.method_args(code.data, TEXT_VA, site_va, method))


def _immediates(code: Code, label: str, method: str) -> dict:
    return _immediates_at(code, code.calls[label], method)


class TestArgumentsByName:
    def test_each_immediate_comes_back_under_its_parameter(self):
        code = Code().add("palette", push(60), PUSH_EAX, push(20), PUSH_ECX,
                          call_method(SET_VS_CONSTANT_F))

        assert _immediates(code, "palette", "SetVertexShaderConstantF") == {
            "this": None, "StartRegister": 20, "pConstantData": None, "Vector4fCount": 60}

    def test_pushed_register_is_reported_by_name(self):
        code = Code().add("view", PUSH_EAX, push(2), PUSH_ECX, call_method(SET_TRANSFORM))

        args = calls.method_args(code.data, TEXT_VA, code.calls["view"], "SetTransform")

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


class TestArgumentsStoredOnTheStack:
    def test_stores_into_reserved_space_are_the_arguments(self):
        sub_esp_12 = bytes([0x83, 0xEC, 0x0C])
        code = Code().add("stored", sub_esp_12, _store(8, 1), _store(4, 22), _STORE_ECX_AT_ESP,
                          call_method(SET_RENDER_STATE))

        args = calls.method_args(code.data, TEXT_VA, code.calls["stored"], "SetRenderState")

        assert args["this"].source == "ecx"
        assert (args["State"].value, args["Value"].value) == (22, 1)

    def test_a_store_overwrites_what_an_earlier_push_put_in_its_slot(self):
        code = Code().add("overwritten", push(7), push(8), _store(8, 1), _store(4, 22), _STORE_ECX_AT_ESP,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "overwritten", "SetRenderState") == {
            "this": None, "State": 22, "Value": 1}

    def test_a_store_counts_the_pushes_after_it(self):
        # mov [esp], 1 replaces the push 9 under it, which push 22 and push ecx then make Value
        code = Code().add("before_pushes", push(9), _store(0, 1), push(22), PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "before_pushes", "SetRenderState") == {
            "this": None, "State": 22, "Value": 1}

    @pytest.mark.parametrize("unreadable_store", [
        bytes([0xD9, 0x5C, 0x24, 0x08]),            # fstp dword ptr [esp+8]
        bytes([0xC6, 0x44, 0x24, 0x08, 0x01]),      # mov byte ptr [esp+8], 1
    ], ids=["fstp", "byte_store"])
    def test_a_store_that_is_not_a_dword_constant_hides_the_push_under_it(self, unreadable_store):
        code = Code().add("unreadable", push(7), push(22), PUSH_ECX, unreadable_store,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "unreadable", "SetRenderState") == {
            "this": None, "State": 22, "Value": None}

    def test_a_store_at_an_indexed_address_ends_the_walk(self):
        store_indexed = bytes([0x89, 0x0C, 0x84])            # mov [esp+eax*4], ecx
        code = Code().add("indexed", push(7), push(22), store_indexed, PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "indexed", "SetRenderState") == {
            "this": None, "State": None, "Value": None}


class TestWhereTheWalkStops:
    def test_an_earlier_call_hides_what_was_pushed_before_it(self):
        code = Code().add("after_call", push(5), _CALL_NEAR, push(19), PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "after_call", "SetRenderState") == {
            "this": None, "State": 19, "Value": None}

    def test_pushes_before_a_call_the_caller_cleans_up_after_are_still_there(self):
        # push 1 / push 22 / push 9 / call f / add esp, 4: f left its argument for the caller to take off
        code = Code().add("cdecl", push(1), push(22), push(9), _CALL_NEAR, _ADD_ESP_4, PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "cdecl", "SetRenderState") == {"this": None, "State": 22, "Value": 1}

    def test_a_stack_adjustment_hides_what_was_pushed_before_it(self):
        code = Code().add("adjusted", push(7), _ADD_ESP_4, push(22), PUSH_ECX,
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

    def test_a_join_at_the_call_hides_every_push(self):
        # test eax, eax / je call / push 1 / push 22 / push esi / (join) call
        code = Code().add("join_at_call", _TEST_EAX, _jump_if_equal_over(push(1), push(22), PUSH_ESI),
                          call_method(SET_RENDER_STATE))

        assert _immediates(code, "join_at_call", "SetRenderState") == {
            "this": None, "State": None, "Value": None}

    def test_pushes_before_a_conditional_jump_are_on_the_fall_through_path(self):
        # push 1 / test eax, eax / je past the call / push 22 / push ecx / call
        skip_call = bytes([0x74, len(push(22) + PUSH_ECX + call_method(SET_RENDER_STATE))])
        code = Code().add("tested", push(1), _TEST_EAX, skip_call, push(22), PUSH_ECX, call_method(SET_RENDER_STATE))

        assert _immediates(code, "tested", "SetRenderState") == {"this": None, "State": 22, "Value": 1}

    def test_a_push_taken_off_again_by_a_pop_is_not_an_argument(self):
        # push 1 / push 5 / pop eax / push 22 / push ecx / call: push 5 / pop eax is mov eax, 5
        pop_eax = bytes([0x58])
        code = Code().add("pop", push(1), push(5), pop_eax, push(22), PUSH_ECX, call_method(SET_RENDER_STATE))

        assert _immediates(code, "pop", "SetRenderState") == {"this": None, "State": 22, "Value": 1}

    _LOAD_METHOD = bytes([0x8B, 0x82]) + SET_RENDER_STATE.to_bytes(4, "little")   # mov eax, [edx+0xE4]

    @pytest.mark.parametrize("chunks", [
        (_jump_if_equal_over(push(1), push(22)), _LOAD_METHOD, PUSH_ECX),
        (push(1), _LOAD_METHOD, _jump_if_equal_over(push(22)), PUSH_ECX),
    ], ids=["join_at_the_load", "join_between_load_and_call"])
    def test_a_join_on_the_way_from_a_method_pointer_load_to_its_call(self, chunks):
        code = Code().add("pointer_join", _TEST_EAX, *chunks, _CALL_EAX)
        after_load = chunks[chunks.index(self._LOAD_METHOD):]
        load_va = code.calls["pointer_join"] - sum(len(chunk) for chunk in after_load)

        assert _immediates_at(code, load_va, "SetRenderState") == {
            "this": None, "State": None, "Value": None}


class TestSitesThatAreNotCalls:
    def test_method_pointer_loaded_then_called_through_the_register(self):
        load_method = bytes([0x8B, 0x82]) + (SET_VS_CONSTANT_F).to_bytes(4, "little")  # mov eax, [edx+0x178]
        code = Code().add("indirect", load_method, push(4), PUSH_ESI, push(8), PUSH_ECX, _CALL_EAX)
        mov_va = code.calls["indirect"] - len(push(4) + PUSH_ESI + push(8) + PUSH_ECX) - len(load_method)

        assert _immediates_at(code, mov_va, "SetVertexShaderConstantF") == {
            "this": None, "StartRegister": 8, "pConstantData": None, "Vector4fCount": 4}

    def test_field_read_at_a_method_offset_has_no_arguments(self):
        read_field = bytes([0x8B, 0x86]) + (SET_VS_CONSTANT_F).to_bytes(4, "little")   # mov eax, [esi+0x178]
        code = Code().add("field", push(16), push(32), _CALL_NEAR, read_field)

        assert _immediates_at(code, code.calls["field"], "SetVertexShaderConstantF") == {
            "this": None, "StartRegister": None, "pConstantData": None, "Vector4fCount": None}

    def test_call_bytes_inside_another_instruction_have_no_arguments(self):
        # mov eax, 0x017892FF holds FF 92 78 01, the start of call [edx+0x178]
        mov_with_call_bytes = bytes([0xB8, 0xFF, 0x92, 0x78, 0x01]) + bytes([0x00, 0x00])
        code = Code().add("embedded", push(4), push(8), mov_with_call_bytes)
        inside = code.calls["embedded"] + 1

        assert _immediates_at(code, inside, "SetVertexShaderConstantF") == {
            "this": None, "StartRegister": None, "pConstantData": None, "Vector4fCount": None}

    @pytest.mark.parametrize("vtable_offset, instruction", [
        (PRESENT, bytes([0xB8, 0x51, 0xFF, 0x52, 0x44])),                  # mov eax, 0x4452FF51
        (QUERY_INTERFACE, bytes([0xE8, 0x50, 0xFF, 0x10, 0x00])),          # call rel32
        (RELEASE, bytes([0xC7, 0x45, 0xFC, 0x56, 0xFF, 0x50, 0x08])),      # mov dword ptr [ebp-4], 0x0850FF56
    ])
    def test_call_bytes_inside_an_instruction_that_real_code_leads_to_are_not_found(self, vtable_offset, instruction):
        code = Code().add("embedded", _REAL_CODE, instruction)

        assert calls.scan_vtable_calls(code.data, TEXT_VA, vtable_offset) == []

    def test_call_in_a_function_that_follows_data_no_decoding_gets_through_is_found(self):
        jump_table = bytes([0xFF]) * 80                                    # FF FF is no instruction
        code = Code()
        code.add_data("table", jump_table)
        code.add("query_interface", load_device(), push(0), push(0), PUSH_ECX, bytes([0xFF, 0x12]))   # call [edx]

        assert calls.scan_vtable_calls(code.data, TEXT_VA, QUERY_INTERFACE) == [
            (code.calls["query_interface"], "edx")]

    def test_call_right_after_the_start_of_the_section_is_found(self):
        code_data = load_device() + b"".join(_NO_PRESENT_ARGUMENTS) + PUSH_ECX + call_method(PRESENT, short=True)
        call_va = TEXT_VA + len(code_data) - 3

        assert calls.scan_vtable_calls(code_data, TEXT_VA, PRESENT) == [(call_va, "edx")]


class TestCallsShortlyAfterData:
    """A function that starts right after data: the data decodes into instructions that run into it."""

    _CALL_THROUGH = {"eax": 0x90, "ecx": 0x91, "edx": 0x92}                # ModRM of call [reg+disp32]
    # (object and vtable loads ending in the push of `this`, register the vtable is in)
    _OPENINGS = [
        (bytes([0xA1]) + struct.pack("<I", DEVICE_GLOBAL) + bytes([0x8B, 0x08, 0x50]), "ecx"),
        (load_device() + PUSH_ECX, "edx"),
        (bytes([0x8B, 0x41, 0x04, 0x8B, 0x10, 0x50]), "edx"),              # mov eax, [ecx+4] / mov edx, [eax]
        (bytes([0x8B, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x50]), "ecx"),        # mov eax, [esp+4] / mov ecx, [eax]
        (bytes([0x56, 0x8B, 0x71, 0x08, 0x8B, 0x06, 0x56]), "eax"),        # push esi / mov esi, [ecx+8] / ...
        (bytes([0x8B, 0x01, 0x51]), "eax"),                                # mov eax, [ecx] / push ecx
        (bytes([0x8B, 0x11, 0x51]), "edx"),                                # mov edx, [ecx] / push ecx
        (bytes([0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x08, 0x50]), "ecx"),
        (bytes([0x53, 0x8B, 0x5C, 0x24, 0x08, 0x8B, 0x03, 0x53]), "eax"),  # push ebx / mov ebx, [esp+8] / ...
    ]

    @classmethod
    def _begin_scene(cls, opening: bytes, vtable_reg: str) -> bytes:
        return opening + bytes([0xFF, cls._CALL_THROUGH[vtable_reg]]) + struct.pack("<I", BEGIN_SCENE)

    @staticmethod
    def _called_functions(preludes_and_bodies: list[tuple[bytes, bytes]]) -> tuple[bytes, list[int]]:
        """Ordinary code that calls each body directly, then each prelude with its body right after it.

        Returns:
            (section bytes, offset of each body).
        """
        callers_at = len(_PADDING + _REAL_CODE)
        after_callers = callers_at + len(_CALL_NEAR) * len(preludes_and_bodies) + len(_RET) + len(_PADDING)
        bodies_at, laid_out = [], b""
        for prelude, body in preludes_and_bodies:
            bodies_at.append(after_callers + len(laid_out) + len(prelude))
            laid_out += prelude + body + _RET
        callers = b"".join(
            bytes([0xE8]) + struct.pack("<i", body_at - (callers_at + len(_CALL_NEAR) * (index + 1)))
            for index, body_at in enumerate(bodies_at))
        return _PADDING + _REAL_CODE + callers + _RET + _PADDING + laid_out + _PADDING, bodies_at

    def test_call_in_a_directly_called_function_that_follows_a_jump_table_is_found(self):
        random = Random(1998)
        functions, call_offsets = [], []
        for _table in range(300):
            jump_table = b"".join(struct.pack("<I", TEXT_VA + random.randrange(0x20000))
                                  for _entry in range(random.randrange(2, 12)))
            for opening, vtable_reg in self._OPENINGS:
                functions.append((jump_table, self._begin_scene(opening, vtable_reg)))
                call_offsets.append(len(opening))
        data, bodies_at = self._called_functions(functions)
        expected = {TEXT_VA + body_at + call_offset for body_at, call_offset in zip(bodies_at, call_offsets)}

        found = {va for va, _reg in calls.scan_vtable_calls(data, TEXT_VA, BEGIN_SCENE)}

        assert found == expected

    @pytest.mark.parametrize("blob, padding", [
        (b"SetRenderState failed\0\0", 1), (struct.pack("<5H", 1, 2, 3, 4, 5), 1), (struct.pack("<5H", 1, 2, 3, 4, 5), 2),
    ], ids=["text", "words", "words_two_bytes"])
    def test_call_in_an_aligned_function_a_few_padding_bytes_after_data_is_found(self, blob, padding):
        opening, vtable_reg = self._OPENINGS[0]
        before = _REAL_CODE + _RET + blob + bytes([0xCC]) * padding
        data = bytes([0xCC]) * (-len(before) % 16) + before + self._begin_scene(opening, vtable_reg) + _RET
        call_va = TEXT_VA + len(data) - len(_RET) - 6

        assert calls.scan_vtable_calls(data, TEXT_VA, BEGIN_SCENE) == [(call_va, vtable_reg)]

    def test_call_bytes_after_a_padding_byte_in_an_immediate_off_the_function_alignment_are_not_found(self):
        push_with_call_bytes = bytes([0x68, 0xCC, 0x56, 0xFF, 0x50])       # push 0x50FF56CC, then 08 ...
        before = _REAL_CODE + push_with_call_bytes[:2]
        data = bytes([0xCC]) * (-len(before) % 16 + 1) + before + push_with_call_bytes[2:] + bytes([RELEASE, 0x00])

        assert calls.scan_vtable_calls(data, TEXT_VA, RELEASE) == []


class TestCallScan:
    def test_finds_the_short_and_the_long_form(self):
        code = (Code().add("short", *_NO_PRESENT_ARGUMENTS, PUSH_ECX, call_method(PRESENT, short=True))
                .add("long", *_NO_PRESENT_ARGUMENTS, PUSH_ECX, call_method(PRESENT)))

        found = calls.scan_vtable_calls(code.data, TEXT_VA, PRESENT)

        assert found == [(code.calls["short"], "edx"), (code.calls["long"], "edx")]

    def test_region_limits_the_sites_and_the_hits_that_are_checked(self, monkeypatch):
        code = Code()
        for label in ("before", "inside", "after"):
            code.add(label, push(1), push(22), PUSH_ECX, call_method(SET_RENDER_STATE))
        checked = []
        is_com_method_call = calls._is_com_method_call
        monkeypatch.setattr(calls, "_is_com_method_call", lambda text_data, text_va, site_va, param_count: (
            checked.append(site_va) or is_com_method_call(text_data, text_va, site_va, param_count)))
        inside = code.calls["inside"]

        found = calls.scan_all_patterns(code.data, TEXT_VA, SET_RENDER_STATE, region=(inside, inside + 1))

        assert found == [(inside, "call [edx+0x0E4]")]
        assert checked == [inside]

    def test_finds_a_call_through_ebp(self):
        through_ebp = bytes([0xFF, 0x95]) + (SET_RENDER_STATE).to_bytes(4, "little")   # call [ebp+0xE4]
        code = Code().add("ebp", push(1), push(22), PUSH_ECX, through_ebp)

        assert calls.scan_vtable_calls(code.data, TEXT_VA, SET_RENDER_STATE) == [(code.calls["ebp"], "ebp")]


    def test_finds_the_first_slot_through_a_register_without_displacement(self):
        call_first_slot = bytes([0xFF, 0x12])                                     # call [edx]
        code = Code().add("query_interface", load_device(), push(0), push(0), PUSH_ECX, call_first_slot)

        assert calls.scan_vtable_calls(code.data, TEXT_VA, 0) == [(code.calls["query_interface"], "edx")]

    def test_a_call_through_an_import_is_not_the_first_slot(self):
        call_import = bytes([0xFF, 0x15]) + (0x40A000).to_bytes(4, "little")     # call [0x40A000]
        code = Code().add("import", push(0), push(0), PUSH_ECX, call_import)

        assert calls.scan_vtable_calls(code.data, TEXT_VA, 0) == []


class TestMethodPointerLoadScan:
    def test_finds_a_first_slot_load_without_displacement(self):
        load_first_slot = bytes([0x8B, 0x02])                                     # mov eax, [edx]
        code = Code().add("query_interface", load_device(), load_first_slot, push(0), push(0), PUSH_ECX,
                          _CALL_EAX)
        load_va = code.calls["query_interface"] - len(push(0) * 2 + PUSH_ECX + load_first_slot)

        assert calls.scan_vtable_mov(code.data, TEXT_VA, 0) == [(load_va, "mov eax, [edx+0x000]")]

    def test_finds_the_short_and_the_long_form_below_slot_32(self):
        load_short = bytes([0x8B, 0x42, PRESENT])                                  # mov eax, [edx+0x44]
        load_long = bytes([0x8B, 0x8E]) + PRESENT.to_bytes(4, "little")            # mov ecx, [esi+0x44]
        code = (Code().add("short", *_NO_PRESENT_ARGUMENTS, load_short, PUSH_ECX, _CALL_EAX)
                .add("long", *_NO_PRESENT_ARGUMENTS, load_long, PUSH_ECX, bytes([0xFF, 0xD1])))
        short_va = code.calls["short"] - len(PUSH_ECX) - len(load_short)
        long_va = code.calls["long"] - len(PUSH_ECX) - len(load_long)

        assert calls.scan_vtable_mov(code.data, TEXT_VA, PRESENT) == [
            (short_va, "mov eax, [edx+0x044]"), (long_va, "mov ecx, [esi+0x044]")]

    def test_short_form_load_leads_to_the_arguments_of_its_call(self):
        load_short = bytes([0x8B, 0x42, CREATE_TEXTURE])                           # mov eax, [edx+0x5C]
        code = Code().add("texture", push(0), PUSH_EAX, push(1), push(21), push(0), push(1),
                          push32(128), push32(256), load_short, PUSH_ECX, _CALL_EAX)
        [(load_va, _)] = calls.scan_vtable_mov(code.data, TEXT_VA, CREATE_TEXTURE)

        pushed = _immediates_at(code, load_va, "CreateTexture")

        assert (pushed["Width"], pushed["Height"], pushed["Format"]) == (256, 128, 21)

    def test_slots_from_32_on_have_no_short_form(self):
        load_short = bytes([0x8B, 0x42, 0x80])                                     # mov eax, [edx-0x80]
        code = Code().add("negative", load_short, PUSH_ECX, _CALL_EAX)

        assert calls.scan_vtable_mov(code.data, TEXT_VA, 0x80) == []

    def test_a_conditional_jump_between_load_and_call_is_passed_by_its_fall_through(self):
        set_sampler_state = 0x114
        load_method = bytes([0x8B, 0x91]) + set_sampler_state.to_bytes(4, "little")  # mov edx, [ecx+0x114]
        call_edx = bytes([0xFF, 0xD2])
        jump_past_call = bytes([0x75, len(push(2) * 3 + PUSH_EAX + call_edx)])     # jne past the call
        code = Code().add("tested", load_method, _TEST_EAX, jump_past_call,
                          push(2), push(7), push(0), PUSH_EAX, call_edx)
        [(load_va, _)] = calls.scan_vtable_mov(code.data, TEXT_VA, set_sampler_state)

        assert _immediates_at(code, load_va, "SetSamplerState") == {
            "this": None, "Sampler": 0, "Type": 7, "Value": 2}

    def test_a_call_between_load_and_call_is_passed_when_the_method_sits_in_a_saved_register(self):
        draw_primitive = 0x144
        load_into_edi = bytes([0x8B, 0xB8]) + draw_primitive.to_bytes(4, "little")  # mov edi, [eax+0x144]
        call_edi = bytes([0xFF, 0xD7])
        code = Code().add("helper_first", load_into_edi, _CALL_NEAR,
                          push(2), push(0), push(4), PUSH_ESI, call_edi)
        [(load_va, _)] = calls.scan_vtable_mov(code.data, TEXT_VA, draw_primitive)

        assert _immediates_at(code, load_va, "DrawPrimitive") == {
            "this": None, "PrimitiveType": 4, "StartVertex": 0, "PrimitiveCount": 2}

    _LOAD_INTO_ESI = bytes([0x8B, 0xB1]) + SET_RENDER_STATE.to_bytes(4, "little")    # mov esi, [ecx+0xE4]
    _CALL_ESI = bytes([0xFF, 0xD6])
    _FIRST_GROUP = (push(1), push(22), PUSH_EAX, _CALL_ESI)
    _SECOND_GROUP = (push(0), push(7), PUSH_EAX, _CALL_ESI)

    def _hoisted(self, *between: bytes) -> tuple[Code, int, int]:
        """A method pointer kept in esi and called twice, *between* the calls: (code, load va, second call va)."""
        code = Code().add("hoisted", self._LOAD_INTO_ESI, *self._FIRST_GROUP, *between, *self._SECOND_GROUP)
        after_load = (*self._FIRST_GROUP, *between, *self._SECOND_GROUP[:-1])
        load_va = code.calls["hoisted"] - sum(len(chunk) for chunk in after_load) - len(self._LOAD_INTO_ESI)
        return code, load_va, code.calls["hoisted"]

    def test_each_call_through_a_kept_method_pointer_is_a_site(self):
        code, load_va, second_call_va = self._hoisted()

        sites = calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE)

        assert [va for va, _ in sites] == [load_va, second_call_va]
        assert _immediates_at(code, load_va, "SetRenderState") == {
            "this": None, "State": 22, "Value": 1}
        assert _immediates_at(code, second_call_va, "SetRenderState") == {
            "this": None, "State": 7, "Value": 0}

    def test_region_holding_only_a_later_call_reports_it(self):
        apart = bytes([0x90]) * 40
        third_group = (push(1), push(7), PUSH_EAX, self._CALL_ESI)
        code = Code().add("hoisted", self._LOAD_INTO_ESI, *self._FIRST_GROUP, apart, *self._SECOND_GROUP, apart,
                          *third_group)
        third_call_va = code.calls["hoisted"]
        load_va = TEXT_VA + code.data.index(self._LOAD_INTO_ESI)

        sites = calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE, region=(third_call_va, third_call_va + 1))

        assert sites == [(third_call_va, f"call esi (mov esi, [ecx+0x0E4] at 0x{load_va:08X})")]

    def test_region_holding_only_the_load_reports_no_later_call(self):
        code, load_va, _second_call_va = self._hoisted()

        sites = calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE, region=(load_va, load_va + 1))

        assert sites == [(load_va, "mov esi, [ecx+0x0E4]")]

    def test_a_later_call_names_the_load_it_calls_through(self):
        code, load_va, _ = self._hoisted()

        [_, (_, description)] = calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE)

        assert description == f"call esi (mov esi, [ecx+0x0E4] at 0x{load_va:08X})"

    def test_a_later_call_past_other_calls_and_a_conditional_jump_is_a_site(self):
        skip_second = bytes([0x74, sum(len(chunk) for chunk in self._SECOND_GROUP)])    # je past the second call
        code, load_va, second_call_va = self._hoisted(_CALL_NEAR, _TEST_EAX, skip_second)

        assert [va for va, _ in calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE)] == [
            load_va, second_call_va]

    @pytest.mark.parametrize("between", [
        bytes([0x8B, 0xF2]),                    # mov esi, edx
        _RET,
        bytes([0xEB, 0x00]),                    # jmp to the next instruction
    ], ids=["register_overwritten", "ret", "jmp"])
    def test_calls_through_the_register_end_where_it_no_longer_holds_the_method(self, between):
        code, load_va, _ = self._hoisted(between)

        assert [va for va, _ in calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE)] == [load_va]

    def test_a_register_that_calls_overwrite_serves_one_call(self):
        load_into_eax = bytes([0x8B, 0x81]) + SET_RENDER_STATE.to_bytes(4, "little")    # mov eax, [ecx+0xE4]
        group = (push(1), push(22), PUSH_ECX, _CALL_EAX)
        code = Code().add("eax", load_into_eax, *group, *group)
        load_va = code.calls["eax"] - sum(len(chunk) for chunk in (*group, *group[:-1])) - len(load_into_eax)

        assert [va for va, _ in calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE)] == [load_va]

    def test_later_calls_are_sought_as_far_from_the_call_before_as_the_first_from_the_load(self):
        filler = bytes([0x8B, 0xC0]) * 20                # mov eax, eax: 40 bytes
        code, load_va, second_call_va = self._hoisted(filler)

        assert [va for va, _ in calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE)] == [
            load_va, second_call_va]

    def test_a_later_call_of_a_load_that_is_another_classes_method_is_not_a_site(self):
        # mov eax, [ecx] / mov esi, [eax+0xE4] / push 1 / push 22 / call esi: ecx is `this`, a __thiscall
        thiscall_load = bytes([0x8B, 0x01, 0x8B, 0xB0]) + SET_RENDER_STATE.to_bytes(4, "little")
        code = Code().add("thiscall", thiscall_load, push(1), push(22), self._CALL_ESI, *self._SECOND_GROUP)

        assert calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE) == []

    def test_a_call_between_load_and_call_ends_the_path_when_it_may_overwrite_the_register(self):
        draw_primitive = 0x144
        load_into_eax = bytes([0x8B, 0x80]) + draw_primitive.to_bytes(4, "little")  # mov eax, [eax+0x144]
        code = Code().add("helper_first", load_into_eax, _CALL_NEAR, push(2), PUSH_ESI, _CALL_EAX)

        assert calls.scan_vtable_mov(code.data, TEXT_VA, draw_primitive) == []

    def test_a_write_to_part_of_the_method_register_ends_the_path(self):
        load_method = bytes([0x8B, 0x42, PRESENT])                                 # mov eax, [edx+0x44]
        overwrite_al = bytes([0xB0, 0x00])                                         # mov al, 0
        code = Code().add("partly_overwritten", *_NO_PRESENT_ARGUMENTS, load_method, overwrite_al, PUSH_ECX,
                          _CALL_EAX)

        assert calls.scan_vtable_mov(code.data, TEXT_VA, PRESENT) == []

    def test_a_field_read_that_is_not_called_is_not_a_method_pointer_load(self):
        read_field = bytes([0x8B, 0x46, PRESENT])                                  # mov eax, [esi+0x44]
        code = Code().add("field", read_field, PUSH_EAX, _CALL_NEAR)

        assert calls.scan_vtable_mov(code.data, TEXT_VA, PRESENT) == []


_DEVICE_GLOBAL = DEVICE_GLOBAL.to_bytes(4, "little")
_LOAD_VTABLE_FROM_ESI = bytes([0x8B, 0x06])             # mov eax, [esi]
_LOAD_VTABLE_FROM_ECX = bytes([0x8B, 0x01])             # mov eax, [ecx]
_CALL_PRESENT_THROUGH_EAX = bytes([0xFF, 0x50, PRESENT])  # call [eax+0x44]
_PUSH_EDX = bytes([0x52])
_PUSH_EDI = bytes([0x57])
_MOV_ECX_ESI = bytes([0x8B, 0xCE])


def _found_calls(code: Code, offset: int) -> list[int]:
    return [va for va, _reg in calls.scan_vtable_calls(code.data, TEXT_VA, offset)]


class TestComThis:
    """A COM call pushes the object its vtable came from as `this`; a __thiscall passes it in ecx."""

    def test_com_call_that_pushes_the_vtables_object_is_kept(self):
        code = Code().add("com", _LOAD_VTABLE_FROM_ESI, push(0), push(0), _PUSH_EDI, PUSH_ESI,
                          _CALL_PRESENT_THROUGH_EAX)

        assert _found_calls(code, PRESENT) == [code.calls["com"]]

    def test_thiscall_through_the_same_slot_is_dropped(self):
        # mov eax, [ecx] / push edx / call [eax+0x44]: ecx is `this`, edx a parameter
        code = Code().add("thiscall", _LOAD_VTABLE_FROM_ECX, _PUSH_EDX, _CALL_PRESENT_THROUGH_EAX)

        assert _found_calls(code, PRESENT) == []

    def test_immediate_on_top_of_the_stack_is_not_this(self):
        code = Code().add("immediate", _LOAD_VTABLE_FROM_ECX, push(1), _CALL_PRESENT_THROUGH_EAX)

        assert _found_calls(code, PRESENT) == []

    def test_register_saved_before_it_takes_the_object_is_not_this(self):
        # push esi / mov esi, ecx / mov eax, [esi] / call [eax+0x44]: the push saves the caller's esi
        mov_esi_ecx = bytes([0x8B, 0xF1])
        code = Code().add("saved", PUSH_ESI, mov_esi_ecx, _LOAD_VTABLE_FROM_ESI, _CALL_PRESENT_THROUGH_EAX)

        assert _found_calls(code, PRESENT) == []

    def test_ecx_set_to_the_object_marks_a_thiscall_when_the_values_are_unknown(self):
        # After a call nothing shows what esi or edi hold, but ecx = esi passes esi in ecx
        code = (Code().add("thiscall", _CALL_NEAR, _LOAD_VTABLE_FROM_ESI, push(0), push(0), push(0), push(0),
                           _PUSH_EDI, _MOV_ECX_ESI, _CALL_PRESENT_THROUGH_EAX)
                .add("com", _CALL_NEAR, _LOAD_VTABLE_FROM_ESI, push(0), push(0), push(0), _PUSH_EDI, PUSH_ESI,
                     _CALL_PRESENT_THROUGH_EAX))

        assert _found_calls(code, PRESENT) == [code.calls["com"]]

    @staticmethod
    def _object_from_a_stack_argument(pushed_disp: int, *between: bytes) -> Code:
        # mov eax, [esp+8] / mov ecx, [eax] / *between / push 1 / push 7 / push [esp+pushed_disp] / call [ecx+0xE4]
        return Code().add("stack", bytes([0x8B, 0x44, 0x24, 0x08]), bytes([0x8B, 0x08]), *between, push(1), push(7),
                          bytes([0xFF, 0x74, 0x24, pushed_disp]),
                          bytes([0xFF, 0x91]) + SET_RENDER_STATE.to_bytes(4, "little"))

    def test_object_pushed_earlier_and_pushed_again_from_its_slot_is_this(self):
        # push esi / mov eax, [esi] / push 1 / push 7 / push [esp+8] / call [eax+0xE4]
        code = Code().add("repushed", PUSH_ESI, _LOAD_VTABLE_FROM_ESI, push(1), push(7),
                          bytes([0xFF, 0x74, 0x24, 0x08]),
                          bytes([0xFF, 0x90]) + SET_RENDER_STATE.to_bytes(4, "little"))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["repushed"]]

    def test_stack_slot_written_between_the_two_reads_is_not_this(self):
        store_edx = bytes([0x89, 0x54, 0x24, 0x08])             # mov [esp+8], edx
        code = self._object_from_a_stack_argument(0x10, store_edx)

        assert _found_calls(code, SET_RENDER_STATE) == []

    def test_object_read_twice_from_one_stack_slot_is_this(self):
        # two pushes later, [esp+0x10] is the slot [esp+8] was
        code = self._object_from_a_stack_argument(0x10)

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["stack"]]

    def test_another_stack_slot_is_not_this(self):
        code = self._object_from_a_stack_argument(0x14)

        assert _found_calls(code, SET_RENDER_STATE) == []

    def test_register_whose_low_word_was_copied_from_the_object_is_not_this(self):
        # mov eax, [esi] / mov di, si / push edi / call [eax+0x44]: edi keeps its own high word
        mov_di_si = bytes([0x66, 0x8B, 0xFE])
        code = Code().add("low_word", _LOAD_VTABLE_FROM_ESI, mov_di_si, *_NO_PRESENT_ARGUMENTS, _PUSH_EDI,
                          _CALL_PRESENT_THROUGH_EAX)

        assert _found_calls(code, PRESENT) == []

    def test_this_the_code_does_not_show_keeps_the_call(self):
        code = Code().add("unsettled", _CALL_NEAR, _LOAD_VTABLE_FROM_ESI, *_NO_PRESENT_ARGUMENTS, _PUSH_EDI,
                          _CALL_PRESENT_THROUGH_EAX)

        assert _found_calls(code, PRESENT) == [code.calls["unsettled"]]

    @pytest.mark.parametrize("cleanup", [(), (_ADD_ESP_4,)], ids=["callee_cleans_up", "caller_cleans_up"])
    def test_nothing_put_on_the_stack_since_the_call_before_is_no_pushed_this(self, cleanup):
        # push 0 (x4) / push esi / call f / mov eax, [esi] / call [eax+0x44]: `this` is pushed last, after f
        code = Code().add("no_this", *_NO_PRESENT_ARGUMENTS, PUSH_ESI, _CALL_NEAR, *cleanup, _LOAD_VTABLE_FROM_ESI,
                          _CALL_PRESENT_THROUGH_EAX)

        assert _found_calls(code, PRESENT) == []

    def test_ecx_loaded_for_the_call_and_read_by_nothing_else_is_a_register_argument(self):
        # call f / mov ecx, esi / push eax / call [edx+0xE4]: the callee is the only reader of ecx
        code = Code().add("thiscall", push(1), _CALL_NEAR, _MOV_ECX_ESI, PUSH_EAX, call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == []

    @pytest.mark.parametrize("after_ecx_is_set", [
        (PUSH_EAX, PUSH_ECX),                                   # push ecx
        (bytes([0x8B, 0x11]), PUSH_EAX),                        # mov edx, [ecx]
        (bytes([0x02, 0xC1]), PUSH_EAX),                        # add al, cl
        (_TEST_EAX, bytes([0x74, 0x07]), PUSH_EAX),             # je past the call, to code that may read ecx
    ], ids=["pushed", "base_of_a_load", "low_byte_read", "live_on_another_path"])
    def test_ecx_the_code_reads_before_the_call_is_not_shown_to_be_an_argument(self, after_ecx_is_set):
        code = Code().add("com", push(1), _CALL_NEAR, _MOV_ECX_ESI, *after_ecx_is_set,
                          call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["com"]]

    def test_ecx_written_by_the_way_is_not_loaded_for_the_call(self):
        # call f / pop ecx / push eax / call [edx+0xE4]: pop ecx takes f's argument off the stack
        pop_ecx = bytes([0x59])
        code = Code().add("cleanup", push(1), push(9), _CALL_NEAR, pop_ecx, PUSH_EAX,
                          call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["cleanup"]]

    @pytest.mark.parametrize("ecx_write", [
        bytes([0x8D, 0x49, 0x00]),                              # lea ecx, [ecx+0]: three bytes of padding
        bytes([0x8B, 0xC9]),                                    # mov ecx, ecx: two bytes of padding
        bytes([0xB1, 0x01]),                                    # mov cl, 1
    ], ids=["lea_padding", "mov_padding", "low_byte"])
    def test_write_that_gives_ecx_no_new_value_is_not_a_register_argument(self, ecx_write):
        code = Code().add("com", push(1), _CALL_NEAR, ecx_write, PUSH_EAX, call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["com"]]

    @pytest.mark.parametrize("ecx_load", [
        bytes([0x8B, 0x49, 0x04]),                              # mov ecx, [ecx+4]
        bytes([0x8D, 0x49, 0x08]),                              # lea ecx, [ecx+8]
    ], ids=["member_object", "base_subobject"])
    def test_ecx_loaded_from_what_ecx_led_to_is_a_register_argument(self, ecx_load):
        code = Code().add("thiscall", push(1), _CALL_NEAR, ecx_load, PUSH_EAX, call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == []

    def test_method_pointer_loaded_into_ecx_is_read_by_the_call(self):
        # mov ecx, [edx+0xE4] / push 1 / push 22 / push eax / call ecx
        load_into_ecx = bytes([0x8B, 0x8A]) + SET_RENDER_STATE.to_bytes(4, "little")
        code = Code().add("into_ecx", _CALL_NEAR, load_into_ecx, push(1), push(22), PUSH_EAX, bytes([0xFF, 0xD1]))

        assert len(calls.scan_vtable_mov(code.data, TEXT_VA, SET_RENDER_STATE)) == 1

    def test_method_pointer_read_through_ecx_reads_ecx(self):
        # mov ecx, [eax] / push 1 / push 22 / push eax / call [ecx+0xE4]
        code = Code().add("through_ecx", _CALL_NEAR, bytes([0x8B, 0x08]), push(1), push(22), PUSH_EAX,
                          bytes([0xFF, 0x91]) + SET_RENDER_STATE.to_bytes(4, "little"))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["through_ecx"]]

    def test_method_pointer_form(self):
        load_vtable = bytes([0x8B, 0x11])                       # mov edx, [ecx]
        load_method = bytes([0x8B, 0x52, CREATE_TEXTURE])       # mov edx, [edx+0x5C]
        call_edx = bytes([0xFF, 0xD2])
        sizes = (push32(256), push32(128), push(1), push(0), push(21), push(1))
        code = (Code().add("com", *sizes, load_vtable, load_method, push(0), PUSH_EAX, PUSH_ECX, call_edx)
                .add("thiscall", *sizes, load_vtable, load_method, push(0), PUSH_EAX, call_edx))
        com_load = code.calls["com"] - len(push(0) + PUSH_EAX + PUSH_ECX) - len(load_method)

        assert [va for va, _ in calls.scan_vtable_mov(code.data, TEXT_VA, CREATE_TEXTURE)] == [com_load]

    def test_global_device_form(self):
        load_device = bytes([0xA1]) + _DEVICE_GLOBAL            # mov eax, [g_device]
        load_vtable = bytes([0x8B, 0x08])                       # mov ecx, [eax]
        call_set_render_state = bytes([0xFF, 0x91]) + SET_RENDER_STATE.to_bytes(4, "little")
        push_device = bytes([0xFF, 0x35]) + _DEVICE_GLOBAL      # push dword ptr [g_device]
        load_object = bytes([0x8B, 0x0D]) + _DEVICE_GLOBAL      # mov ecx, [g_device]
        code = (Code().add("register", load_device, load_vtable, push(1), push(22), PUSH_EAX, call_set_render_state)
                .add("memory", load_device, load_vtable, push(1), push(22), push_device, call_set_render_state)
                .add("thiscall", load_object, bytes([0x8B, 0x01]), push(1), push(22),
                     bytes([0xFF, 0x90]) + SET_RENDER_STATE.to_bytes(4, "little")))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["register"], code.calls["memory"]]
        assert _immediates(code, "register", "SetRenderState") == {"this": None, "State": 22, "Value": 1}


class TestArgumentCount:
    """A call that is shown to put fewer dwords on the stack than the method's parameters and `this` is dropped."""

    _SUB_ESP_12 = bytes([0x83, 0xEC, 0x0C])
    _GET_DEVICE_THEN_ITS_VTABLE = _CALL_NEAR + bytes([0x8B, 0x08])           # call GetDevice / mov ecx, [eax]
    _CALL_SET_RENDER_STATE_THROUGH_ECX = bytes([0xFF, 0x91]) + SET_RENDER_STATE.to_bytes(4, "little")

    def test_too_few_pushes_since_the_entry_of_the_code_is_dropped(self):
        # the frame pointer the function saves on entry is the only other dword in sight
        code = (Code().add("short", push(0), PUSH_ECX, call_method(PRESENT))
                .add("full", *_NO_PRESENT_ARGUMENTS, PUSH_ECX, call_method(PRESENT)))

        assert _found_calls(code, PRESENT) == [code.calls["full"]]

    def test_too_few_pushes_since_a_return_is_dropped(self):
        code = Code().add("short", push(1), _RET, push(22), PUSH_ECX, call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == []

    def test_arguments_pushed_before_an_inner_call_are_not_missing(self):
        # dev = GetDevice() after its arguments are pushed: push 1 / push 22 / call GetDevice / push eax
        code = Code().add("getter", push(1), push(22), self._GET_DEVICE_THEN_ITS_VTABLE, PUSH_EAX,
                          self._CALL_SET_RENDER_STATE_THROUGH_ECX)

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["getter"]]

    def test_arguments_under_an_inner_call_are_not_guessed(self):
        # GetDevice may have taken dwords off the stack, so which push is State is not shown
        code = Code().add("getter", push(1), push(22), self._GET_DEVICE_THEN_ITS_VTABLE, PUSH_EAX,
                          self._CALL_SET_RENDER_STATE_THROUGH_ECX)

        args = calls.method_args(code.data, TEXT_VA, code.calls["getter"], "SetRenderState")

        assert args["this"].source == "eax" and (args["State"], args["Value"]) == (None, None)

    @pytest.mark.parametrize("cleanup", [(), (_ADD_ESP_4,)], ids=["callee_cleans_up", "caller_cleans_up"])
    def test_an_argument_computed_by_an_inner_call_keeps_the_call(self, cleanup):
        # dev->SetRenderState(g(5), value): push value is out of sight, push 5 / call g / push eax in front
        load_device_into_eax = bytes([0xA1]) + _DEVICE_GLOBAL + bytes([0x8B, 0x08])    # mov eax, [g] / mov ecx, [eax]
        code = Code().add("computed", push(5), _CALL_NEAR, *cleanup, PUSH_EAX, load_device_into_eax, PUSH_EAX,
                          self._CALL_SET_RENDER_STATE_THROUGH_ECX)

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["computed"]]

    def test_a_change_of_esp_the_walk_cannot_follow_is_not_the_bottom_of_the_stack(self):
        align_stack = bytes([0x83, 0xE4, 0xF0])                             # and esp, -16
        code = Code().add("aligned", align_stack, push(0), PUSH_ECX, call_method(PRESENT))

        assert _found_calls(code, PRESENT) == [code.calls["aligned"]]

    def test_too_few_pushes_after_a_join_is_kept(self):
        # what the other path put on the stack before the join is not in front of the call
        code = Code().add("joined", _TEST_EAX, _jump_if_equal_over(push(5)), push(0), PUSH_ECX,
                          call_method(PRESENT))

        assert _found_calls(code, PRESENT) == [code.calls["joined"]]

    def test_pushes_of_an_outer_call_in_front_of_the_arguments_are_kept(self):
        # f(SetRenderState(...), 7): the outer call's push 7 precedes the inner call's arguments
        code = Code().add("nested", _CALL_NEAR, push(7), push(1), push(22), PUSH_ECX,
                          call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["nested"]]

    def test_stores_into_a_reserved_frame_count_as_arguments(self):
        code = Code().add("stored", _CALL_NEAR, self._SUB_ESP_12, _store(8, 1), _store(4, 22), _STORE_ECX_AT_ESP,
                          call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["stored"]]

    def test_a_reserved_slot_left_unwritten_is_not_an_argument(self):
        code = Code().add("unwritten", _CALL_NEAR, self._SUB_ESP_12, _store(4, 22), _STORE_ECX_AT_ESP,
                          call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == []

    def test_a_slot_under_the_reserved_ones_may_be_an_argument(self):
        # push 1 / call f / sub esp, 8 / mov [esp+4], 22 / mov [esp], ecx: the reservation covers this and State only
        sub_esp_8 = bytes([0x83, 0xEC, 0x08])
        code = Code().add("under", push(1), _CALL_NEAR, sub_esp_8, _store(4, 22), _STORE_ECX_AT_ESP,
                          call_method(SET_RENDER_STATE))

        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["under"]]

    def test_lea_of_esp_moves_the_slots_like_add_and_sub(self):
        lea_esp_padding = bytes([0x8D, 0x64, 0x24, 0x00])                  # lea esp, [esp]
        lea_esp_reserve = bytes([0x8D, 0x64, 0x24, 0xF8])                  # lea esp, [esp-8]
        code = (Code().add("padded", _CALL_NEAR, *_NO_PRESENT_ARGUMENTS, lea_esp_padding, PUSH_ECX,
                           call_method(PRESENT))
                .add("reserved", _CALL_NEAR, push(0), push(0), lea_esp_reserve, _store(4, 0), _STORE_ECX_AT_ESP,
                     call_method(SET_RENDER_STATE)))

        assert _found_calls(code, PRESENT) == [code.calls["padded"]]
        assert _found_calls(code, SET_RENDER_STATE) == [code.calls["reserved"]]

    def test_offset_the_interface_has_no_method_at_is_not_counted(self):
        beyond_the_constant_table = 0x6C
        code = Code().add("unknown_method", _CALL_NEAR, PUSH_ECX, call_method(beyond_the_constant_table))

        assert calls.scan_vtable_calls(code.data, TEXT_VA, beyond_the_constant_table, calls.D3DX_CONSTANT_TABLE) == [
            (code.calls["unknown_method"], "edx")]

    def test_d3dx_scan_counts_the_d3dx_method_parameters(self):
        # slot 0x5C is CreateTexture (8 parameters) on the device, SetMatrixPointerArray (4) on the constant table
        code = Code().add("set_matrices", push(4), PUSH_EAX, push(0), PUSH_EAX, PUSH_ECX,
                          call_method(CREATE_TEXTURE))

        assert calls.scan_vtable_calls(code.data, TEXT_VA, CREATE_TEXTURE, calls.D3DX_CONSTANT_TABLE) == [
            (code.calls["set_matrices"], "edx")]
        assert _found_calls(code, CREATE_TEXTURE) == []


_OTHER_GLOBAL = 0x9D9200
_HIGH_SLOT_METHODS = sorted(offset for offset in calls.DEVICE if offset >= calls.DEVICE_LOW_SLOT_END)
_LOAD_FIELD_OF_THIS = bytes([0x8B, 0x49, 0x3C, 0x8B, 0x11])     # mov ecx, [ecx+0x3C] / mov edx, [ecx]


def _device_methods(count: int, start: int = 0) -> dict[int, int]:
    """*count* device methods from vtable+0x80 on, from the *start*-th: {offset: parameter count}."""
    return {offset: calls.DEVICE[offset] for offset in _HIGH_SLOT_METHODS[start:start + count]}


_DRAW_PRIMITIVE = {0x144: 3}


def _present_hits(code: Code) -> calls.DeviceHits:
    hits = calls.scan_vtable_calls(code.data, TEXT_VA, PRESENT)
    return calls.split_device_hits(code.data, TEXT_VA, PRESENT, hits)


def _present_on(object_and_vtable: bytes) -> tuple[bytes, ...]:
    return object_and_vtable, *_NO_PRESENT_ARGUMENTS, PUSH_ECX, call_method(PRESENT)


class TestDeviceProvenance:
    """A call below vtable+0x80 is a device call when its object comes from where the calls above it get theirs."""

    _EVIDENCE = {**_device_methods(11), **_DRAW_PRIMITIVE}

    def test_low_slot_call_on_the_device_global_is_confirmed(self):
        code = Code().add_com_calls(load_device(), self._EVIDENCE).add("present", *_present_on(load_device()))

        assert calls.device_origins(code.data, TEXT_VA) == {"[0x009D915C]"}
        assert _present_hits(code) == ([(code.calls["present"], "edx")], [])

    def test_same_slot_on_an_object_from_another_global_is_unconfirmed(self):
        code = (Code().add_com_calls(load_device(), self._EVIDENCE)
                .add("other", *_present_on(load_device(_OTHER_GLOBAL))))

        assert _present_hits(code) == ([], [(code.calls["other"], "edx")])

    def test_low_slot_call_with_arguments_under_an_inner_call_is_split_by_its_object(self):
        # push 0 x4 / call f / mov ecx, [g] / mov edx, [ecx] / push ecx / call [edx+0x44]
        def present_after_helper(global_va: int) -> tuple[bytes, ...]:
            return *_NO_PRESENT_ARGUMENTS, _CALL_NEAR, load_device(global_va), PUSH_ECX, call_method(PRESENT)
        code = (Code().add_com_calls(load_device(), self._EVIDENCE)
                .add("device", *present_after_helper(DEVICE_GLOBAL))
                .add("other", *present_after_helper(_OTHER_GLOBAL)))

        assert _present_hits(code) == ([(code.calls["device"], "edx")], [(code.calls["other"], "edx")])

    def test_later_call_through_a_kept_method_pointer_has_the_object_of_its_load(self):
        # mov eax, [g] / mov ecx, [eax] / mov esi, [ecx+0x44] / ... / call esi / ... / call esi
        load_present = bytes([0xA1]) + _DEVICE_GLOBAL + bytes([0x8B, 0x08, 0x8B, 0x71, PRESENT])
        call_esi = bytes([0xFF, 0xD6])
        code = Code().add("hoisted", load_present, *_NO_PRESENT_ARGUMENTS, PUSH_EAX, call_esi,
                          *_NO_PRESENT_ARGUMENTS, PUSH_EAX, call_esi)
        [_, later] = calls.scan_vtable_mov(code.data, TEXT_VA, PRESENT)

        assert later[0] == code.calls["hoisted"]
        assert calls.object_origin(code.data, TEXT_VA, later[0]) == "[0x009D915C]"

    def test_high_slot_calls_are_kept_whatever_their_object(self):
        code = Code().add_com_calls(load_device(_OTHER_GLOBAL), _device_methods(1))
        [offset] = _device_methods(1)
        hits = calls.scan_vtable_calls(code.data, TEXT_VA, offset)

        assert calls.split_device_hits(code.data, TEXT_VA, offset, hits).confirmed == hits != []

    def test_object_kept_in_a_preserved_register_across_calls(self):
        # mov esi, [g] / call f / mov eax, esi / mov ecx, [eax] / push eax / call [ecx+0x44]
        load_esi = bytes([0x8B, 0x35]) + _DEVICE_GLOBAL
        code = Code().add("copied", load_esi, _CALL_NEAR, bytes([0x8B, 0xC6]), bytes([0x8B, 0x08]),
                          *_NO_PRESENT_ARGUMENTS, PUSH_EAX, bytes([0xFF, 0x51, PRESENT]))

        assert calls.object_origin(code.data, TEXT_VA, code.calls["copied"]) == "[0x009D915C]"

    def test_object_in_a_register_a_call_clobbers_has_no_origin(self):
        # mov eax, [g] / call f / mov ecx, [eax] / push eax / call [ecx+0x44]
        load_eax = bytes([0xA1]) + _DEVICE_GLOBAL
        code = Code().add("clobbered", load_eax, _CALL_NEAR, bytes([0x8B, 0x08]),
                          *_NO_PRESENT_ARGUMENTS, PUSH_EAX, bytes([0xFF, 0x51, PRESENT]))

        assert calls.object_origin(code.data, TEXT_VA, code.calls["clobbered"]) is None

    def test_object_whose_low_byte_is_overwritten_has_no_origin(self):
        # mov ecx, [g] / mov cl, 0 / mov edx, [ecx] / push ecx / call [edx+0x44]
        load_then_overwrite_cl = bytes([0x8B, 0x0D]) + _DEVICE_GLOBAL + bytes([0xB1, 0x00, 0x8B, 0x11])
        code = Code().add("partly_overwritten", *_present_on(load_then_overwrite_cl))

        assert calls.object_origin(code.data, TEXT_VA, code.calls["partly_overwritten"]) is None

    def test_object_whose_low_byte_is_loaded_from_a_global_has_no_origin(self):
        # mov ecx, [ecx+0x3C] / mov cl, [g] / mov edx, [ecx] / push ecx / call [edx+0x44]
        load_cl_from_global = bytes([0x8B, 0x49, 0x3C, 0x8A, 0x0D]) + _DEVICE_GLOBAL + bytes([0x8B, 0x11])
        code = Code().add("low_byte", *_present_on(load_cl_from_global))

        assert calls.object_origin(code.data, TEXT_VA, code.calls["low_byte"]) is None

    def test_object_in_a_field_of_a_global_object(self):
        # mov eax, [g] / mov ecx, [eax+0x1C] / mov edx, [ecx] / push ecx / call [edx+0x44]
        load_field_of_global = bytes([0xA1]) + _DEVICE_GLOBAL + bytes([0x8B, 0x48, 0x1C, 0x8B, 0x11])
        code = Code().add("field", *_present_on(load_field_of_global))

        assert calls.object_origin(code.data, TEXT_VA, code.calls["field"]) == "[[0x009D915C]+0x1C]"

    def test_device_in_a_field_of_this_teaches_no_origin(self):
        code = (Code().add_com_calls(_LOAD_FIELD_OF_THIS, self._EVIDENCE)
                .add("present", *_present_on(_LOAD_FIELD_OF_THIS)))

        assert calls.device_origins(code.data, TEXT_VA) == frozenset()
        assert _present_hits(code) == ([], [(code.calls["present"], "edx")])
        assert "none learned" in calls.device_origin_summary(code.data, TEXT_VA)

    def test_a_global_object_beside_a_device_in_a_field_of_this_is_not_learned(self):
        # an ID3DXEffect in a global reaches past vtable+0x80 through many methods, none of them a draw
        code = (Code().add_com_calls(_LOAD_FIELD_OF_THIS, self._EVIDENCE)
                .add_com_calls(load_device(_OTHER_GLOBAL), _device_methods(20)))

        assert calls.device_origins(code.data, TEXT_VA) == frozenset()

    def test_an_object_nothing_is_drawn_with_is_not_learned(self):
        code = (Code().add_com_calls(load_device(), {**_device_methods(13), **_DRAW_PRIMITIVE})
                .add_com_calls(load_device(_OTHER_GLOBAL), _device_methods(13, start=13)))

        assert calls.device_origins(code.data, TEXT_VA) == {"[0x009D915C]"}

    def test_an_object_drawn_with_through_too_few_methods_is_not_learned(self):
        code = Code().add_com_calls(load_device(), {**_device_methods(10), **_DRAW_PRIMITIVE})

        assert calls.device_origins(code.data, TEXT_VA) == frozenset()

    def test_an_object_called_through_under_half_the_methods_of_the_device_is_not_learned(self):
        code = (Code().add_com_calls(load_device(), {**_device_methods(30), **_DRAW_PRIMITIVE})
                .add_com_calls(load_device(_OTHER_GLOBAL), self._EVIDENCE))

        assert calls.device_origins(code.data, TEXT_VA) == {"[0x009D915C]"}


class TestLoadBinary:
    def test_pe32_loads(self, tmp_path):
        path = write_pe32(tmp_path / "game.exe", Code().data)

        data, image_base, sections = dx9_pe.load_binary(path)

        assert image_base == 0x400000 and sections[0]["name"] == ".text"

    def test_64_bit_binary_is_refused(self, tmp_path):
        path = write_pe32_plus(tmp_path / "game64.exe", Code().data)

        with pytest.raises(SystemExit) as refusal:
            dx9_pe.load_binary(path)

        assert "64-bit" in str(refusal.value)

    def test_section_table_cut_short_is_refused(self, tmp_path):
        path = write_pe32(tmp_path / "cut.exe", Code().data)
        path.write_bytes(path.read_bytes()[:0x140])                 # the .text header starts at 0x138

        with pytest.raises(SystemExit) as refusal:
            dx9_pe.load_binary(path)

        assert "cut.exe" in str(refusal.value) and "section table" in str(refusal.value)

    def test_missing_file_is_refused(self, tmp_path):
        with pytest.raises(SystemExit) as refusal:
            dx9_pe.load_binary(tmp_path / "absent.exe")

        assert "absent.exe" in str(refusal.value) and "No such file" in str(refusal.value)

    def test_file_that_is_not_a_pe_is_refused(self, tmp_path):
        path = tmp_path / "notes.txt"
        path.write_text("not a program")

        with pytest.raises(SystemExit) as refusal:
            dx9_pe.load_binary(path)

        assert "not a PE" in str(refusal.value)
