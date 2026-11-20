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
    DEVICE_GLOBAL, PUSH_EAX, PUSH_ECX, PUSH_ESI, TEXT_VA, Code, call_method, load_device, push, push32,
    write_pe32, write_pe32_plus,
)

SET_RENDER_STATE = 0xE4
SET_TRANSFORM = 0xB0
SET_VS_CONSTANT_F = 0x178
CREATE_TEXTURE = 0x5C
PRESENT = 0x44

_CALL_NEAR = bytes([0xE8, 0, 0, 0, 0])
_NO_PRESENT_ARGUMENTS = (push(0), push(0), push(0), push(0))
_CALL_EAX = bytes([0xFF, 0xD0])
_TEST_EAX = bytes([0x85, 0xC0])
_STORE_ECX_AT_ESP = bytes([0x89, 0x0C, 0x24])           # mov [esp], ecx


def _store(disp: int, value: int) -> bytes:
    """``mov dword ptr [esp+disp], imm32``."""
    return bytes([0xC7, 0x44, 0x24, disp]) + value.to_bytes(4, "little")


def _jump_if_equal_over(*chunks: bytes) -> bytes:
    """``je`` to the first byte after *chunks*, then *chunks*."""
    skipped = b"".join(chunks)
    return bytes([0x74, len(skipped)]) + skipped


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


class TestArgumentsStoredOnTheStack:
    def test_stores_into_reserved_space_are_the_arguments(self):
        sub_esp_12 = bytes([0x83, 0xEC, 0x0C])
        code = Code().add("stored", sub_esp_12, _store(8, 1), _store(4, 22), _STORE_ECX_AT_ESP,
                          call_method(SET_RENDER_STATE))

        args = dx.method_args(code.data, TEXT_VA, code.calls["stored"], "SetRenderState")

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

        assert dx.method_immediates(code.data, TEXT_VA, load_va, "SetRenderState") == {
            "this": None, "State": None, "Value": None}


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
        code = (Code().add("short", *_NO_PRESENT_ARGUMENTS, PUSH_ECX, call_method(PRESENT, short=True))
                .add("long", *_NO_PRESENT_ARGUMENTS, PUSH_ECX, call_method(PRESENT)))

        found = dx.scan_vtable_calls(code.data, TEXT_VA, PRESENT)

        assert found == [(code.calls["short"], "edx"), (code.calls["long"], "edx")]

    def test_finds_a_call_through_ebp(self):
        through_ebp = bytes([0xFF, 0x95]) + (SET_RENDER_STATE).to_bytes(4, "little")   # call [ebp+0xE4]
        code = Code().add("ebp", push(1), push(22), PUSH_ECX, through_ebp)

        assert dx.scan_vtable_calls(code.data, TEXT_VA, SET_RENDER_STATE) == [(code.calls["ebp"], "ebp")]


class TestMethodPointerLoadScan:
    def test_finds_the_short_and_the_long_form_below_slot_32(self):
        load_short = bytes([0x8B, 0x42, PRESENT])                                  # mov eax, [edx+0x44]
        load_long = bytes([0x8B, 0x8E]) + PRESENT.to_bytes(4, "little")            # mov ecx, [esi+0x44]
        code = (Code().add("short", *_NO_PRESENT_ARGUMENTS, load_short, PUSH_ECX, _CALL_EAX)
                .add("long", *_NO_PRESENT_ARGUMENTS, load_long, PUSH_ECX, bytes([0xFF, 0xD1])))
        short_va = code.calls["short"] - len(PUSH_ECX) - len(load_short)
        long_va = code.calls["long"] - len(PUSH_ECX) - len(load_long)

        assert dx.scan_vtable_mov(code.data, TEXT_VA, PRESENT) == [
            (short_va, "mov eax, [edx+0x044]"), (long_va, "mov ecx, [esi+0x044]")]

    def test_short_form_load_leads_to_the_arguments_of_its_call(self):
        load_short = bytes([0x8B, 0x42, CREATE_TEXTURE])                           # mov eax, [edx+0x5C]
        code = Code().add("texture", push(0), PUSH_EAX, push(1), push(21), push(0), push(1),
                          push32(128), push32(256), load_short, PUSH_ECX, _CALL_EAX)
        [(load_va, _)] = dx.scan_vtable_mov(code.data, TEXT_VA, CREATE_TEXTURE)

        pushed = dx.method_immediates(code.data, TEXT_VA, load_va, "CreateTexture")

        assert (pushed["Width"], pushed["Height"], pushed["Format"]) == (256, 128, 21)

    def test_slots_from_32_on_have_no_short_form(self):
        load_short = bytes([0x8B, 0x42, 0x80])                                     # mov eax, [edx-0x80]
        code = Code().add("negative", load_short, PUSH_ECX, _CALL_EAX)

        assert dx.scan_vtable_mov(code.data, TEXT_VA, 0x80) == []

    def test_a_conditional_jump_between_load_and_call_is_passed_by_its_fall_through(self):
        set_sampler_state = 0x114
        load_method = bytes([0x8B, 0x91]) + set_sampler_state.to_bytes(4, "little")  # mov edx, [ecx+0x114]
        call_edx = bytes([0xFF, 0xD2])
        jump_past_call = bytes([0x75, len(push(2) * 3 + PUSH_EAX + call_edx)])     # jne past the call
        code = Code().add("tested", load_method, _TEST_EAX, jump_past_call,
                          push(2), push(7), push(0), PUSH_EAX, call_edx)
        [(load_va, _)] = dx.scan_vtable_mov(code.data, TEXT_VA, set_sampler_state)

        assert dx.method_immediates(code.data, TEXT_VA, load_va, "SetSamplerState") == {
            "this": None, "Sampler": 0, "Type": 7, "Value": 2}

    def test_a_field_read_that_is_not_called_is_not_a_method_pointer_load(self):
        read_field = bytes([0x8B, 0x46, PRESENT])                                  # mov eax, [esi+0x44]
        code = Code().add("field", read_field, PUSH_EAX, _CALL_NEAR)

        assert dx.scan_vtable_mov(code.data, TEXT_VA, PRESENT) == []


_DEVICE_GLOBAL = DEVICE_GLOBAL.to_bytes(4, "little")
_LOAD_VTABLE_FROM_ESI = bytes([0x8B, 0x06])             # mov eax, [esi]
_LOAD_VTABLE_FROM_ECX = bytes([0x8B, 0x01])             # mov eax, [ecx]
_CALL_PRESENT_THROUGH_EAX = bytes([0xFF, 0x50, PRESENT])  # call [eax+0x44]
_PUSH_EDX = bytes([0x52])
_PUSH_EDI = bytes([0x57])
_MOV_ECX_ESI = bytes([0x8B, 0xCE])


def _found_calls(code: Code, offset: int) -> list[int]:
    return [va for va, _reg in dx.scan_vtable_calls(code.data, TEXT_VA, offset)]


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

    def test_this_the_code_does_not_show_keeps_the_call(self):
        code = Code().add("unsettled", _CALL_NEAR, _LOAD_VTABLE_FROM_ESI, *_NO_PRESENT_ARGUMENTS, _PUSH_EDI,
                          _CALL_PRESENT_THROUGH_EAX)

        assert _found_calls(code, PRESENT) == [code.calls["unsettled"]]

    def test_method_pointer_form(self):
        load_vtable = bytes([0x8B, 0x11])                       # mov edx, [ecx]
        load_method = bytes([0x8B, 0x52, CREATE_TEXTURE])       # mov edx, [edx+0x5C]
        call_edx = bytes([0xFF, 0xD2])
        sizes = (push32(256), push32(128), push(1), push(0), push(21), push(1))
        code = (Code().add("com", *sizes, load_vtable, load_method, push(0), PUSH_EAX, PUSH_ECX, call_edx)
                .add("thiscall", *sizes, load_vtable, load_method, push(0), PUSH_EAX, call_edx))
        com_load = code.calls["com"] - len(push(0) + PUSH_EAX + PUSH_ECX) - len(load_method)

        assert [va for va, _ in dx.scan_vtable_mov(code.data, TEXT_VA, CREATE_TEXTURE)] == [com_load]

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

    def test_too_few_pushes_after_an_earlier_call_is_dropped(self):
        code = (Code().add("short", _CALL_NEAR, push(0), PUSH_ECX, call_method(PRESENT))
                .add("full", _CALL_NEAR, *_NO_PRESENT_ARGUMENTS, PUSH_ECX, call_method(PRESENT)))

        assert _found_calls(code, PRESENT) == [code.calls["full"]]

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

    def test_offset_the_interface_has_no_method_at_is_not_counted(self):
        beyond_the_constant_table = 0x6C
        code = Code().add("unknown_method", _CALL_NEAR, PUSH_ECX, call_method(beyond_the_constant_table))

        assert dx.scan_vtable_calls(code.data, TEXT_VA, beyond_the_constant_table, dx.D3DX_CONSTANT_TABLE) == [
            (code.calls["unknown_method"], "edx")]

    def test_d3dx_scan_counts_the_d3dx_method_parameters(self):
        # slot 0x5C is CreateTexture (8 parameters) on the device, SetMatrixPointerArray (4) on the constant table
        code = Code().add("set_matrices", _CALL_NEAR, push(4), PUSH_EAX, push(0), PUSH_EAX, PUSH_ECX,
                          call_method(CREATE_TEXTURE))

        assert dx.scan_vtable_calls(code.data, TEXT_VA, CREATE_TEXTURE, dx.D3DX_CONSTANT_TABLE) == [
            (code.calls["set_matrices"], "edx")]
        assert _found_calls(code, CREATE_TEXTURE) == []


_OTHER_GLOBAL = 0x9D9200
_HIGH_SLOT_METHODS = sorted(offset for offset in dx.DEVICE if offset >= dx.DEVICE_LOW_SLOT_END)
_LOAD_FIELD_OF_THIS = bytes([0x8B, 0x49, 0x3C, 0x8B, 0x11])     # mov ecx, [ecx+0x3C] / mov edx, [ecx]


def _device_methods(count: int, start: int = 0) -> dict[int, int]:
    """*count* device methods from vtable+0x80 on, from the *start*-th: {offset: parameter count}."""
    return {offset: dx.DEVICE[offset] for offset in _HIGH_SLOT_METHODS[start:start + count]}


def _present_hits(code: Code) -> dx.DeviceHits:
    hits = dx.scan_vtable_calls(code.data, TEXT_VA, PRESENT)
    return dx.split_device_hits(code.data, TEXT_VA, PRESENT, hits)


def _present_on(object_and_vtable: bytes) -> tuple[bytes, ...]:
    return object_and_vtable, *_NO_PRESENT_ARGUMENTS, PUSH_ECX, call_method(PRESENT)


class TestDeviceProvenance:
    """A call below vtable+0x80 is a device call when its object comes from where the calls above it get theirs."""

    _EVIDENCE = _device_methods(12)

    def test_low_slot_call_on_the_device_global_is_confirmed(self):
        code = Code().add_com_calls(load_device(), self._EVIDENCE).add("present", *_present_on(load_device()))

        assert dx.device_origins(code.data, TEXT_VA) == {"[0x009D915C]"}
        assert _present_hits(code) == ([(code.calls["present"], "edx")], [])

    def test_same_slot_on_an_object_from_another_global_is_unconfirmed(self):
        code = (Code().add_com_calls(load_device(), self._EVIDENCE)
                .add("other", *_present_on(load_device(_OTHER_GLOBAL))))

        assert _present_hits(code) == ([], [(code.calls["other"], "edx")])

    def test_high_slot_calls_are_kept_whatever_their_object(self):
        code = Code().add_com_calls(load_device(_OTHER_GLOBAL), _device_methods(1))
        [offset] = _device_methods(1)
        hits = dx.scan_vtable_calls(code.data, TEXT_VA, offset)

        assert dx.split_device_hits(code.data, TEXT_VA, offset, hits).confirmed == hits != []

    def test_object_kept_in_a_preserved_register_across_calls(self):
        # mov esi, [g] / call f / mov eax, esi / mov ecx, [eax] / push eax / call [ecx+0x44]
        load_esi = bytes([0x8B, 0x35]) + _DEVICE_GLOBAL
        code = Code().add("copied", load_esi, _CALL_NEAR, bytes([0x8B, 0xC6]), bytes([0x8B, 0x08]),
                          *_NO_PRESENT_ARGUMENTS, PUSH_EAX, bytes([0xFF, 0x51, PRESENT]))

        assert dx.object_origin(code.data, TEXT_VA, code.calls["copied"]) == "[0x009D915C]"

    def test_object_in_a_register_a_call_clobbers_has_no_origin(self):
        # mov eax, [g] / call f / mov ecx, [eax] / push eax / call [ecx+0x44]
        load_eax = bytes([0xA1]) + _DEVICE_GLOBAL
        code = Code().add("clobbered", load_eax, _CALL_NEAR, bytes([0x8B, 0x08]),
                          *_NO_PRESENT_ARGUMENTS, PUSH_EAX, bytes([0xFF, 0x51, PRESENT]))

        assert dx.object_origin(code.data, TEXT_VA, code.calls["clobbered"]) is None

    def test_object_in_a_field_of_a_global_object(self):
        # mov eax, [g] / mov ecx, [eax+0x1C] / mov edx, [ecx] / push ecx / call [edx+0x44]
        load_field_of_global = bytes([0xA1]) + _DEVICE_GLOBAL + bytes([0x8B, 0x48, 0x1C, 0x8B, 0x11])
        code = Code().add("field", *_present_on(load_field_of_global))

        assert dx.object_origin(code.data, TEXT_VA, code.calls["field"]) == "[[0x009D915C]+0x1C]"

    def test_device_in_a_field_of_this_teaches_no_origin(self):
        code = (Code().add_com_calls(_LOAD_FIELD_OF_THIS, self._EVIDENCE)
                .add("present", *_present_on(_LOAD_FIELD_OF_THIS)))

        assert dx.device_origins(code.data, TEXT_VA) == frozenset()
        assert _present_hits(code) == ([], [(code.calls["present"], "edx")])
        assert "none learned" in dx.device_origin_summary(code.data, TEXT_VA)

    def test_a_global_object_beside_a_device_in_a_field_of_this_is_not_learned(self):
        # an ID3DXEffect in a global reaches past vtable+0x80 through a few methods
        code = (Code().add_com_calls(_LOAD_FIELD_OF_THIS, self._EVIDENCE)
                .add_com_calls(load_device(_OTHER_GLOBAL), _device_methods(9)))

        assert dx.device_origins(code.data, TEXT_VA) == frozenset()

    def test_an_object_called_through_under_half_the_methods_of_the_device_is_not_learned(self):
        code = (Code().add_com_calls(load_device(), _device_methods(26))
                .add_com_calls(load_device(_OTHER_GLOBAL), _device_methods(12, start=26)))

        assert dx.device_origins(code.data, TEXT_VA) == {"[0x009D915C]"}


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
