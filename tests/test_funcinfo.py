"""Tests for retools/funcinfo.py -- function extent, returns with stack cleanup, and callees."""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import funcinfo  # noqa: E402
from common import Binary  # noqa: E402
from pe_fakes import (DATA_RVA, IMAGE_BASE, TEXT_RVA, binary_from_sections, fake_section,  # noqa: E402
                      pe_image)

TEXT = IMAGE_BASE + TEXT_RVA
REPO = Path(__file__).resolve().parent.parent
MOV = bytes.fromhex("8b442404")          # mov eax, [esp + 4]: neither ret, call, nop nor int3


def _call(at: int, target: int) -> bytes:
    """call rel32 placed at text offset *at*, aimed at text offset *target*."""
    return b"\xE8" + struct.pack("<i", target - (at + 5))


def _binary(tmp_path, code: bytes) -> Binary:
    return Binary(str(pe_image(tmp_path / "a.exe", code)))


class TestReturns:
    def test_plain_ret_has_no_cleanup_and_ret_imm16_reports_its_bytes(self, tmp_path):
        code = MOV + b"\xC2\x10\x00" + MOV + b"\xC3"
        rets, calls, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 4, 0x10), (TEXT + 11, 0)]
        assert calls == []
        assert end == TEXT + 12

    def test_end_is_after_the_last_ret_including_its_imm16(self, tmp_path):
        code = b"\xC3" + MOV + b"\xC2\x0C\x00"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT, 0), (TEXT + 5, 0x0C)]
        assert end == TEXT + 8

    def test_small_cleanup_printed_in_decimal_by_the_disassembler(self, tmp_path):
        rets, _, end = funcinfo.analyze(_binary(tmp_path, b"\xC2\x08\x00"), TEXT, 0x100)
        assert rets == [(TEXT, 8)] and end == TEXT + 3

    def test_without_a_ret_the_end_is_after_the_last_instruction_before_the_padding(self, tmp_path):
        rets, _, end = funcinfo.analyze(_binary(tmp_path, MOV * 3), TEXT, 0x100)
        assert rets == [] and end == TEXT + 12


class TestCalls:
    def test_direct_calls_resolve_to_targets_and_indirect_keep_operand_text(self, tmp_path):
        code = bytearray(MOV * 0x10)
        code[0:5] = _call(0, 0x30)
        code[5:7] = b"\xFF\xD0"                                         # call eax
        code[7:13] = b"\xFF\x15" + struct.pack("<I", IMAGE_BASE + DATA_RVA)   # call [data]
        code[13:18] = _call(13, 0x30)
        code[18] = 0xC3
        rets, calls, _ = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert calls == [(TEXT, TEXT + 0x30), (TEXT + 5, "eax"),
                         (TEXT + 7, f"dword ptr [0x{IMAGE_BASE + DATA_RVA:x}]"), (TEXT + 13, TEXT + 0x30)]
        assert rets == [(TEXT + 18, 0)]

    def test_backward_call_target(self, tmp_path):
        code = bytearray(b"\xC3" + MOV * 8)
        code[0x10:0x15] = _call(0x10, 0)
        code[0x15] = 0xC3
        _, calls, _ = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT + 0x10, 0x100)
        assert calls == [(TEXT + 0x10, TEXT)]


class TestLongFunctions:
    def test_every_instruction_in_the_window_is_scanned(self, tmp_path):
        code = MOV * 0x40 + b"\xC3"                                    # 64 instructions before the ret
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x200)
        assert rets == [(TEXT + 0x100, 0)] and end == TEXT + 0x101


class TestScanStops:
    def test_nop_padding_after_a_ret_ends_the_function(self, tmp_path):
        code = MOV + b"\xC3" + b"\x90" * 8 + _call(13, 0x40) + b"\xC3"
        rets, calls, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 4, 0)] and calls == [] and end == TEXT + 5

    def test_multibyte_nop_padding_after_a_ret_ends_the_function(self, tmp_path):
        code = b"\xC3" + bytes.fromhex("0f1f4000") * 4 + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT, 0)] and end == TEXT + 1

    def test_nops_before_any_ret_do_not_end_the_function(self, tmp_path):
        code = b"\x90" * 8 + MOV + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 12, 0)] and end == TEXT + 13

    def test_scattered_nops_after_a_ret_are_not_padding(self, tmp_path):
        code = b"\xC3" + (b"\x90" + MOV) * 4 + b"\xC2\x04\x00"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT, 0), (TEXT + 21, 4)] and end == TEXT + 24

    def test_single_nops_between_calls_and_rets_are_not_padding(self, tmp_path):
        code = bytearray(b"\xC3")
        for _ in range(3):
            code += b"\x90" + _call(len(code) + 1, 0x80)
        for _ in range(3):
            code += b"\x90\xC3"
        code += MOV + b"\xC2\x04\x00"
        rets, calls, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert len(calls) == 3
        assert rets == [(TEXT, 0), (TEXT + 20, 0), (TEXT + 22, 0), (TEXT + 24, 0), (TEXT + 29, 4)]
        assert end == TEXT + 32

    def test_int3_padding_ends_the_function(self, tmp_path):
        code = MOV + b"\xC3" + b"\xCC" + _call(6, 0x40) + b"\xC3"
        rets, calls, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 4, 0)] and calls == [] and end == TEXT + 5

    def test_int3_that_no_branch_jumps_past_ends_the_scan_even_before_any_ret(self, tmp_path):
        code = _call(0, 0x40) + b"\xCC" + b"\xC3"
        rets, calls, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert calls == [(TEXT, TEXT + 0x40)] and rets == [] and end == TEXT + 5

    def test_int3_after_a_noreturn_call_that_a_branch_jumps_past_does_not_end_the_scan(self, tmp_path):
        # je over / call noreturn / int3 / over: ret / int3 padding / the next function: ret
        code = b"\x74\x06" + _call(2, 0x40) + b"\xCC" + b"\xC3" + b"\xCC" * 4 + b"\xC3"
        rets, calls, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 8, 0)] and calls == [(TEXT + 2, TEXT + 0x40)] and end == TEXT + 9

    def test_int3_padding_ends_the_scan_although_a_branch_jumps_past_it_to_another_function(self, tmp_path):
        # je tail_call / ret / int3 padding / the next function: ret
        code = b"\x74\x05" + b"\xC3" + b"\xCC" * 4 + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 2, 0)] and end == TEXT + 3

    def test_int3_padding_after_a_tail_jump_ends_the_scan(self, tmp_path):
        # je other / jmp other / int3 padding / other function: ret
        code = b"\x74\x06" + b"\xEB\x04" + b"\xCC" * 4 + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [] and end == TEXT + 4

    def test_branch_past_an_int3_to_another_known_function_does_not_carry_the_scan_over_it(self, tmp_path):
        # je over / jmp far (tail call) / over: call noreturn / int3 padding / the next function / far: ret
        code = bytearray(b"\xCC" * 0x101)
        code[0:2] = b"\x85\xC0"                                         # test eax, eax
        code[2:4] = b"\x74\x05"                                         # je +9
        code[4:9] = b"\xE9" + struct.pack("<i", 0x100 - 9)              # jmp +0x100
        code[9:14] = _call(9, 0x40)
        code[16:20] = b"\x55\x33\xC0\xC3"                               # push ebp / xor eax, eax / ret
        code[0x100] = 0xC3
        rets, calls, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x200)
        assert rets == [] and calls == [(TEXT + 9, TEXT + 0x40)] and end == TEXT + 14

    def test_x64_branch_past_an_int3_to_another_function_of_the_exception_table(self):
        # je over / jmp far (tail call) / over: call far / int3 padding / next: xor eax, eax; ret / far: ret
        text_rva, pdata_rva, xdata_rva = 0x1000, 0x2000, 0x3000
        text = bytearray(b"\xCC" * 0x41)
        text[0:2] = b"\x85\xC0"
        text[2:4] = b"\x74\x05"
        text[4:9] = b"\xE9" + struct.pack("<i", 0x40 - 9)
        text[9:14] = _call(9, 0x40)
        text[0x10:0x13] = b"\x33\xC0\xC3"
        text[0x40] = 0xC3
        xdata = bytes([0x01, 0, 0, 0])                                  # version 1, no flags, no unwind codes
        pdata = b"".join(struct.pack("<III", text_rva + begin, text_rva + end, xdata_rva)
                         for begin, end in [(0, 0x0E), (0x10, 0x13), (0x40, 0x41)])
        sections = [fake_section(text_rva, len(text), 0, len(text), executable=True),
                    fake_section(pdata_rva, len(pdata), len(text), len(pdata)),
                    fake_section(xdata_rva, len(xdata), len(text) + len(pdata), len(xdata))]
        b = binary_from_sections(bytes(text) + pdata + xdata, sections, is_64=True,
                                 exception_table=(pdata_rva, len(pdata)))
        rets, calls, end = funcinfo.analyze(b, TEXT, 0x100)
        assert rets == [] and calls == [(TEXT + 9, TEXT + 0x40)] and end == TEXT + 14

    def test_branch_to_a_later_label_of_the_same_function_carries_the_scan_over_an_int3(self, tmp_path):
        # caller of the function at +0x10, whose je jumps over a noreturn call and its int3
        code = bytearray(b"\xCC" * 0x40)
        code[0:6] = _call(0, 0x10) + b"\xC3"
        code[0x10:0x12] = b"\x74\x06"
        code[0x12:0x17] = _call(0x12, 0x30)
        code[0x18] = 0xC3
        code[0x30] = 0xC3
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT + 0x10, 0x100)
        assert rets == [(TEXT + 0x18, 0)] and end == TEXT + 0x19

    def test_bytes_behind_the_last_ret_that_no_branch_reaches_are_outside_the_function(self, tmp_path):
        # xor eax, eax / ret / lea ecx, [ecx] (alignment) / two jump-table pointers / int3
        table = struct.pack("<II", TEXT + 0x20, TEXT + 0x30)
        code = b"\x33\xC0" + b"\xC3" + b"\x8D\x49\x00" + table + b"\xCC"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 2, 0)] and end == TEXT + 3

    def test_bytes_behind_a_final_jump_that_no_branch_reaches_are_outside_the_function(self, tmp_path):
        # jmp eax / lea ecx, [ecx] / two jump-table pointers / int3
        table = struct.pack("<II", TEXT + 0x20, TEXT + 0x30)
        code = b"\xFF\xE0" + b"\x8D\x49\x00" + table + b"\xCC"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [] and end == TEXT + 2

    def test_code_behind_a_ret_that_a_branch_reaches_extends_the_function(self, tmp_path):
        # je over / ret / over: mov / jmp eax / int3
        code = b"\x74\x01" + b"\xC3" + MOV + b"\xFF\xE0" + b"\xCC"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 2, 0)] and end == TEXT + 9

    def test_the_next_known_function_bounds_the_scan_without_padding_between(self, tmp_path):
        # first: mov / ret, second (called from +0x20): mov / ret 4
        code = bytearray(b"\xCC" * 0x30)
        code[0:5] = MOV + b"\xC3"
        code[5:12] = MOV + b"\xC2\x04\x00"
        code[0x20:0x26] = _call(0x20, 5) + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert rets == [(TEXT + 4, 0)] and end == TEXT + 5

    def test_a_known_start_a_conditional_branch_jumps_past_lies_inside_the_function(self, tmp_path):
        # je +0x0C / mov / ret / label called from +0x20: mov / ret / je target: mov / ret 4
        code = bytearray(b"\xCC" * 0x30)
        code[0:2] = b"\x74\x0A"
        code[2:7] = MOV + b"\xC3"
        code[7:12] = MOV + b"\xC3"
        code[12:19] = MOV + b"\xC2\x04\x00"
        code[0x20:0x26] = _call(0x20, 7) + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert rets == [(TEXT + 6, 0), (TEXT + 11, 0), (TEXT + 16, 4)] and end == TEXT + 19

    def test_a_known_start_a_jump_passes_into_straight_line_code_lies_inside_the_function(self, tmp_path):
        # je +4 / jmp exit / mov / jmp label / label called from +0x30: mov / mov / exit: ret
        code = bytearray(b"\xCC" * 0x40)
        code[0:2] = b"\x74\x02"
        code[2:4] = b"\xEB\x0E"
        code[4:8] = MOV
        code[8:10] = b"\xEB\x00"
        code[10:18] = MOV + MOV
        code[18] = 0xC3
        code[0x30:0x36] = _call(0x30, 10) + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert rets == [(TEXT + 18, 0)] and end == TEXT + 19

    def test_a_jump_to_code_that_follows_a_function_end_is_a_tail_call(self, tmp_path):
        # je +4 / jmp other / mov / ret / next function, called from +0x30: mov / ret / other, not a known start: ret
        code = bytearray(b"\xCC" * 0x40)
        code[0:2] = b"\x74\x02"
        code[2:4] = b"\xEB\x0C"
        code[4:9] = MOV + b"\xC3"
        code[9:14] = MOV + b"\xC3"
        code[16] = 0xC3
        code[0x30:0x36] = _call(0x30, 9) + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert rets == [(TEXT + 8, 0)] and end == TEXT + 9

    def test_a_case_reached_only_through_the_jump_table_behind_the_last_ret_is_counted(self, tmp_path):
        # jmp [eax*4 + table] / case 0: mov / ret / case 1: mov / jmp eax / mov edi, edi / table / int3
        table = struct.pack("<II", TEXT + 7, TEXT + 12)
        code = (b"\xFF\x24\x85" + struct.pack("<I", TEXT + 20) + MOV + b"\xC3" + MOV + b"\xFF\xE0"
                + b"\x8B\xFF" + table + b"\xCC" * 8)
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 11, 0)] and end == TEXT + 18

    def test_a_jump_table_entry_outside_the_scan_window_ends_the_table(self, tmp_path):
        # jmp [eax*4 + table] / case 0: mov / jmp eax / mov edi, edi / nop / table of one case / a pointer elsewhere
        table = struct.pack("<II", TEXT + 7, TEXT + 0x1000)
        code = (b"\xFF\x24\x85" + struct.pack("<I", TEXT + 16) + MOV + b"\xFF\xE0" + b"\x8B\xFF\x90"
                + table + b"\xCC" * 8)
        _, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert end == TEXT + 13

    def test_a_function_right_behind_a_jump_table_that_no_branch_jumps_past_is_not_scanned(self, tmp_path):
        # jmp [eax*4 + table] / case 0: mov / ret / case 1: mov / jmp eax / table / another function: mov / ret
        table = struct.pack("<II", TEXT + 7, TEXT + 12)
        code = (b"\xFF\x24\x85" + struct.pack("<I", TEXT + 18) + MOV + b"\xC3" + MOV + b"\xFF\xE0"
                + table + MOV + b"\xC3" + b"\xCC" * 8)
        rets, _, end = funcinfo.analyze(_binary(tmp_path, code), TEXT, 0x100)
        assert rets == [(TEXT + 11, 0)] and end == TEXT + 18

    def test_jump_table_bytes_that_decode_as_a_jump_carry_the_scan_nowhere(self, tmp_path):
        # jmp [eax*4 + table] / movs / case at +0xEB: call noreturn / movs / table (EB 10 ..., 07 10 ...) /
        # int3 padding / the next function, called from +0x300: mov / mov / ret
        code = bytearray(b"\xCC" * 0x310)
        code[0:7] = b"\xFF\x24\x85" + struct.pack("<I", TEXT + 0x100)
        code[7:0xEB] = MOV * 57
        code[0xEB:0xF0] = _call(0xEB, 0x1F0)
        code[0xF0:0x100] = MOV * 4
        code[0x100:0x108] = struct.pack("<II", TEXT + 0xEB, TEXT + 7)
        code[0x110:0x119] = MOV + MOV + b"\xC3"
        code[0x300:0x306] = _call(0x300, 0x110) + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x200)
        assert rets == [] and end == TEXT + 0x100

    def test_live_code_that_runs_into_a_known_start_goes_on_through_it(self, tmp_path):
        # mov / mov eax, imm32 / ret: the imm32's last two bytes are called from +0x20
        code = bytearray(b"\xCC" * 0x30)
        code[0:4] = MOV
        code[4:9] = b"\xB8\x00\x00\x33\xC0"
        code[9] = 0xC3
        code[0x20:0x26] = _call(0x20, 7) + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert rets == [(TEXT + 9, 0)] and end == TEXT + 10

    def test_a_branch_target_read_from_bytes_behind_the_last_return_carries_the_scan_nowhere(self, tmp_path):
        # mov / ret / table bytes that decode as "loope +0x10" / the function called from +0x20
        code = bytearray(b"\xCC" * 0x30)
        code[0:5] = MOV + b"\xC3"
        code[5:7] = b"\xE1\x10"
        code[7:12] = MOV + b"\xC3"
        code[0x20:0x26] = _call(0x20, 7) + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert rets == [(TEXT + 4, 0)] and end == TEXT + 5

    def test_an_instruction_behind_a_return_running_into_the_next_known_function_is_not_decoded(self, tmp_path):
        # mov / ret / mov eax, imm32 whose last two bytes are the function called from +0x20
        code = bytearray(b"\xCC" * 0x30)
        code[0:4] = MOV
        code[4] = 0xC3
        code[5:10] = b"\xB8\x00\x00\x33\xC0"
        code[10] = 0xC3
        code[0x20:0x26] = _call(0x20, 8) + b"\xC3"
        rets, _, end = funcinfo.analyze(_binary(tmp_path, bytes(code)), TEXT, 0x100)
        assert rets == [(TEXT + 4, 0)] and end == TEXT + 5


class TestMaxSize:
    def test_scan_window_is_max_size_bytes(self, tmp_path):
        code = MOV * 4 + b"\xC3"                                        # ret at offset 16
        b = _binary(tmp_path, code)
        assert funcinfo.analyze(b, TEXT, 17)[0] == [(TEXT + 16, 0)]
        assert funcinfo.analyze(b, TEXT, 16)[0] == []

    def test_instruction_straddling_the_window_is_not_decoded(self, tmp_path):
        code = MOV * 4 + b"\xC2\x10\x00"                                # 3-byte ret at offset 16
        b = _binary(tmp_path, code)
        assert funcinfo.analyze(b, TEXT, 18)[0] == []
        assert funcinfo.analyze(b, TEXT, 19)[0] == [(TEXT + 16, 0x10)]


class TestFindStart:
    def test_nearest_call_target_at_or_before_the_address(self, tmp_path):
        code = bytearray(MOV * 0x20)
        code[0:5] = _call(0, 0x20)
        code[5:10] = _call(5, 0x40)
        b = _binary(tmp_path, bytes(code))
        assert funcinfo.find_start(b, TEXT + 0x30) == TEXT + 0x20
        assert funcinfo.find_start(b, TEXT + 0x40) == TEXT + 0x40
        assert funcinfo.find_start(b, TEXT + 0x10) is None


def _cli_image(tmp_path) -> Path:
    """Caller at +0 calls a function at +0x20 that makes two calls to +0x60, one to eax, then ret 8 and ret."""
    code = bytearray(MOV * 0x20)
    code[0:5] = _call(0, 0x20)
    code[0x20:0x25] = _call(0x20, 0x60)
    code[0x25:0x27] = b"\xFF\xD0"
    code[0x27:0x2C] = _call(0x27, 0x60)
    code[0x2C:0x2F] = b"\xC2\x10\x00"
    code[0x2F] = 0xC3
    code[0x30:0x34] = b"\x90" * 4
    code[0x60] = 0xC3
    return pe_image(tmp_path / "a.exe", bytes(code))


EXPECTED = [
    f"Function: 0x{TEXT + 0x20:08X} .. 0x{TEXT + 0x30:08X}  (16 bytes)",
    "",
    "Returns (2):",
    f"  0x{TEXT + 0x2C:08X}: ret 0x10    stdcall/thiscall  16 bytes = 4 stack args",
    f"  0x{TEXT + 0x2F:08X}: ret 0x0     cdecl/thiscall  0 stack args",
    "",
    "Callees (2):",
    f"  0x{TEXT + 0x60:08X}  (2x)",
    "  eax",
]


class TestCli:
    def _run(self, monkeypatch, capsys, *argv):
        monkeypatch.setattr(sys, "argv", ["funcinfo.py", *argv])
        funcinfo.main()
        return capsys.readouterr().out.splitlines()

    def test_address_inside_a_function_reports_the_whole_function(self, tmp_path, monkeypatch, capsys):
        path = _cli_image(tmp_path)
        assert self._run(monkeypatch, capsys, str(path), f"0x{TEXT + 0x27:X}") == EXPECTED

    def test_va_without_0x_prefix_is_hex(self, tmp_path, monkeypatch, capsys):
        path = _cli_image(tmp_path)
        assert self._run(monkeypatch, capsys, str(path), f"{TEXT + 0x20:X}") == EXPECTED

    def test_address_before_every_known_function_is_used_as_the_start(self, tmp_path, monkeypatch, capsys):
        path = pe_image(tmp_path / "a.exe", MOV + b"\xC3")
        out = self._run(monkeypatch, capsys, str(path), f"0x{TEXT:X}")
        assert out[0] == f"Function: 0x{TEXT:08X} .. 0x{TEXT + 5:08X}  (5 bytes)"
        assert out[2:] == ["Returns (1):", f"  0x{TEXT + 4:08X}: ret 0x0     cdecl/thiscall  0 stack args",
                           "", "Callees (0):"]

    def test_function_ending_in_a_tail_jump_contains_its_interior_addresses(self, tmp_path, monkeypatch, capsys):
        code = bytearray(b"\xCC" * 0x61)
        code[0:6] = _call(0, 0x20) + b"\xC3"
        code[0x20:0x28] = MOV * 2
        code[0x28:0x2D] = b"\xE9" + struct.pack("<i", 0x60 - 0x2D)       # jmp +0x60
        code[0x60] = 0xC3
        path = pe_image(tmp_path / "a.exe", bytes(code))
        out = self._run(monkeypatch, capsys, str(path), f"0x{TEXT + 0x24:X}")
        assert out[:3] == [f"Function: 0x{TEXT + 0x20:08X} .. 0x{TEXT + 0x2D:08X}  (13 bytes)", "", "Returns (0):"]

    @pytest.mark.parametrize("size, found", [("0x2C", False), ("0x2D", True), ("44", False), ("45", True), (None, True)])
    def test_max_size_bounds_the_scan(self, tmp_path, monkeypatch, capsys, size, found):
        """--max-size accepts hex or decimal; the 0x2000 default covers the whole function."""
        path = pe_image(tmp_path / "a.exe", MOV * 0xB + b"\xC3")          # ret at offset 0x2C
        extra = ["--max-size", size] if size else []
        out = self._run(monkeypatch, capsys, str(path), f"0x{TEXT:X}", *extra)
        assert (out[2] == "Returns (1):") is found

    def test_each_callee_listed_once_in_first_call_order(self, tmp_path, monkeypatch, capsys):
        code = bytearray(MOV * 0x20)
        code[0:5] = _call(0, 0x40)
        code[5:10] = _call(5, 0x40)
        code[10:12] = b"\xFF\xD0"
        code[12:17] = _call(12, 0x50)
        code[17] = 0xC3
        path = pe_image(tmp_path / "a.exe", bytes(code))
        out = self._run(monkeypatch, capsys, str(path), f"0x{TEXT:X}")
        assert out[out.index("Callees (3):") + 1:] == [f"  0x{TEXT + 0x40:08X}  (2x)", "  eax", f"  0x{TEXT + 0x50:08X}"]

    def test_script_runs_standalone(self, tmp_path):
        path = _cli_image(tmp_path)
        proc = subprocess.run([sys.executable, str(REPO / "retools" / "funcinfo.py"), str(path), f"0x{TEXT + 0x20:X}"],
                              capture_output=True, text=True, cwd=tmp_path, timeout=60)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.splitlines() == EXPECTED
