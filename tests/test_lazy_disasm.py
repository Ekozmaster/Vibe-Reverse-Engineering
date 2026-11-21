"""Capstone decodes only what the caller needs, in bounded amounts.

Capstone decodes everything one disasm call asks for before the first
instruction reaches Python, so a lazy Python iterator over a large buffer
still pays for the whole buffer. These tests count what the C decoder
itself was handed and returned, not what Python iterated over.
"""

import random

import capstone
import pytest
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

from pe_fakes import CODE_VA, binary_over

import common
from cfg import build_cfg
from funcinfo import analyze
from sigdb import _estimate_func_size

# push ebp; mov ebp, esp; pop ebp; ret; then padding and unrelated code
_SMALL_FUNCTION = bytes([0x55, 0x8B, 0xEC, 0x5D, 0xC3])
_SMALL_FUNCTION_INSNS = 4
_AFTER_FUNCTION = bytes([0xCC] * 4) + bytes([0x90] * 0x3000)


class _DecoderLog:
    """Every capstone decode call: bytes handed to it and instructions it returned."""

    def __init__(self):
        self.calls: list[tuple[int, int]] = []

    @property
    def decoded(self) -> int:
        return sum(count for _size, count in self.calls)

    @property
    def largest_input(self) -> int:
        return max(size for size, _count in self.calls)


@pytest.fixture
def decoder_log(monkeypatch):
    log = _DecoderLog()
    real = capstone._cs.cs_disasm

    def counting_cs_disasm(handle, code, size, offset, count, insns):
        decoded = real(handle, code, size, offset, count, insns)
        log.calls.append((size, decoded))
        return decoded

    monkeypatch.setattr(capstone._cs, "cs_disasm", counting_cs_disasm)
    return log


class TestBinaryDisasm:
    def test_decodes_only_the_requested_instructions(self, decoder_log):
        insns = binary_over(bytes([0x90] * 0x400)).disasm(CODE_VA, count=5, max_bytes=0x400)
        assert len(insns) == 5
        assert decoder_log.decoded == 5

    def test_zero_count_returns_nothing(self, decoder_log):
        assert binary_over(bytes([0x90] * 0x40)).disasm(CODE_VA, count=0) == []
        assert decoder_log.decoded == 0


class TestIterDisasm:
    def test_first_instruction_decodes_one_batch(self, decoder_log):
        first = next(iter(binary_over(bytes([0x90] * 0x400)).iter_disasm(CODE_VA, max_bytes=0x400)))
        assert first.address == CODE_VA
        assert decoder_log.decoded <= common._ITER_BATCH_INSNS

    def test_decodes_across_batches_up_to_the_first_non_instruction(self):
        nops = 3 * common._ITER_BATCH_INSNS + 5
        b = binary_over(bytes([0x90] * nops) + bytes([0xFF] * 0x40))
        insns = list(b.iter_disasm(CODE_VA, max_bytes=0x200))
        assert [insn.address for insn in insns] == [CODE_VA + i for i in range(nops)]


class TestFunctionExtentHelpers:
    def test_size_estimate_stops_at_the_function_end(self, decoder_log):
        b = binary_over(_SMALL_FUNCTION + _AFTER_FUNCTION)
        assert _estimate_func_size(b, CODE_VA) == len(_SMALL_FUNCTION)
        assert decoder_log.decoded <= common._ITER_BATCH_INSNS

    def test_cfg_stops_at_the_function_end(self, decoder_log):
        b = binary_over(_SMALL_FUNCTION + _AFTER_FUNCTION)
        blocks, _edges = build_cfg(b, CODE_VA)
        assert sum(len(insns) for insns in blocks.values()) == _SMALL_FUNCTION_INSNS
        assert decoder_log.decoded <= common._ITER_BATCH_INSNS

    def test_funcinfo_stops_at_the_function_end(self, decoder_log):
        b = binary_over(_SMALL_FUNCTION + _AFTER_FUNCTION)
        rets, _calls, end_va = analyze(b, CODE_VA, 0x2000)
        assert [addr for addr, _cleanup in rets] == [CODE_VA + 4]
        assert end_va == CODE_VA + len(_SMALL_FUNCTION)
        assert decoder_log.decoded <= common._ITER_BATCH_INSNS


class TestSweepBatches:
    def test_each_decode_call_is_bounded(self, decoder_log):
        code = bytes([0x90] * (4 * common._SWEEP_BATCH_INSNS + 7))
        swept = sum(1 for _ in binary_over(code).sweep())
        assert swept == len(code)
        assert len(decoder_log.calls) > 4
        assert decoder_log.largest_input <= common._SWEEP_BATCH_INSNS * common._MAX_INSN_LEN
        assert decoder_log.decoded == len(code)  # nothing is decoded twice

    @pytest.mark.parametrize("seed", range(5))
    def test_batches_decode_what_one_whole_buffer_call_does(self, seed, monkeypatch):
        code = random.Random(seed).randbytes(0x3000)
        whole = Cs(CS_ARCH_X86, CS_MODE_32)
        whole.detail = True
        whole.skipdata = True
        expected = [(i.address, bytes(i.bytes)) for i in whole.disasm(code, CODE_VA) if i.id]

        monkeypatch.setattr(common, "_SWEEP_BATCH_INSNS", 7)
        batched = [(i.address, bytes(i.bytes)) for i in common.sweep_code(code, CODE_VA, False)]

        assert batched == expected

    def test_data_longer_than_a_batch_is_stepped_over(self, monkeypatch):
        monkeypatch.setattr(common, "_SWEEP_BATCH_INSNS", 8)
        code = bytes([0xFF] * 100) + bytes([0x90])
        assert [i.address for i in common.sweep_code(code, CODE_VA, False)] == [CODE_VA + 100]
