"""Decoding stops when the caller has what it asked for.

Function-level helpers look at a window of up to 16 KB after a function
start. Decoding that whole window for every function is what made bulk
signature scans slow, so these tests pin the amount of decoding, not only
the results.
"""

from pe_fakes import CODE_VA, binary_over

from cfg import build_cfg
from common import Binary
from funcinfo import analyze
from sigdb import _estimate_func_size

# push ebp; mov ebp, esp; pop ebp; ret; then padding and unrelated code
_SMALL_FUNCTION = bytes([0x55, 0x8B, 0xEC, 0x5D, 0xC3])
_SMALL_FUNCTION_INSNS = 4
_AFTER_FUNCTION = bytes([0xCC] * 4) + bytes([0x90] * 0x3000)


class _CountingDisassembler:
    """Wraps a capstone handle and counts the instructions it hands out."""

    def __init__(self, cs):
        self._cs = cs
        self.decoded = 0

    def disasm(self, code, offset, count=0):
        for insn in self._cs.disasm(code, offset, count):
            self.decoded += 1
            yield insn


def _binary_over(code: bytes) -> Binary:
    """A Binary over *code* that counts how many instructions get decoded."""
    b = binary_over(code)
    b._cs = _CountingDisassembler(b._cs)
    return b


class TestBinaryDisasm:
    def test_decodes_only_the_requested_instructions(self):
        b = _binary_over(bytes([0x90] * 0x400))
        insns = b.disasm(CODE_VA, count=5, max_bytes=0x400)
        assert len(insns) == 5
        assert b._cs.decoded == 5

    def test_zero_count_returns_nothing(self):
        b = _binary_over(bytes([0x90] * 0x40))
        assert b.disasm(CODE_VA, count=0) == []

    def test_iter_disasm_is_lazy(self):
        b = _binary_over(bytes([0x90] * 0x400))
        first = next(iter(b.iter_disasm(CODE_VA, max_bytes=0x400)))
        assert first.address == CODE_VA
        assert b._cs.decoded == 1


class TestFunctionExtentHelpers:
    def test_size_estimate_stops_at_the_function_end(self):
        b = _binary_over(_SMALL_FUNCTION + _AFTER_FUNCTION)
        assert _estimate_func_size(b, CODE_VA) == len(_SMALL_FUNCTION)
        assert b._cs.decoded <= _SMALL_FUNCTION_INSNS + 2

    def test_cfg_stops_at_the_function_end(self):
        b = _binary_over(_SMALL_FUNCTION + _AFTER_FUNCTION)
        blocks, _edges = build_cfg(b, CODE_VA)
        assert sum(len(insns) for insns in blocks.values()) == _SMALL_FUNCTION_INSNS
        assert b._cs.decoded <= _SMALL_FUNCTION_INSNS + 2

    def test_funcinfo_stops_at_the_function_end(self):
        b = _binary_over(_SMALL_FUNCTION + _AFTER_FUNCTION)
        rets, _calls, end_va = analyze(b, CODE_VA, 0x2000)
        assert [addr for addr, _cleanup in rets] == [CODE_VA + 4]
        assert end_va == CODE_VA + len(_SMALL_FUNCTION)
        assert b._cs.decoded <= _SMALL_FUNCTION_INSNS + 2
