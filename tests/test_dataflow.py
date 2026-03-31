"""Tests for retools/dataflow.py -- value tracking and constant propagation."""

import sys
from pathlib import Path

import pytest
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestValueTypes:
    def test_const(self):
        from dataflow import Const
        v = Const(42)
        assert v.value == 42
        assert str(v) == "0x2a"

    def test_unknown(self):
        from dataflow import Unknown
        v = Unknown()
        assert str(v) == "?"

    def test_binop(self):
        from dataflow import BinOp, Const
        v = BinOp("+", Const(10), Const(20))
        assert v.op == "+"
        assert str(v) == "(0xa + 0x14)"

    def test_load(self):
        from dataflow import Load, Const
        v = Load(Const(0x7C0000), 0x10)
        assert v.offset == 0x10
        assert "0x10" in str(v)

    def test_arg(self):
        from dataflow import Arg
        v = Arg(0)
        assert v.index == 0
        assert "arg0" in str(v)


class TestForwardPropagation:
    def _disasm(self, code_bytes, va=0x401000):
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        return list(cs.disasm(code_bytes, va))

    def test_mov_immediate(self):
        """mov eax, 5 should resolve eax to Const(5)."""
        from dataflow import propagate_forward, Const
        # B8 05000000 = mov eax, 5
        insns = self._disasm(b"\xB8\x05\x00\x00\x00")
        state = propagate_forward(insns)
        assert isinstance(state["eax"], Const)
        assert state["eax"].value == 5

    def test_add_constants(self):
        """mov eax, 5 / add eax, 3 should resolve eax to Const(8)."""
        from dataflow import propagate_forward, Const
        code = b"\xB8\x05\x00\x00\x00" + b"\x83\xC0\x03"
        insns = self._disasm(code)
        state = propagate_forward(insns)
        assert isinstance(state["eax"], Const)
        assert state["eax"].value == 8

    def test_sub_constants(self):
        """mov ecx, 10 / sub ecx, 3 should resolve ecx to Const(7)."""
        from dataflow import propagate_forward, Const
        code = b"\xB9\x0A\x00\x00\x00" + b"\x83\xE9\x03"
        insns = self._disasm(code)
        state = propagate_forward(insns)
        assert isinstance(state["ecx"], Const)
        assert state["ecx"].value == 7

    def test_mov_reg_to_reg(self):
        """mov eax, 5 / mov ecx, eax should resolve ecx to Const(5)."""
        from dataflow import propagate_forward, Const
        code = b"\xB8\x05\x00\x00\x00" + b"\x89\xC1"
        insns = self._disasm(code)
        state = propagate_forward(insns)
        assert isinstance(state["ecx"], Const)
        assert state["ecx"].value == 5

    def test_call_clobbers_caller_saved(self):
        """call should set eax, ecx, edx to Unknown."""
        from dataflow import propagate_forward, Unknown
        code = b"\xB8\x05\x00\x00\x00" + b"\xB9\x0A\x00\x00\x00" + b"\xE8\x00\x10\x00\x00"
        insns = self._disasm(code)
        state = propagate_forward(insns)
        assert isinstance(state["eax"], Unknown)
        assert isinstance(state["ecx"], Unknown)

    def test_unknown_reg_stays_unknown(self):
        """add eax, ebx where ebx is unknown should not be Const."""
        from dataflow import propagate_forward, Const
        code = b"\xB8\x05\x00\x00\x00" + b"\x01\xD8"
        insns = self._disasm(code)
        state = propagate_forward(insns)
        assert not (isinstance(state["eax"], Const) and state["eax"].value == 5)

    def test_memory_load(self):
        """mov eax, [ecx+0x10] should produce Load."""
        from dataflow import propagate_forward, Load
        code = b"\x8B\x41\x10"
        insns = self._disasm(code)
        state = propagate_forward(insns)
        assert isinstance(state["eax"], Load)
        assert state["eax"].offset == 0x10

    def test_push_pop_preserves(self):
        """push eax / pop ecx should propagate value."""
        from dataflow import propagate_forward, Const
        code = b"\xB8\x07\x00\x00\x00" + b"\x50" + b"\x59"
        insns = self._disasm(code)
        state = propagate_forward(insns)
        assert isinstance(state["ecx"], Const)
        assert state["ecx"].value == 7

    def test_empty_insns(self):
        from dataflow import propagate_forward
        state = propagate_forward([])
        assert isinstance(state, dict)


class TestPropagateCfg:
    def test_importable(self):
        from dataflow import propagate_cfg
        assert callable(propagate_cfg)

    def test_linear_function(self):
        """Single-block function should produce same result as propagate_forward."""
        from dataflow import propagate_cfg, Const
        from common import Binary
        from unittest.mock import MagicMock

        # mov eax, 5; ret
        code = b"\xB8\x05\x00\x00\x00\xC3"
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True

        b = MagicMock(spec=Binary)
        b.is_64 = False
        b.ptr_size = 4
        b.base = 0x400000
        b.read_va.return_value = code
        b.disasm.return_value = list(cs.disasm(code, 0x401000))
        b.in_exec.return_value = True
        b.exec_ranges.return_value = [(0x401000, 0, len(code))]
        b.find_func_start.return_value = 0x401000

        result = propagate_cfg(b, 0x401000)
        assert 0x401000 in result
        assert isinstance(result[0x401000]["eax"], Const)
        assert result[0x401000]["eax"].value == 5

    def test_returns_dict_of_block_states(self):
        from dataflow import propagate_cfg
        from common import Binary
        from unittest.mock import MagicMock

        b = MagicMock(spec=Binary)
        b.is_64 = False
        b.disasm.return_value = []
        b.find_func_start.return_value = 0x401000
        b.read_va.return_value = b""
        b.exec_ranges.return_value = []
        b.in_exec.return_value = True
        b.ptr_size = 4
        b.base = 0x400000

        result = propagate_cfg(b, 0x401000)
        assert isinstance(result, dict)


class TestBackwardSlice:
    def test_importable(self):
        from dataflow import backward_slice
        assert callable(backward_slice)

    def test_single_block_slice(self):
        """Slice eax at end of: mov eax, 5; add eax, 3."""
        from dataflow import backward_slice
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        code = b"\xB8\x05\x00\x00\x00" + b"\x83\xC0\x03"
        insns = list(cs.disasm(code, 0x401000))
        target_va = insns[-1].address  # add eax, 3
        result = backward_slice(insns, target_va, "eax")
        vas = [entry[0] for entry in result]
        assert 0x401000 in vas  # mov eax, 5
        assert target_va in vas  # add eax, 3

    def test_unrelated_reg_not_in_slice(self):
        """Slice eax should not include mov ecx, 10."""
        from dataflow import backward_slice
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        code = b"\xB9\x0A\x00\x00\x00" + b"\xB8\x05\x00\x00\x00"
        insns = list(cs.disasm(code, 0x401000))
        target_va = insns[-1].address
        result = backward_slice(insns, target_va, "eax")
        vas = [entry[0] for entry in result]
        assert 0x401000 not in vas

    def test_empty_insns(self):
        from dataflow import backward_slice
        result = backward_slice([], 0x401000, "eax")
        assert result == []


class TestDataflowCLI:
    def test_help_works(self):
        """--help should print help text."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "retools.dataflow", "--help"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        assert result.returncode == 0
        assert "constants" in result.stdout
        assert "slice" in result.stdout
