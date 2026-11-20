"""Tests for retools/dataflow.py -- value tracking and constant propagation."""

import sys
from pathlib import Path

import pytest
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

from pe_fakes import binary_over


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

    def test_partial_init_still_tracks_the_other_registers(self):
        """With eax given, mov ecx, 5 still resolves ecx."""
        from dataflow import propagate_forward, Const
        init = {"eax": Const(1)}
        state = propagate_forward(self._disasm(b"\xB9\x05\x00\x00\x00"), init)
        assert state["ecx"] == Const(5)
        assert state["eax"] == Const(1)
        assert init == {"eax": Const(1)}


_SET_EAX_ECX_EDX = bytes.fromhex("B805000000" "B906000000" "BA07000000")   # mov eax, 5; mov ecx, 6; mov edx, 7


class TestRegistersAnInstructionOverwrites:
    """A constant is reported only while nothing has written the register since."""

    def _state_after(self, instruction: str):
        from dataflow import propagate_forward
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        return propagate_forward(list(cs.disasm(_SET_EAX_ECX_EDX + bytes.fromhex(instruction), 0x401000)))

    @pytest.mark.parametrize("instruction, overwritten", [
        ("0BC2", {"eax"}),              # or eax, edx
        ("23D1", {"edx"}),              # and edx, ecx
        ("40", {"eax"}),                # inc eax
        ("C1E002", {"eax"}),            # shl eax, 2
        ("0FAFC1", {"eax"}),            # imul eax, ecx
        ("8D0491", {"eax"}),            # lea eax, [ecx + edx*4]
        ("0FB6C1", {"eax"}),            # movzx eax, cl
        ("F7E1", {"eax", "edx"}),       # mul ecx
        ("91", {"eax", "ecx"}),         # xchg eax, ecx
        ("99", {"edx"}),                # cdq
        ("B101", {"ecx"}),              # mov cl, 1
        ("32C0", {"eax"}),              # xor al, al
        ("6683C001", {"eax"}),          # add ax, 1
    ])
    def test_written_register_is_no_longer_a_constant(self, instruction, overwritten):
        from dataflow import Const, Unknown
        state = self._state_after(instruction)
        for register in ("eax", "ecx", "edx"):
            if register in overwritten:
                assert state[register] == Unknown(), register
            else:
                assert isinstance(state[register], Const), register

    @pytest.mark.parametrize("instruction", [
        "83F805",       # cmp eax, 5
        "85C0",         # test eax, eax
        "8906",         # mov [esi], eax
        "50",           # push eax
    ])
    def test_register_that_is_only_read_keeps_its_constant(self, instruction):
        from dataflow import Const
        assert self._state_after(instruction)["eax"] == Const(5)

    def test_only_the_32_bit_registers_are_reported(self):
        state = self._state_after("B101" "32C0")    # mov cl, 1; xor al, al
        assert sorted(state) == ["eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp"]


class TestPropagateCfg:
    def test_importable(self):
        from dataflow import propagate_cfg
        assert callable(propagate_cfg)

    def test_linear_function(self):
        """Single-block function should produce same result as propagate_forward."""
        from dataflow import propagate_cfg, Const

        # mov eax, 5; ret
        code = b"\xB8\x05\x00\x00\x00\xC3"
        b = binary_over(code)

        result = propagate_cfg(b, 0x401000)
        assert 0x401000 in result
        assert isinstance(result[0x401000]["eax"], Const)
        assert result[0x401000]["eax"].value == 5

    def test_branch_merges_to_unknown(self):
        """At a merge point after a branch, conflicting values become Unknown."""
        from dataflow import propagate_cfg, Const, Unknown

        # Block 0 (0x401000): mov eax,5; cmp ecx,0; je block2
        # Block 1 (0x40100A): mov eax,10  (fall-through)
        # Block 2 (0x40100F): ret         (merge: eax=5 from je, eax=10 from fall)
        code = (
            b"\xB8\x05\x00\x00\x00"  # mov eax, 5
            b"\x83\xF9\x00"          # cmp ecx, 0
            b"\x74\x05"              # je +5 -> 0x40100F
            b"\xB8\x0A\x00\x00\x00"  # mov eax, 10
            b"\xC3"                   # ret
        )
        b = binary_over(code)

        result = propagate_cfg(b, 0x401000)

        # Block 0 exit: eax = 5
        assert isinstance(result[0x401000]["eax"], Const)
        assert result[0x401000]["eax"].value == 5
        # Block 1 exit: eax = 10
        assert isinstance(result[0x40100A]["eax"], Const)
        assert result[0x40100A]["eax"].value == 10
        # Merge block: eax is Unknown (5 vs 10)
        assert isinstance(result[0x40100F]["eax"], Unknown)

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


class TestBackwardSliceCfg:
    def test_cross_block_slice(self):
        """Slice should follow predecessor edges to find contributions in earlier blocks."""
        from dataflow import backward_slice_cfg

        # Block 0 (0x401000): mov eax, 5; jmp block1
        # Block 1 (0x401007): add eax, 3; ret
        # Slice eax at the add — should find both mov and add.
        code = (
            b"\xB8\x05\x00\x00\x00"  # mov eax, 5
            b"\xEB\x00"              # jmp +0 -> 0x401007
            b"\x83\xC0\x03"          # add eax, 3
            b"\xC3"                   # ret
        )
        b = binary_over(code)

        result = backward_slice_cfg(b, 0x401000, 0x401007, "eax")
        vas = [entry[0] for entry in result]
        assert 0x401000 in vas  # mov eax, 5 (in predecessor block)
        assert 0x401007 in vas  # add eax, 3 (target block)

    def test_branch_both_paths(self):
        """Slice through a merge point should find contributions from both predecessors."""
        from dataflow import backward_slice_cfg

        # Block 0 (0x401000): mov eax, 5; cmp ecx, 0; je block2
        # Block 1 (0x40100A): mov eax, 10  (fall-through into block2)
        # Block 2 (0x40100F): ret
        # Slice eax at ret — should find mov eax,5 AND mov eax,10.
        code = (
            b"\xB8\x05\x00\x00\x00"  # mov eax, 5
            b"\x83\xF9\x00"          # cmp ecx, 0
            b"\x74\x05"              # je +5 -> 0x40100F
            b"\xB8\x0A\x00\x00\x00"  # mov eax, 10
            b"\xC3"                   # ret
        )
        b = binary_over(code)

        result = backward_slice_cfg(b, 0x401000, 0x40100F, "eax")
        vas = [entry[0] for entry in result]
        assert 0x401000 in vas  # mov eax, 5 (from je path)
        assert 0x40100A in vas  # mov eax, 10 (from fall-through path)


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
