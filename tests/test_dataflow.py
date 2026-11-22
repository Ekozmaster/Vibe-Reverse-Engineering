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
        ("E800100000", {"eax", "ecx", "edx"}),          # call rel32
        ("9A785634121200", {"eax", "ecx", "edx"}),      # lcall 0x12:0x12345678
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


_CALL = "E800100000"                       # call rel32
_SET_ESI_9 = "BE09000000"                  # mov esi, 9


class TestStackSlotsAPopReads:
    """A pop yields a pushed value only while the pushes and pops since are all accounted for."""

    def _state_after(self, code: str):
        from dataflow import propagate_forward
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        insns = list(cs.disasm(bytes.fromhex(code), 0x401000))
        assert sum(insn.size for insn in insns) == len(code) // 2
        return propagate_forward(insns)

    @pytest.mark.parametrize("code", [
        _SET_ESI_9 + "56" "6A05" + _CALL + "83C404" "5E",   # push esi; push 5; call; add esp, 4; pop esi
        _SET_ESI_9 + "56" "6A05" + _CALL + "5E",            # push esi; push 5; call; pop esi
        _SET_ESI_9 + "56" "6A05" "FF10" "5E",               # push esi; push 5; call [eax]; pop esi
        _SET_ESI_9 + "56" "6A05" "9A785634121200" "5E",     # push esi; push 5; lcall 0x12:0x12345678; pop esi
        _SET_ESI_9 + "56" "6A05" "FF18" "5E",               # push esi; push 5; call far [eax]; pop esi
    ])
    def test_pop_behind_a_call_is_unknown(self, code):
        from dataflow import Unknown
        assert self._state_after(code)["esi"] == Unknown()

    def test_add_esp_drops_the_slots_it_releases(self):
        from dataflow import Const
        state = self._state_after(_SET_ESI_9 + "56" "6A05" "6A06" "83C408" "5E")   # push esi; push 5; push 6; add esp, 8; pop esi
        assert state["esi"] == Const(9)

    def test_slots_below_the_first_push_are_unknown(self):
        from dataflow import Const, Unknown
        state = self._state_after("6A05" "83C408" "6A06" "58" "59")   # push 5; add esp, 8; push 6; pop eax; pop ecx
        assert state["eax"] == Const(6)
        assert state["ecx"] == Unknown()

    @pytest.mark.parametrize("reserve", [
        "83EC04",           # sub esp, 4
        "83C4FC",           # add esp, -4
    ])
    def test_a_reserved_slot_is_unknown_and_the_push_below_it_is_kept(self, reserve):
        from dataflow import Const, Unknown
        state = self._state_after("6A05" + reserve + "58" "59")       # push 5; reserve; pop eax; pop ecx
        assert state["eax"] == Unknown()
        assert state["ecx"] == Const(5)

    @pytest.mark.parametrize("store, eax, ecx", [
        ("C7042407000000", None, 1),        # mov dword [esp], 7
        ("C744240407000000", 2, None),      # mov dword [esp + 4], 7
        ("C644240507", 2, None),            # mov byte [esp + 5], 7
        ("66C74424030700", None, None),     # mov word [esp + 3], 7
        ("D91C24", None, 1),                # fstp dword [esp]
        ("DD1C24", None, None),             # fstp qword [esp]
        ("C744240807000000", 2, 1),         # mov dword [esp + 8], 7
        ("C74424FC07000000", 2, 1),         # mov dword [esp - 4], 7
        ("C7043407000000", None, None),     # mov dword [esp + esi], 7
        ("660FD60424", None, None),         # movq [esp], xmm0
        ("0F7F0424", None, None),           # movq [esp], mm0
        ("0F7E0424", None, 1),              # movd [esp], mm0
        ("0FAE1C24", None, 1),              # stmxcsr [esp]
        ("0F9F0424", None, 1),              # setg byte [esp]
        ("0FB1542404", 2, None),            # cmpxchg [esp + 4], edx
        ("0FC70C24", None, None),           # cmpxchg8b [esp]
        ("C10C2402", None, 1),              # ror dword [esp], 2
        ("660F3A160C2401", None, 1),        # pextrd [esp], xmm1, 1
        ("0FAE0424", None, None),           # fxsave [esp]
        ("DD3424", None, None),             # fnsave [esp]
        ("0FAE2424", None, None),           # xsave [esp]
        ("0FAE3424", None, None),           # xsaveopt [esp]
        ("0FC72424", None, None),           # xsavec [esp]
        ("0FC72C24", None, None),           # xsaves [esp]
        ("0FAE442408", None, None),         # fxsave [esp + 8]
    ])
    def test_a_store_through_esp_makes_the_slots_it_writes_unknown(self, store, eax, ecx):
        from dataflow import Const, Unknown
        state = self._state_after("6A01" "6A02" + store + "58" "59")      # push 1; push 2; store; pop eax; pop ecx
        assert state["eax"] == (Unknown() if eax is None else Const(eax))
        assert state["ecx"] == (Unknown() if ecx is None else Const(ecx))

    def test_pop_into_memory_takes_a_slot(self):
        from dataflow import Const
        state = self._state_after("6A07" "6A05" "8F03" "58")          # push 7; push 5; pop dword [ebx]; pop eax
        assert state["eax"] == Const(7)

    @pytest.mark.parametrize("instruction", [
        "C9",               # leave
        "8BE5",             # mov esp, ebp
        "8D6424F8",         # lea esp, [esp - 8]
        "83C402",           # add esp, 2
        "03E1",             # add esp, ecx
        "81ECFCFFFF7F",     # sub esp, 0x7ffffffc
        "61",               # popal
        "9D",               # popfd
        "C8080000",         # enter 8, 0
        "6658",             # pop ax
        "07",               # pop es
        "0FA0",             # push fs
        "5C",               # pop esp
    ])
    def test_pop_behind_a_stack_pointer_change_that_is_not_followed_is_unknown(self, instruction):
        from dataflow import Unknown
        state = self._state_after("6A07" "6A05" + instruction + "5F")  # push 7; push 5; ...; pop edi
        assert state["edi"] == Unknown()


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

    @pytest.mark.parametrize("call", [
        "E800100000",           # call rel32
        "9A785634121200",       # lcall 0x12:0x12345678
        "FF1E",                 # call far [esi]
    ])
    def test_a_call_writes_the_registers_a_callee_may_change(self, call):
        from dataflow import backward_slice
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        insns = list(cs.disasm(bytes.fromhex("B805000000" + call + "8BD8"), 0x401000))   # mov eax, 5; call; mov ebx, eax
        result = backward_slice(insns, insns[-1].address, "ebx")
        assert [(va, reg) for va, reg, _ in result] == [(insns[1].address, "eax"), (insns[2].address, "ebx")]

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
