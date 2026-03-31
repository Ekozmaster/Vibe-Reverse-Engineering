"""Tests for switch/jump table resolution in cfg.py."""

import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestResolveSwitch:
    def test_importable(self):
        from cfg import _resolve_switch
        assert callable(_resolve_switch)

    def test_pattern_a_direct_table(self):
        """Pattern A: cmp ecx,N / ja default / jmp [table+ecx*4]."""
        from cfg import _resolve_switch
        from common import Binary

        # Build a minimal code + jump table:
        # 0x401000: cmp ecx, 3
        # 0x401003: ja 0x401020 (default)
        # 0x401005: jmp [0x401100 + ecx*4]
        # Jump table at 0x401100: [0x401010, 0x401014, 0x401018, 0x40101C]
        cmp_bytes = b"\x83\xF9\x03"          # cmp ecx, 3
        ja_bytes = b"\x77\x1B"               # ja +0x1B (relative)
        # FF 24 8D 00114000 = jmp dword ptr [ecx*4 + 0x401100]
        jmp_bytes = b"\xFF\x24\x8D" + struct.pack("<I", 0x401100)

        code_at_1000 = cmp_bytes + ja_bytes + jmp_bytes
        # Pad to offset 0x100 for the jump table
        padding = b"\x90" * (0x100 - len(code_at_1000))
        table_entries = struct.pack("<4I", 0x401010, 0x401014, 0x401018, 0x40101C)
        raw = code_at_1000 + padding + table_entries + b"\x00" * 0x100

        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        insns = list(cs.disasm(code_at_1000, 0x401000))
        # Find the jmp instruction
        jmp_insn = [i for i in insns if i.mnemonic == "jmp"][0]

        # Build a mock Binary with read_va and in_exec
        b = MagicMock(spec=Binary)
        b.is_64 = False
        b.ptr_size = 4
        b.base = 0x400000

        def mock_read_va(va, size):
            off = va - 0x401000
            if 0 <= off < len(raw):
                return raw[off : off + size]
            return b""
        b.read_va = mock_read_va
        b.in_exec = lambda va: 0x401000 <= va < 0x402000

        targets = _resolve_switch(b, jmp_insn, insns)
        assert targets is not None
        assert set(targets) == {0x401010, 0x401014, 0x401018, 0x40101C}

    def test_non_switch_jmp_returns_none(self):
        """A regular jmp eax should not resolve as a switch."""
        from cfg import _resolve_switch

        # FF E0 = jmp eax (register, not memory)
        code = b"\xFF\xE0"
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        insns = list(cs.disasm(code, 0x401000))
        b = MagicMock()
        b.is_64 = False
        targets = _resolve_switch(b, insns[0], insns)
        assert targets is None


class TestBuildCfgWithSwitch:
    def test_empty_disasm(self):
        """build_cfg with empty disassembly shouldn't crash."""
        from cfg import build_cfg
        from common import Binary
        b = MagicMock(spec=Binary)
        b.disasm.return_value = []
        b.find_func_start.return_value = 0x401000
        blocks, edges = build_cfg(b, 0x401000)
        assert blocks == {}
        assert edges == []
