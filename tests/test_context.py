"""Tests for retools/context.py -- RAG context assembly and postprocessing."""

import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


# ---------------------------------------------------------------------------
# _parse_kb_names
# ---------------------------------------------------------------------------

class TestParseKbNames:
    def test_extracts_names(self, tmp_path):
        from context import _parse_kb_names
        kb = tmp_path / "kb.h"
        kb.write_text(textwrap.dedent("""\
            struct Foo { int x; };
            @ 0x401000 void __cdecl ProcessInput(int key);
            @ 0x402000 float __thiscall Object_GetValue(Object* this);
            $ 0x7C5548 Object* g_mainObject
        """))
        result = _parse_kb_names(kb)
        assert result == {
            0x401000: "ProcessInput",
            0x402000: "Object_GetValue",
        }

    def test_empty_file(self, tmp_path):
        from context import _parse_kb_names
        kb = tmp_path / "kb.h"
        kb.write_text("")
        result = _parse_kb_names(kb)
        assert result == {}

    def test_missing_file(self, tmp_path):
        from context import _parse_kb_names
        result = _parse_kb_names(tmp_path / "nonexistent.h")
        assert result == {}

    def test_various_signatures(self, tmp_path):
        from context import _parse_kb_names
        kb = tmp_path / "kb.h"
        kb.write_text(textwrap.dedent("""\
            @ 0x00401000 void __cdecl SimpleFunc();
            @ 0x500000 int ComplexFunc(int a, int b);
            @ 0xDEAD _malloc;
        """))
        result = _parse_kb_names(kb)
        assert 0x00401000 in result
        assert result[0x00401000] == "SimpleFunc"
        assert result[0x500000] == "ComplexFunc"
        assert result[0xDEAD] == "_malloc"


# ---------------------------------------------------------------------------
# _parse_kb_globals
# ---------------------------------------------------------------------------

class TestParseKbGlobals:
    def test_extracts_globals(self, tmp_path):
        from context import _parse_kb_globals
        kb = tmp_path / "kb.h"
        kb.write_text(textwrap.dedent("""\
            @ 0x401000 void __cdecl ProcessInput(int key);
            $ 0x7C5548 Object* g_mainObject
            $ 0x7C554C Flags g_renderFlags
        """))
        result = _parse_kb_globals(kb)
        assert result == {
            0x7C5548: "g_mainObject",
            0x7C554C: "g_renderFlags",
        }

    def test_empty_file(self, tmp_path):
        from context import _parse_kb_globals
        kb = tmp_path / "kb.h"
        kb.write_text("")
        result = _parse_kb_globals(kb)
        assert result == {}

    def test_missing_file(self, tmp_path):
        from context import _parse_kb_globals
        result = _parse_kb_globals(tmp_path / "nonexistent.h")
        assert result == {}


# ---------------------------------------------------------------------------
# postprocess
# ---------------------------------------------------------------------------

class TestPostprocess:
    def test_renames_fcn_lowercase(self):
        from context import postprocess
        raw = "call fcn.00401000\nmov eax, fcn.00402000\n"
        kb = {0x00401000: "ProcessInput", 0x00402000: "GetValue"}
        result = postprocess(raw, kb)
        assert "ProcessInput" in result
        assert "GetValue" in result
        assert "fcn.00401000" not in result
        assert "fcn.00402000" not in result

    def test_renames_fcn_uppercase(self):
        from context import postprocess
        raw = "call fcn.00401ABC\n"
        kb = {0x00401ABC: "MyFunc"}
        result = postprocess(raw, kb)
        assert "MyFunc" in result
        assert "fcn.00401ABC" not in result

    def test_no_matches_returns_unchanged(self):
        from context import postprocess
        raw = "some output with no fcn patterns\n"
        result = postprocess(raw, {})
        assert result == raw

    def test_no_matches_with_names(self):
        from context import postprocess
        raw = "call fcn.00999999\n"
        kb = {0x00401000: "ProcessInput"}
        result = postprocess(raw, kb)
        # fcn.00999999 is not in kb, so it stays
        assert "fcn.00999999" in result

    def test_replaces_struct_field_accesses(self):
        from context import postprocess
        raw = "*(int *)(param_1 + 0x10)"
        fields = {0x10: ("int", "health")}
        result = postprocess(raw, {}, struct_fields=fields)
        assert "param_1->health" in result

    def test_struct_fields_none(self):
        from context import postprocess
        raw = "*(int *)(param_1 + 0x10)"
        result = postprocess(raw, {}, struct_fields=None)
        assert result == raw

    def test_combined_fcn_and_struct(self):
        from context import postprocess
        raw = "call fcn.00401000\n*(float *)(param_1 + 0x4)"
        kb = {0x00401000: "Init"}
        fields = {0x4: ("float", "speed")}
        result = postprocess(raw, kb, struct_fields=fields)
        assert "Init" in result
        assert "param_1->speed" in result

    def test_renames_ghidra_FUN_prefix(self):
        from context import postprocess
        raw = "call FUN_00401000\nmov eax, FUN_00402000\n"
        kb = {0x00401000: "ProcessInput", 0x00402000: "GetValue"}
        result = postprocess(raw, kb)
        assert "ProcessInput" in result
        assert "GetValue" in result
        assert "FUN_00401000" not in result

    def test_renames_ghidra_FUN_16digit(self):
        from context import postprocess
        raw = "call FUN_0000000140001000\n"
        kb = {0x0000000140001000: "WideFunc"}
        result = postprocess(raw, kb)
        assert "WideFunc" in result
        assert "FUN_0000000140001000" not in result


# ---------------------------------------------------------------------------
# assemble
# ---------------------------------------------------------------------------

class TestAssemble:
    def _make_mock_binary(self):
        b = MagicMock()
        b.is_64 = False
        b.base = 0x400000
        b.find_func_start.return_value = 0x401500
        # disasm returns instructions with call targets
        call_insn = MagicMock()
        call_insn.mnemonic = "call"
        call_insn.op_str = "0x401200"
        call_insn.address = 0x401510
        call_insn.size = 5

        ret_insn = MagicMock()
        ret_insn.mnemonic = "ret"
        ret_insn.op_str = ""
        ret_insn.address = 0x401580
        ret_insn.size = 1

        b.disasm.return_value = [call_insn, ret_insn]
        b.read_va.return_value = b"\x55\x8B\xEC" + b"\x90" * 61
        b.exec_ranges.return_value = [(0x401000, 0x1000, 0x1000)]
        b.abs_mem_refs.return_value = []
        b.abs_imm_refs.return_value = []
        b.rip_rel_refs.return_value = []
        b.mem_operands.return_value = []
        return b

    def test_returns_string_with_header(self, tmp_path):
        from context import assemble
        b = self._make_mock_binary()
        proj = tmp_path / "proj"
        proj.mkdir()
        result = assemble(b, 0x401500, str(proj))
        assert isinstance(result, str)
        assert "CONTEXT FOR 0x00401500" in result

    def test_includes_callees_section(self, tmp_path):
        from context import assemble
        b = self._make_mock_binary()
        proj = tmp_path / "proj"
        proj.mkdir()
        result = assemble(b, 0x401500, str(proj))
        assert "[callees]" in result

    def test_uses_kb_for_identity(self, tmp_path):
        from context import assemble
        b = self._make_mock_binary()
        proj = tmp_path / "proj"
        proj.mkdir()
        patches = tmp_path / "patches" / "proj"
        patches.mkdir(parents=True)
        kb = patches / "kb.h"
        kb.write_text("@ 0x401500 void __cdecl MyFunc();\n")
        result = assemble(b, 0x401500, str(proj), project_dir_for_kb=str(patches))
        assert "MyFunc" in result

    def test_unknown_function_identity(self, tmp_path):
        from context import assemble
        b = self._make_mock_binary()
        proj = tmp_path / "proj"
        proj.mkdir()
        result = assemble(b, 0x401500, str(proj))
        assert "unknown function at 0x00401500" in result


class TestAssembleSingleDisasm:
    def test_disasm_called_once(self, tmp_path):
        """assemble() should disassemble the function only once."""
        from context import assemble
        from search import StringRef

        kb = tmp_path / "kb.h"
        kb.write_text("$ 0x500000 int g_global\n")

        mock_binary = MagicMock()
        mock_binary.is_64 = False
        mock_binary.disasm.return_value = []
        mock_binary.abs_imm_refs.return_value = []
        mock_binary.abs_mem_refs.return_value = []

        fake_strings = [StringRef(va=0x500000, offset=0x1000, value="test_error")]

        with patch("context.find_start", return_value=0x401000), \
             patch("context.analyze", return_value=([], [], 0x401100)), \
             patch("context.aggregate_struct", return_value=[]), \
             patch("context.find_strings", return_value=fake_strings), \
             patch("context.propagate_cfg", return_value={}):
            assemble(mock_binary, 0x401000, str(tmp_path))

        assert mock_binary.disasm.call_count <= 1


class TestAssembleDataflow:
    def test_dataflow_section_present(self, tmp_path):
        """assemble() should include [dataflow] section by default."""
        from context import assemble
        from dataflow import Const

        b = MagicMock()
        b.is_64 = False
        b.base = 0x400000
        b.find_func_start.return_value = 0x401500
        b.disasm.return_value = []
        b.read_va.return_value = b"\x90" * 64
        b.exec_ranges.return_value = [(0x401000, 0x1000, 0x1000)]
        b.abs_mem_refs.return_value = []
        b.abs_imm_refs.return_value = []
        b.in_exec.return_value = True
        b.ptr_size = 4

        proj = tmp_path / "proj"
        proj.mkdir()

        mock_states = {0x401500: {"eax": Const(5), "ecx": Const(3)}}
        with patch("context.find_start", return_value=0x401500), \
             patch("context.analyze", return_value=([], [], 0x401600)), \
             patch("context.aggregate_struct", return_value=[]), \
             patch("context.find_strings", return_value=[]), \
             patch("context.propagate_cfg", return_value=mock_states):
            result = assemble(b, 0x401500, str(proj))

        assert "[dataflow]" in result
        assert "eax = 0x5" in result

    def test_no_dataflow_flag(self, tmp_path):
        """assemble() with no_dataflow=True should skip [dataflow] section."""
        from context import assemble

        b = MagicMock()
        b.is_64 = False
        b.base = 0x400000
        b.find_func_start.return_value = 0x401500
        b.disasm.return_value = []
        b.read_va.return_value = b"\x90" * 64
        b.exec_ranges.return_value = [(0x401000, 0x1000, 0x1000)]
        b.abs_mem_refs.return_value = []
        b.abs_imm_refs.return_value = []
        b.ptr_size = 4

        proj = tmp_path / "proj"
        proj.mkdir()

        with patch("context.find_start", return_value=0x401500), \
             patch("context.analyze", return_value=([], [], 0x401600)), \
             patch("context.aggregate_struct", return_value=[]), \
             patch("context.find_strings", return_value=[]):
            result = assemble(b, 0x401500, str(proj), no_dataflow=True)

        assert "[dataflow]" not in result
