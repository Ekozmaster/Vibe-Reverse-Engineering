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

    def test_x64_skips_dataflow_and_says_so(self, tmp_path):
        from context import assemble
        b = self._make_mock_binary()
        b.is_64 = True
        with patch("context.propagate_cfg", side_effect=AssertionError("ran on x64")):
            result = assemble(b, 0x401500, str(tmp_path))
        assert "[dataflow] skipped" in result


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


# ---------------------------------------------------------------------------
# _callees_from_index
# ---------------------------------------------------------------------------

class TestIndexFastPath:
    def test_callees_from_index(self, tmp_path):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))
        from index import GameIndex
        from context import _callees_from_index

        db = str(tmp_path / "index.db")
        gi = GameIndex(db)
        # Both the caller (0x1000) and callee (0x2000) are known functions, as in
        # a real Ghidra export.
        gi.replace("funcs", [{"address": 0x1000, "name": "Caller"},
                             {"address": 0x2000, "name": "Target"}], source="ghidra")
        gi.replace("xrefs", [{"from_ea": 0x1010, "to_ea": 0x2000, "type": "call",
                              "is_code": 1, "from_func": 0x1000}], source="ghidra")
        gi.close()

        callees = _callees_from_index(db, 0x1000)
        assert callees == [(0x2000, "Target")]

    def test_missing_index_returns_none(self, tmp_path):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))
        from context import _callees_from_index
        assert _callees_from_index(str(tmp_path / "absent.db"), 0x1000) is None

    def test_empty_xrefs_returns_none(self, tmp_path):
        """Bootstrap-only projects write funcs but never xrefs (ghidra-only).

        _callees_from_index must fall back to None (scan) rather than
        trusting an empty callees query result as authoritative.
        """
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))
        from index import GameIndex
        from context import _callees_from_index

        db = str(tmp_path / "index.db")
        gi = GameIndex(db)
        gi.replace("funcs", [{"address": 0x1000, "name": "SomeFunc"}], source="bootstrap")
        gi.close()

        assert _callees_from_index(db, 0x1000) is None

    def test_unknown_start_returns_none(self, tmp_path):
        """When the queried start isn't a known function entry (find_start
        disagreed with Ghidra), an empty result must not be trusted."""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))
        from index import GameIndex
        from context import _callees_from_index

        db = str(tmp_path / "index.db")
        gi = GameIndex(db)
        gi.replace("funcs", [{"address": 0x2000, "name": "Known"}], source="ghidra")
        gi.replace("xrefs", [{"from_ea": 0x2010, "to_ea": 0x3000, "type": "call",
                              "is_code": 1, "from_func": 0x2000}], source="ghidra")
        gi.close()
        # 0x9999 is not a function entry -> caller must scan, not trust []
        assert _callees_from_index(db, 0x9999) is None

    def test_schemaless_db_returns_none(self, tmp_path):
        """A present but foreign/half-initialised index.db (no xrefs table) must
        fall back to None rather than raising OperationalError."""
        import sqlite3
        from context import _callees_from_index

        db = str(tmp_path / "index.db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE unrelated (x INTEGER)")
        conn.commit()
        conn.close()
        assert _callees_from_index(db, 0x1000) is None


class TestAssembleIndexBranch:
    def _mock_binary(self):
        b = MagicMock()
        b.is_64 = False
        b.base = 0x400000
        b.disasm.return_value = []
        b.abs_mem_refs.return_value = []
        b.abs_imm_refs.return_value = []
        return b

    def test_kb_name_beats_index_name_and_indirect_recovered(self, tmp_path):
        """On the index fast-path, a fresh kb.h name outranks the exported Ghidra
        name, and indirect-call markers from the scan are still emitted."""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))
        from index import GameIndex
        from context import assemble

        proj = tmp_path / "proj"
        proj.mkdir()
        gi = GameIndex(str(proj / "index.db"))
        gi.replace("funcs", [{"address": 0x401500, "name": "FUN_00401500"},
                             {"address": 0x401200, "name": "FUN_00401200"}], source="ghidra")
        gi.replace("xrefs", [{"from_ea": 0x401510, "to_ea": 0x401200, "type": "call",
                              "is_code": 1, "from_func": 0x401500}], source="ghidra")
        gi.close()

        kb = proj / "kb.h"
        kb.write_text("@ 0x401200 void __cdecl RealCallee();\n")

        b = self._mock_binary()
        with patch("context.find_start", return_value=0x401500), \
             patch("context.analyze", return_value=([], [(0x401510, 0x401200),
                                                          (0x401520, "dword ptr [eax + 0x14]")], 0x401600)), \
             patch("context.aggregate_struct", return_value=[]), \
             patch("context.find_strings", return_value=[]), \
             patch("context.propagate_cfg", return_value={}):
            result = assemble(b, 0x401500, str(proj), project_dir_for_kb=str(proj))

        assert "RealCallee" in result           # kb.h name wins over FUN_00401200
        assert "FUN_00401200" not in result
        assert "indirect call" in result        # indirect marker recovered


def _assemble(b, proj, calls=(), end=0x401100, start=0x401000, **kwargs):
    from context import assemble
    with patch("context.find_start", return_value=start), \
         patch("context.analyze", return_value=([], list(calls), end)), \
         patch("context.aggregate_struct", return_value=[]) as agg, \
         patch("context.find_strings", return_value=[]):
        result = assemble(b, start, str(proj), **kwargs)
    return result, agg


def _bare_binary():
    b = MagicMock()
    b.is_64 = False
    b.disasm.return_value = []
    b.abs_mem_refs.return_value = []
    b.abs_imm_refs.return_value = []
    return b


def _section(result: str, header: str) -> list[str]:
    """The indented lines under *header* in an assemble() result."""
    lines = result.splitlines()
    body = []
    for line in lines[lines.index(header) + 1:]:
        if not line.startswith("  "):
            break
        body.append(line)
    return body


class TestAssembleCallees:
    def test_scan_lists_each_callee_once_named_from_kb(self, tmp_path):
        """Without an index, the scan lists every distinct target once: kb name,
        'unknown', or an indirect-call marker."""
        (tmp_path / "kb.h").write_text("@ 0x401200 void __cdecl Foo();\n")
        calls = [(0x401010, 0x401200), (0x401020, 0x401300), (0x401030, 0x401200),
                 (0x401040, "dword ptr [eax]"), (0x401050, "dword ptr [eax]")]
        result, _ = _assemble(_bare_binary(), tmp_path, calls)
        assert _section(result, "[callees]") == [
            "  0x00401200: Foo",
            "  0x00401300: unknown",
            "  dword ptr [eax]: indirect call",
        ]

    def test_index_path_recovers_each_indirect_marker_once(self, tmp_path):
        from index import GameIndex
        gi = GameIndex(str(tmp_path / "index.db"))
        gi.replace("funcs", [{"address": 0x401000, "name": "Caller"},
                             {"address": 0x401200, "name": "Callee"}], source="ghidra")
        gi.replace("xrefs", [{"from_ea": 0x401010, "to_ea": 0x401200, "type": "call",
                              "is_code": 1, "from_func": 0x401000}], source="ghidra")
        gi.close()
        calls = [(0x401010, 0x401200), (0x401020, "dword ptr [eax]"),
                 (0x401030, "dword ptr [eax]")]
        result, _ = _assemble(_bare_binary(), tmp_path, calls)
        assert _section(result, "[callees]") == [
            "  0x00401200: Callee",
            "  dword ptr [eax]: indirect call",
        ]


class TestAssembleFunctionBounds:
    def test_scans_only_the_function_bytes(self, tmp_path):
        b = _bare_binary()
        _, agg = _assemble(b, tmp_path, start=0x401000, end=0x401100)
        assert agg.call_args.kwargs["fn_size"] == 0x100
        assert b.disasm.call_args.kwargs["max_bytes"] == 0x100

    def test_unknown_end_scans_up_to_the_analysis_cap(self, tmp_path):
        """analyze() caps a function at 0x2000 bytes; an end equal to the start
        means no end was found, and the sections still scan that cap."""
        b = _bare_binary()
        _, agg = _assemble(b, tmp_path, start=0x401000, end=0x401000)
        assert agg.call_args.kwargs["fn_size"] == 0x2000
        assert b.disasm.call_args.kwargs["max_bytes"] == 0x2000


class TestAssembleGlobals:
    def test_lists_each_referenced_kb_global_once(self, tmp_path):
        (tmp_path / "kb.h").write_text(
            "$ 0x500000 int g_first\n$ 0x500010 int g_second\n$ 0x500020 int g_unused\n")
        b = _bare_binary()
        insn1, insn2 = MagicMock(), MagicMock()
        b.disasm.return_value = [insn1, insn2]
        b.abs_mem_refs.side_effect = (
            lambda i: [0x500000, 0x500010, 0x600000] if i is insn1 else [0x500000])
        result, _ = _assemble(b, tmp_path)
        assert _section(result, "[globals]") == [
            "  g_first at 0x00500000",
            "  g_second at 0x00500010",
        ]

    def test_no_section_without_a_referenced_global(self, tmp_path):
        (tmp_path / "kb.h").write_text("$ 0x500000 int g_first\n")
        result, _ = _assemble(_bare_binary(), tmp_path)
        assert "[globals]" not in result


class TestAssembleKbLookup:
    def test_explicit_kb_dir_outranks_project_kb(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "kb.h").write_text("@ 0x401000 void __cdecl ProjectName();\n")
        override = tmp_path / "override"
        override.mkdir()
        (override / "kb.h").write_text("@ 0x401000 void __cdecl OverrideName();\n")
        result, _ = _assemble(_bare_binary(), proj, project_dir_for_kb=str(override))
        assert "[identity] OverrideName (from KB)" in result.splitlines()


class TestAssembleSimilar:
    def _match(self, source, name):
        m = MagicMock(source=source)
        m.name = name
        return m

    def test_reports_the_best_structural_match(self, tmp_path):
        sig = {"block_count": 3, "edge_count": 4, "call_count": 2,
               "mnemonic_hash": "h", "constants": []}
        with patch("context.SignatureDB") as db_cls, \
             patch("context.extract_structural_sig", return_value=sig):
            db_cls.open_existing.return_value.match_structural.return_value = [
                self._match("msvc", "best"), self._match("other", "second")]
            result, _ = _assemble(_bare_binary(), tmp_path, db_path="sigs.db")
        db_cls.open_existing.assert_called_once_with("sigs.db")
        assert "[similar] msvc: best (block_count=3, call_count=2)" in result.splitlines()

    def test_no_line_without_a_signature(self, tmp_path):
        with patch("context.SignatureDB") as db_cls, \
             patch("context.extract_structural_sig", return_value=None):
            db_cls.open_existing.return_value.match_structural.return_value = [self._match("a", "b")]
            result, _ = _assemble(_bare_binary(), tmp_path, db_path="sigs.db")
        assert "[similar]" not in result

    def test_missing_db_is_refused_without_creating_it(self, tmp_path):
        missing = tmp_path / "missing.db"
        with pytest.raises(FileNotFoundError, match="no signature database"):
            _assemble(_bare_binary(), tmp_path, db_path=str(missing))
        assert not missing.exists()

    def test_db_is_closed_when_matching_fails(self, tmp_path):
        with patch("context.SignatureDB") as db_cls, \
             patch("context.extract_structural_sig", side_effect=ValueError("bad bytes")):
            with pytest.raises(ValueError, match="bad bytes"):
                _assemble(_bare_binary(), tmp_path, db_path="sigs.db")
        db_cls.open_existing.return_value.close.assert_called_once_with()


class TestCli:
    def test_assemble_with_missing_db_exits_with_message(self, tmp_path, capsys):
        from context import main
        missing = tmp_path / "missing.db"
        with patch("context.Binary"), \
             patch("context.assemble", side_effect=FileNotFoundError(f"no signature database at {missing}")):
            with pytest.raises(SystemExit) as exc:
                main(["assemble", "game.exe", "401000", "--project", str(tmp_path), "--db", str(missing)])
        assert exc.value.code == 1
        assert f"context: no signature database at {missing}" in capsys.readouterr().err

    def test_assemble_prints_identity_and_named_callees_from_the_projects_kb(self, tmp_path, capsys):
        import struct
        from context import main
        from pe_fakes import pe_image
        code = bytearray(b"\xCC" * 0x40)
        code[0:3] = b"\x55\x8B\xEC"                                   # push ebp / mov ebp, esp
        code[3:8] = b"\xE8" + struct.pack("<i", 0x20 - 8)             # call 0x401020
        code[8:10] = b"\x5D\xC3"                                      # pop ebp / ret
        code[0x20] = 0xC3
        image = pe_image(tmp_path / "game.exe", bytes(code))
        project = tmp_path / "Game"
        project.mkdir()
        (project / "kb.h").write_text("@ 0x401000 int __cdecl Outer(void);\n"
                                      "@ 0x401020 void __cdecl Inner(void);\n")
        main(["assemble", str(image), "401000", "--project", str(project), "--no-dataflow"])
        assert capsys.readouterr().out.splitlines() == [
            "=== CONTEXT FOR 0x00401000 ===",
            "[identity] Outer (from KB)",
            "[callees]",
            "  0x00401020: Inner",
        ]

    def _postprocess(self, project, stdin_text, fields, capsys, monkeypatch):
        import io
        from context import main
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
        with patch("context.Binary"), \
             patch("context.find_start", return_value=0x401500) as fs, \
             patch("context.aggregate_struct", return_value=fields) as agg:
            main(["postprocess", "game.exe", "401510", "--project", project])
        assert fs.call_args.args[1] == 0x401510
        assert agg.call_args.args[1] == 0x401500
        return capsys.readouterr().out

    def test_postprocess_renames_calls_and_struct_fields_from_stdin(
            self, tmp_path, capsys, monkeypatch):
        from structrefs import FieldAccess
        (tmp_path / "kb.h").write_text("@ 0x401200 void __cdecl Foo();\n")
        fields = [FieldAccess(offset=0x10, type_name="int", size=4, access="read")]
        out = self._postprocess(str(tmp_path),
                                "call fcn.00401200;\nx = *(int *)(this + 0x10);\n",
                                fields, capsys, monkeypatch)
        assert out == "call Foo;\nx = this->field_10;\n"

    def test_postprocess_falls_back_to_patches_kb(self, tmp_path, capsys, monkeypatch):
        """A project dir without kb.h reads patches/<project name>/kb.h from the cwd."""
        kb_dir = tmp_path / "patches" / "Game"
        kb_dir.mkdir(parents=True)
        (kb_dir / "kb.h").write_text("@ 0x401200 void __cdecl Foo();\n")
        monkeypatch.chdir(tmp_path)
        out = self._postprocess(str(tmp_path / "elsewhere" / "Game"), "call fcn.00401200;",
                                [], capsys, monkeypatch)
        assert out == "call Foo;"
