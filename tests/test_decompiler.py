"""Tests for decompiler.py backend routing logic."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestScriptModeImports:
    def test_load_types_import_resolves_in_script_mode(self, tmp_path):
        """`python retools/decompiler.py` puts only retools/ on sys.path[0];
        _load_types must still be able to import the kb parser."""
        import subprocess
        import textwrap

        retools = Path(__file__).resolve().parent.parent / "retools"
        driver = tmp_path / "driver.py"
        driver.write_text(textwrap.dedent(f"""
            import sys
            sys.path.insert(0, r"{retools}")   # simulate script-dir-only sys.path
            import decompiler

            class FakeR2:
                def cmd(self, c): pass

            decompiler._load_types(FakeR2(), "@ 0x401000 void Foo(void);")
            print("OK")
        """))
        proc = subprocess.run(
            [sys.executable, str(driver)],
            cwd=str(tmp_path), capture_output=True, text=True,
        )
        assert "OK" in proc.stdout, proc.stderr


class TestBackendRouting:
    def test_auto_no_project_uses_r2(self):
        """--backend auto without --project should use r2ghidra."""
        from decompiler import decompile
        with patch("decompiler._find_r2_bin", return_value=None):
            with pytest.raises(FileNotFoundError, match="radare2 not found"):
                decompile("fake.exe", 0x401000, backend="auto")

    def test_auto_with_project_no_ghidra_falls_through(self, tmp_path):
        """--backend auto with --project but no Ghidra project falls through to r2."""
        mock_backend = MagicMock()
        mock_backend.is_analyzed.return_value = False

        with patch.dict(sys.modules, {"retools.pyghidra_backend": mock_backend}):
            from importlib import reload
            import decompiler
            reload(decompiler)
            with patch("decompiler._find_r2_bin", return_value=None):
                with pytest.raises(FileNotFoundError, match="radare2 not found"):
                    decompiler.decompile("fake.exe", 0x401000, backend="auto", project_dir=str(tmp_path))

    def test_ghidra_backend_without_project_errors(self):
        """--backend ghidra without --project returns error."""
        from decompiler import decompile
        result = decompile("fake.exe", 0x401000, backend="ghidra")
        assert "[error]" in result
        assert "--project required" in result

    def test_ghidra_backend_routes_to_pyghidra(self, tmp_path):
        """--backend ghidra with --project routes to pyghidra_backend."""
        mock_backend = MagicMock()
        mock_backend.decompile.return_value = "void func() {}"
        mock_backend.is_analyzed.return_value = True

        with patch.dict(sys.modules, {"retools.pyghidra_backend": mock_backend}):
            from importlib import reload
            import decompiler
            reload(decompiler)
            result = decompiler.decompile("fake.exe", 0x401000, backend="ghidra", project_dir=str(tmp_path))

        mock_backend.decompile.assert_called_once()
        assert result == "void func() {}"


class FakeR2:
    def __init__(self):
        self.cmds = []

    def cmd(self, c):
        self.cmds.append(c)
        return ""


class TestLoadTypesOrdering:
    def test_typedefs_emitted_before_references(self, tmp_path):
        """td must be sent to r2 before any tl/afs that could reference the type."""
        kb_path = tmp_path / "kb.h"
        kb_path.write_text(
            "struct Foo { int x; };\n"
            "$ 0x7C5548 Foo* g_mainObject\n"
            "@ 0x401000 void __cdecl ProcessInput(int key);\n"
        )

        from decompiler import _load_types
        r2 = FakeR2()
        _load_types(r2, str(kb_path))

        td_idx = next(i for i, c in enumerate(r2.cmds) if c.startswith("td "))
        tl_idx = next(i for i, c in enumerate(r2.cmds) if c.startswith("tl "))
        afs_idx = next(i for i, c in enumerate(r2.cmds) if c.startswith("afs "))

        assert td_idx < tl_idx
        assert td_idx < afs_idx


class _ScriptedR2:
    """Stands in for an r2pipe session: answers decompile commands from a table."""

    def __init__(self, outputs: dict):
        self._outputs = outputs
        self.cmds = []

    def cmd(self, c):
        self.cmds.append(c)
        for prefix, output in self._outputs.items():
            if c.startswith(prefix + " "):
                return output
        return ""

    def quit(self):
        pass


def _decompile_with(outputs: dict, **kwargs) -> str:
    import decompiler
    session = _ScriptedR2(outputs)
    with (
        patch("decompiler._find_r2_bin", return_value="r2"),
        patch("decompiler._ensure_r2_in_path"),
        patch("decompiler._find_sleigh_home", return_value=None),
        patch("decompiler.r2pipe.open", return_value=session),
    ):
        return decompiler.decompile("fake.exe", 0x401000, **kwargs)


class TestAutoBackendOutputSelection:
    def test_output_mentioning_install_is_kept(self):
        code = "uint sym.MsiInstallProductW(int64_t arg1) { return 0; }"
        assert _decompile_with({"pdg": code}, backend="auto") == code

    def test_missing_plugin_hint_falls_back_to_next_backend(self):
        hint = "You need to install the plugin with r2pm -ci r2ghidra"
        fallback = "void fcn_00401000(void) { }"
        assert _decompile_with({"pdg": hint, "pdc": fallback}, backend="auto") == fallback

    def test_error_when_no_backend_is_installed(self):
        hint = "You need to install the plugin with r2pm -ci r2ghidra"
        result = _decompile_with({"pdg": hint}, backend="auto")
        assert result.startswith("[error]")


class TestAutoBackendGhidraProjectLookup:
    def test_binary_name_with_dots_is_looked_up_by_file_name(self, tmp_path):
        """A project for `sl.common.dll` lives under ghidra/sl.common/, which
        is_analyzed derives from the file name it is given."""
        mock_backend = MagicMock()
        mock_backend.is_analyzed.return_value = True
        mock_backend.decompile.return_value = "void func() {}"

        with patch.dict(sys.modules, {"retools.pyghidra_backend": mock_backend}):
            from importlib import reload
            import decompiler
            reload(decompiler)
            result = decompiler.decompile(
                str(tmp_path / "sl.common.dll"), 0x180001000,
                backend="auto", project_dir=str(tmp_path))

        assert result == "void func() {}"
        mock_backend.is_analyzed.assert_called_once_with(
            str(tmp_path / "ghidra"), "sl.common.dll")
