"""Tests for retools/pyghidra_backend.py -- pyghidra headless Ghidra backend."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


# ---------------------------------------------------------------------------
# is_analyzed
# ---------------------------------------------------------------------------

class TestIsAnalyzed:
    def test_missing_dir(self, tmp_path):
        from pyghidra_backend import is_analyzed
        assert is_analyzed(str(tmp_path / "nonexistent"), "test.exe") is False

    def test_missing_gpr(self, tmp_path):
        from pyghidra_backend import is_analyzed
        project_dir = tmp_path / "ghidra"
        project_dir.mkdir()
        assert is_analyzed(str(project_dir), "test.exe") is False

    def test_empty_rep(self, tmp_path):
        from pyghidra_backend import is_analyzed
        project_dir = tmp_path / "ghidra"
        project_dir.mkdir()
        (project_dir / "test.gpr").write_text("")
        (project_dir / "test.rep").mkdir()
        assert is_analyzed(str(project_dir), "test.exe") is False

    def test_valid_project(self, tmp_path):
        from pyghidra_backend import is_analyzed
        project_dir = tmp_path / "ghidra"
        # pyghidra nests: project_dir/stem/stem.gpr
        nested = project_dir / "test"
        nested.mkdir(parents=True)
        (nested / "test.gpr").write_text("project")
        rep = nested / "test.rep"
        rep.mkdir()
        (rep / "data").write_text("data")
        assert is_analyzed(str(project_dir), "test.exe") is True


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_calls_start_and_open_program(self, tmp_path, monkeypatch):
        from pyghidra_backend import analyze
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))

        mock_pyghidra = MagicMock()
        mock_ctx = MagicMock()
        mock_pyghidra.open_program.return_value.__enter__ = MagicMock(return_value=mock_ctx)
        mock_pyghidra.open_program.return_value.__exit__ = MagicMock(return_value=False)
        monkeypatch.setitem(sys.modules, "pyghidra", mock_pyghidra)

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)
        result = analyze(str(binary), str(tmp_path / "ghidra"))

        mock_pyghidra.start.assert_called_once()
        mock_pyghidra.open_program.assert_called_once()
        assert "[error]" not in result

    def test_creates_project_dir(self, tmp_path, monkeypatch):
        from pyghidra_backend import analyze
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))

        mock_pyghidra = MagicMock()
        mock_ctx = MagicMock()
        mock_pyghidra.open_program.return_value.__enter__ = MagicMock(return_value=mock_ctx)
        mock_pyghidra.open_program.return_value.__exit__ = MagicMock(return_value=False)
        monkeypatch.setitem(sys.modules, "pyghidra", mock_pyghidra)

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)
        project_dir = tmp_path / "ghidra" / "sub"
        result = analyze(str(binary), str(project_dir))

        assert project_dir.exists()

    def test_error_no_ghidra_install_dir(self, tmp_path, monkeypatch):
        from pyghidra_backend import analyze
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        # Patch _ensure_ghidra_env to not auto-detect from tools/
        monkeypatch.setattr("pyghidra_backend._ensure_ghidra_env", lambda: None)

        mock_pyghidra = MagicMock()
        monkeypatch.setitem(sys.modules, "pyghidra", mock_pyghidra)

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)
        result = analyze(str(binary), str(tmp_path / "ghidra"))

        assert result.startswith("[error]")

    def test_error_pyghidra_missing(self, tmp_path, monkeypatch):
        from pyghidra_backend import analyze
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
        monkeypatch.delitem(sys.modules, "pyghidra", raising=False)

        with patch("pyghidra_backend._import_pyghidra", return_value=None):
            binary = tmp_path / "test.exe"
            binary.write_bytes(b"MZ" + b"\x00" * 100)
            result = analyze(str(binary), str(tmp_path / "ghidra"))

        assert result.startswith("[error]")


# ---------------------------------------------------------------------------
# decompile
# ---------------------------------------------------------------------------

def _setup_ghidra_project(tmp_path):
    """Create a fake valid Ghidra project on disk for decompile() checks."""
    project_dir = tmp_path / "ghidra"
    # pyghidra nests: project_dir/stem/stem.gpr
    nested = project_dir / "test"
    nested.mkdir(parents=True)
    (nested / "test.gpr").write_text("project")
    rep = nested / "test.rep"
    rep.mkdir()
    (rep / "data").write_text("data")
    return project_dir


def _mock_java_modules(monkeypatch):
    """Inject mock Java modules (ghidra.app.decompiler, ghidra.util.task)."""
    mock_decomp_mod = MagicMock()
    mock_task_mod = MagicMock()

    mock_ifc = MagicMock()
    mock_decomp_mod.DecompInterface.return_value = mock_ifc

    mock_monitor = MagicMock()
    mock_task_mod.ConsoleTaskMonitor.return_value = mock_monitor

    monkeypatch.setitem(sys.modules, "ghidra", MagicMock())
    monkeypatch.setitem(sys.modules, "ghidra.app", MagicMock())
    monkeypatch.setitem(sys.modules, "ghidra.app.decompiler", mock_decomp_mod)
    monkeypatch.setitem(sys.modules, "ghidra.util", MagicMock())
    monkeypatch.setitem(sys.modules, "ghidra.util.task", mock_task_mod)

    return mock_ifc, mock_monitor


class TestDecompile:
    def test_returns_c_output(self, tmp_path, monkeypatch):
        from pyghidra_backend import decompile
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))

        project_dir = _setup_ghidra_project(tmp_path)
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)

        mock_pyghidra = MagicMock()
        mock_flat_api = MagicMock()
        mock_program = MagicMock()
        mock_pyghidra.open_program.return_value.__enter__ = MagicMock(return_value=mock_flat_api)
        mock_pyghidra.open_program.return_value.__exit__ = MagicMock(return_value=False)
        mock_flat_api.getCurrentProgram.return_value = mock_program
        monkeypatch.setitem(sys.modules, "pyghidra", mock_pyghidra)

        mock_ifc, mock_monitor = _mock_java_modules(monkeypatch)

        # Mock the listing / function lookup
        mock_func = MagicMock()
        mock_listing = MagicMock()
        mock_program.getListing.return_value = mock_listing
        mock_listing.getFunctionContaining.return_value = mock_func

        # Mock decompile result
        mock_result = MagicMock()
        mock_result.getDecompiledFunction.return_value.getC.return_value = (
            "int foo(void) {\n  return 42;\n}"
        )
        mock_ifc.decompileFunction.return_value = mock_result

        result = decompile(str(project_dir), str(binary), 0x401000)
        assert "int foo(void)" in result
        assert "[error]" not in result

    def test_error_no_function(self, tmp_path, monkeypatch):
        from pyghidra_backend import decompile
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))

        project_dir = _setup_ghidra_project(tmp_path)
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)

        mock_pyghidra = MagicMock()
        mock_flat_api = MagicMock()
        mock_program = MagicMock()
        mock_pyghidra.open_program.return_value.__enter__ = MagicMock(return_value=mock_flat_api)
        mock_pyghidra.open_program.return_value.__exit__ = MagicMock(return_value=False)
        mock_flat_api.getCurrentProgram.return_value = mock_program
        monkeypatch.setitem(sys.modules, "pyghidra", mock_pyghidra)

        mock_ifc, mock_monitor = _mock_java_modules(monkeypatch)

        # No function at this address
        mock_listing = MagicMock()
        mock_program.getListing.return_value = mock_listing
        mock_listing.getFunctionContaining.return_value = None

        result = decompile(str(project_dir), str(binary), 0x401000)
        assert result.startswith("[error]")


# ---------------------------------------------------------------------------
# CLI (main)
# ---------------------------------------------------------------------------

class TestCLI:
    def test_status_not_analyzed(self, tmp_path, capsys):
        from pyghidra_backend import main
        with pytest.raises(SystemExit, match="0"):
            sys.argv = [
                "pyghidra_backend",
                "status",
                str(tmp_path / "test.exe"),
                "--project", "TestProj",
            ]
            main()
        captured = capsys.readouterr()
        assert "not analyzed" in captured.out.lower()

    def test_status_analyzed(self, tmp_path, capsys):
        from pyghidra_backend import main
        # Set up a valid project under patches/TestProj/ghidra/test/
        nested = tmp_path / "patches" / "TestProj" / "ghidra" / "test"
        nested.mkdir(parents=True)
        (nested / "test.gpr").write_text("project")
        rep = nested / "test.rep"
        rep.mkdir()
        (rep / "data").write_text("data")

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)

        with pytest.raises(SystemExit, match="0"):
            sys.argv = [
                "pyghidra_backend",
                "status",
                str(binary),
                "--project", str(tmp_path / "patches" / "TestProj"),
            ]
            main()
        captured = capsys.readouterr()
        assert "analyzed" in captured.out.lower()

    def test_analyze_subcommand(self, tmp_path, capsys, monkeypatch):
        from pyghidra_backend import main
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))

        mock_pyghidra = MagicMock()
        mock_ctx = MagicMock()
        mock_pyghidra.open_program.return_value.__enter__ = MagicMock(return_value=mock_ctx)
        mock_pyghidra.open_program.return_value.__exit__ = MagicMock(return_value=False)
        monkeypatch.setitem(sys.modules, "pyghidra", mock_pyghidra)

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)

        with pytest.raises(SystemExit, match="0"):
            sys.argv = [
                "pyghidra_backend",
                "analyze",
                str(binary),
                "--project", str(tmp_path / "patches" / "TestProj"),
            ]
            main()
        captured = capsys.readouterr()
        assert "analysis complete" in captured.out.lower()

    def test_decompile_subcommand(self, tmp_path, capsys, monkeypatch):
        from pyghidra_backend import main
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))

        # Set up a valid project (nested: ghidra/test/test.gpr)
        nested = tmp_path / "patches" / "TestProj" / "ghidra" / "test"
        nested.mkdir(parents=True)
        (nested / "test.gpr").write_text("project")
        rep = nested / "test.rep"
        rep.mkdir()
        (rep / "data").write_text("data")

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)

        mock_pyghidra = MagicMock()
        mock_flat_api = MagicMock()
        mock_program = MagicMock()
        mock_pyghidra.open_program.return_value.__enter__ = MagicMock(return_value=mock_flat_api)
        mock_pyghidra.open_program.return_value.__exit__ = MagicMock(return_value=False)
        mock_flat_api.getCurrentProgram.return_value = mock_program
        monkeypatch.setitem(sys.modules, "pyghidra", mock_pyghidra)

        mock_ifc, _ = _mock_java_modules(monkeypatch)
        mock_func = MagicMock()
        mock_listing = MagicMock()
        mock_program.getListing.return_value = mock_listing
        mock_listing.getFunctionContaining.return_value = mock_func
        mock_result = MagicMock()
        mock_result.getDecompiledFunction.return_value.getC.return_value = "void bar(void) {}"
        mock_ifc.decompileFunction.return_value = mock_result

        with pytest.raises(SystemExit, match="0"):
            sys.argv = [
                "pyghidra_backend",
                "decompile",
                str(binary),
                "0x401000",
                "--project", str(tmp_path / "patches" / "TestProj"),
            ]
            main()
        captured = capsys.readouterr()
        assert "void bar(void)" in captured.out


# ---------------------------------------------------------------------------
# export / _export_program
# ---------------------------------------------------------------------------

class TestExportProgram:
    def test_export_program_writes_ghidra_rows(self, tmp_path):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))
        from pyghidra_backend import _export_program
        from index import GameIndex

        # --- minimal fakes mimicking the Ghidra API surface used by _export_program ---
        class FakeAddr:
            def __init__(self, off): self._off = off
            def getOffset(self): return self._off

        class FakeBody:
            def __init__(self, start, end, n):
                self._max = FakeAddr(end)
                self._n = n
            def getMaxAddress(self): return self._max
            def getNumAddresses(self): return self._n

        class FakeSig:
            def getPrototypeString(self): return "void Foo(void)"

        class FakeFunc:
            def __init__(self, ep, name):
                self._ep = FakeAddr(ep)
                self._name = name
            def getEntryPoint(self): return self._ep
            def getName(self): return self._name
            def getBody(self): return FakeBody(self._ep.getOffset(), self._ep.getOffset() + 0x40, 0x40)
            def getSignature(self): return FakeSig()

        class FakeFuncMgr:
            def getFunctions(self, forward): return [FakeFunc(0x148001000, "Foo")]

        class FakeProgram:
            def getFunctionManager(self): return FakeFuncMgr()

        gi = GameIndex(str(tmp_path / "index.db"))
        # _export_program must accept an optional iterables override so xrefs/blocks
        # (which need Ghidra-only classes) can be supplied empty in the fake path.
        counts = _export_program(FakeProgram(), gi, xrefs=[], blocks=[])
        assert counts["funcs"] == 1
        assert gi.counts()["funcs"] == 1
        row = gi._conn.execute("SELECT name, prototype, source FROM funcs").fetchone()
        gi.close()
        assert row[0] == "Foo"
        assert row[1] == "void Foo(void)"
        assert row[2] == "ghidra"
