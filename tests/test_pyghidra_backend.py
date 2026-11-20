"""Tests for retools/pyghidra_backend.py -- pyghidra headless Ghidra backend."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


# ---------------------------------------------------------------------------
# _ensure_java_env
# ---------------------------------------------------------------------------

class TestJavaForPyghidra:
    """pyghidra takes JAVA_HOME_OVERRIDE, else runs whatever `java` is on PATH; it does not read JAVA_HOME."""

    @pytest.fixture
    def no_override(self, monkeypatch):
        # Set before deleting, so that monkeypatch also takes back a value the code under test writes
        monkeypatch.setenv("JAVA_HOME_OVERRIDE", "")
        monkeypatch.delenv("JAVA_HOME_OVERRIDE")

    def test_the_resolved_jdk_is_handed_to_pyghidra(self, no_override, tmp_path, monkeypatch):
        import os
        import jdk
        import pyghidra_backend
        monkeypatch.setattr(jdk, "find_jdk", lambda: jdk.Jdk(tmp_path / "jdk", 21))

        pyghidra_backend._ensure_java_env()

        assert os.environ["JAVA_HOME_OVERRIDE"] == str(tmp_path / "jdk")

    def test_nothing_is_handed_over_without_a_jdk(self, no_override, monkeypatch):
        import os
        import jdk
        import pyghidra_backend
        monkeypatch.setattr(jdk, "find_jdk", lambda: None)

        pyghidra_backend._ensure_java_env()

        assert "JAVA_HOME_OVERRIDE" not in os.environ

    def test_an_override_the_user_set_is_kept(self, monkeypatch):
        import os
        import jdk
        import pyghidra_backend
        monkeypatch.setenv("JAVA_HOME_OVERRIDE", "C:/my/jdk")
        monkeypatch.setattr(jdk, "find_jdk", lambda: pytest.fail("resolved a JDK over the user's override"))

        pyghidra_backend._ensure_java_env()

        assert os.environ["JAVA_HOME_OVERRIDE"] == "C:/my/jdk"


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
        counts, _, funcs = _export(tmp_path, _fake_program([_FakeFunc(0x148001000, "Foo")]))
        assert counts["funcs"] == 1
        assert funcs == [("Foo", "void Foo(void)", "ghidra")]

    def test_export_writes_imported_and_user_defined_labels(self, tmp_path):
        program = _fake_program(
            [_FakeFunc(0x401000, "Foo")],
            [_FakeSym(0x8D27D8, "g_basicGame", "Label", "IMPORTED"),
             _FakeSym(0x8CC4AC, "g_game", "Label", "USER_DEFINED")],
        )
        _, names, _ = _export(tmp_path, program)
        assert names == [
            (0x401000, "Foo", "ghidra"),
            (0x8CC4AC, "g_game", "ghidra"),
            (0x8D27D8, "g_basicGame", "ghidra"),
        ]

    def test_export_writes_both_names_for_one_address(self, tmp_path):
        program = _fake_program(
            [],
            [_FakeSym(0x8D27D8, "g_basicGame", "Label", "IMPORTED"),
             _FakeSym(0x8D27D8, "g_basicGame_kb", "Label", "USER_DEFINED")],
        )
        _, names, _ = _export(tmp_path, program)
        assert [n[1] for n in names] == ["g_basicGame", "g_basicGame_kb"]

    def test_export_qualifies_class_scoped_labels(self, tmp_path):
        program = _fake_program(
            [],
            [_FakeSym(0x8C1AE8, "fTimeMultiplier", "Label", "IMPORTED", namespace="rglConfig::Campaign"),
             _FakeSym(0x8D27D8, "g_basicGame", "Label", "IMPORTED")],
        )
        _, names, _ = _export(tmp_path, program)
        assert [n[1] for n in names] == ["rglConfig::Campaign::fTimeMultiplier", "g_basicGame"]

    def test_export_skips_default_analysis_and_non_label_symbols(self, tmp_path):
        program = _fake_program(
            [],
            [_FakeSym(0x900000, "DAT_00900000", "Label", "DEFAULT"),
             _FakeSym(0x900010, "switchD_00401234", "Label", "ANALYSIS"),
             _FakeSym(0x401000, "Foo", "Function", "IMPORTED"),
             _FakeSym(0x401004, "param_1", "Parameter", "USER_DEFINED")],
        )
        _, names, _ = _export(tmp_path, program)
        assert names == []


# ---------------------------------------------------------------------------
# kb-apply / _kb_apply_program
# ---------------------------------------------------------------------------

class TestKbApplyProgram:
    def test_applies_function_name_and_global(self, monkeypatch):
        import sys
        import types
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))
        from pyghidra_backend import _kb_apply_program
        from kb import parse_kb

        for name in ("ghidra", "ghidra.program", "ghidra.program.model", "ghidra.program.model.symbol"):
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))

        class _SourceType:
            USER_DEFINED = object()

        monkeypatch.setattr(sys.modules["ghidra.program.model.symbol"], "SourceType", _SourceType, raising=False)

        applied = {"names": [], "labels": []}

        class FakeAddr:
            def __init__(self, off): self._off = off

        class FakeAddrSpace:
            def getAddress(self, off): return FakeAddr(off)

        class FakeAddrFactory:
            def getDefaultAddressSpace(self): return FakeAddrSpace()

        class FakeFunc:
            def setName(self, name, src): applied["names"].append(name)

        class FakeListing:
            # A real function lives at 0x401000; 0x402000 is a data address
            # (e.g. an RTTI vtable) with no containing function.
            def getFunctionContaining(self, addr):
                return FakeFunc() if addr._off == 0x401000 else None

        class FakeSymbolTable:
            def createLabel(self, addr, name, src):
                applied["labels"].append(name)
                return object()

        class FakeProgram:
            def getAddressFactory(self): return FakeAddrFactory()
            def getListing(self): return FakeListing()
            def getSymbolTable(self): return FakeSymbolTable()

        kb = parse_kb("@ 0x401000 void Foo(void);\n"
                      "@ 0x402000 SomeClass_vtable;\n"
                      "$ 0x7C5548 int g_x\n")
        counts = _kb_apply_program(FakeProgram(), kb,
                                   apply_prototypes=False, apply_types=False)
        assert "Foo" in applied["names"]            # existing function renamed
        assert "SomeClass_vtable" in applied["labels"]  # data @ -> label, not a bogus function
        assert "g_x" in applied["labels"]           # $ global -> label
        assert counts["functions"] == 1
        assert counts["labels"] == 1
        assert counts["globals"] == 1


# ---------------------------------------------------------------------------
# _route_daemon
# ---------------------------------------------------------------------------

class TestRouteDaemon:
    """Covers all four branches of _route_daemon without Ghidra or sockets."""

    def test_daemon_present_returns_response(self, monkeypatch):
        from pyghidra_backend import _route_daemon
        import ghidra_client

        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: True)
        monkeypatch.setattr(
            ghidra_client, "send_command",
            lambda project_dir, cmd, timeout=None: {"ok": True, "text": "ROUTED"},
        )
        result = _route_daemon("TestGame", {"cmd": "decompile", "binary": "b.exe", "va": 1})
        assert result == {"ok": True, "text": "ROUTED"}

    def test_cold_env_no_daemon_returns_none(self, monkeypatch):
        from pyghidra_backend import _route_daemon
        import ghidra_client

        monkeypatch.setenv("RETOOLS_GHIDRA_COLD", "1")
        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: False)
        # No daemon owns the lock -> cold path proceeds (None), nothing sent.
        assert _route_daemon("TestGame", {"cmd": "decompile"}) is None

    def test_cold_env_refuses_when_daemon_holds_lock(self, monkeypatch):
        """--cold cannot open a project this project's own daemon already holds
        (the Ghidra project lock is exclusive). It must refuse with a clean
        error instead of falling through to a cold open that dies with a raw
        LockException -- and must never contact the daemon in cold mode."""
        from pyghidra_backend import _route_daemon
        import ghidra_client

        monkeypatch.setenv("RETOOLS_GHIDRA_COLD", "1")
        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: True)

        def _must_not_send(*args, **kwargs):
            raise AssertionError("cold mode must not contact the daemon")

        monkeypatch.setattr(ghidra_client, "send_command", _must_not_send)
        routed = _route_daemon("TestGame", {"cmd": "decompile"})
        assert routed is not None
        assert routed["ok"] is False
        assert "cold" in routed["error"].lower()

    def test_dead_daemon_returns_none(self, monkeypatch):
        from pyghidra_backend import _route_daemon
        import ghidra_client

        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: False)
        assert _route_daemon("TestGame", {"cmd": "decompile"}) is None

    def test_send_error_returns_none(self, monkeypatch):
        from pyghidra_backend import _route_daemon
        import ghidra_client

        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: True)

        def _raise(project_dir, cmd, timeout=None):
            raise ConnectionError("boom")

        monkeypatch.setattr(ghidra_client, "send_command", _raise)
        assert _route_daemon("TestGame", {"cmd": "decompile"}) is None

    def test_corrupted_state_degrades_to_none(self, monkeypatch):
        """A malformed state file raising inside is_daemon_alive still degrades cleanly."""
        from pyghidra_backend import _route_daemon
        import ghidra_client

        def _raise(project_dir):
            raise TypeError("'>' not supported between instances of 'str' and 'int'")

        monkeypatch.setattr(ghidra_client, "is_daemon_alive", _raise)
        assert _route_daemon("TestGame", {"cmd": "decompile"}) is None


class TestDecompileRouting:
    """Proves decompile() actually uses _route_daemon's result when present."""

    def test_decompile_uses_daemon_when_routed(self, tmp_path, monkeypatch):
        import pyghidra_backend

        monkeypatch.setattr(pyghidra_backend, "is_analyzed", lambda project_dir, binary_name: True)
        monkeypatch.setattr(
            pyghidra_backend, "_route_daemon",
            lambda project_dir, cmd: {"ok": True, "text": "ROUTED"},
        )
        result = pyghidra_backend.decompile(str(tmp_path / "ghidra"), "test.exe", 0x401000)
        assert result == "ROUTED"


class TestRouteDaemonSafety:
    def test_wrong_project_response_falls_back_to_cold(self, monkeypatch):
        """A daemon that reports it serves a different project must not answer;
        _route_daemon returns None so the caller takes the cold path."""
        from pyghidra_backend import _route_daemon
        import ghidra_client

        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: True)
        monkeypatch.setattr(
            ghidra_client, "send_command",
            lambda project_dir, cmd, timeout=None: {"ok": False, "wrong_project": True},
        )
        assert _route_daemon(str(Path("patches") / "G" / "ghidra"), {"cmd": "decompile"}) is None

    def test_timeout_errors_not_silent_cold_retry(self, monkeypatch):
        """A timeout on a live daemon may have already run the command; falling
        through to a cold re-run would double-execute, so it must return an
        error response (not None, which would trigger the cold path)."""
        import socket
        from pyghidra_backend import _route_daemon
        import ghidra_client

        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: True)

        def _timeout(project_dir, cmd, timeout=None):
            raise socket.timeout("timed out")

        monkeypatch.setattr(ghidra_client, "send_command", _timeout)
        routed = _route_daemon(str(Path("patches") / "G" / "ghidra"), {"cmd": "export"})
        assert routed is not None
        assert routed["ok"] is False
        assert "did not reply" in routed["error"]

    def test_injects_game_identity(self, monkeypatch):
        """_route_daemon tags the command with the game derived from project_dir
        so the daemon can reject cross-project routing."""
        from pyghidra_backend import _route_daemon
        import ghidra_client

        seen = {}
        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: True)
        monkeypatch.setattr(
            ghidra_client, "send_command",
            lambda project_dir, cmd, timeout=None: seen.update(cmd) or {"ok": True},
        )
        _route_daemon(str(Path("patches") / "MyGame" / "ghidra"),
                      {"cmd": "export", "binary": "game.exe", "db": "patches/MyGame/index.db"})
        assert seen.get("game") == "MyGame"
        # Paths are absolutised so the daemon can't resolve them against a
        # different cwd than the client's.
        assert Path(seen["binary"]).is_absolute()
        assert Path(seen["db"]).is_absolute()


class TestIterBlocks:
    def test_func_ea_is_containing_function_entry(self, monkeypatch):
        """Every basic block must be keyed by its owning function's entry point,
        not by the block's own start address."""
        import sys
        import types
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

        for name in ("ghidra", "ghidra.program", "ghidra.program.model",
                     "ghidra.program.model.block", "ghidra.util", "ghidra.util.task"):
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))

        class FakeAddr:
            def __init__(self, off): self._off = off
            def getOffset(self): return self._off

        class FakeBlock:
            def __init__(self, start, end):
                self._start = FakeAddr(start)
                self._end = FakeAddr(end - 1)
            def getFirstStartAddress(self): return self._start
            def getMaxAddress(self): return self._end

        class FakeIter:
            def __init__(self, blocks): self._b = list(blocks)
            def hasNext(self): return bool(self._b)
            def next(self): return self._b.pop(0)

        class FakeModel:
            def __init__(self, program): pass
            def getCodeBlocks(self, monitor):
                return FakeIter([FakeBlock(0x401000, 0x401020),
                                 FakeBlock(0x401020, 0x401055)])

        class FakeFunc:
            def getEntryPoint(self): return FakeAddr(0x401000)

        class FakeFuncMgr:
            def getFunctionContaining(self, addr): return FakeFunc()

        class FakeProgram:
            def getFunctionManager(self): return FakeFuncMgr()

        monkeypatch.setattr(sys.modules["ghidra.program.model.block"],
                            "BasicBlockModel", FakeModel, raising=False)
        monkeypatch.setattr(sys.modules["ghidra.util.task"],
                            "ConsoleTaskMonitor", lambda: object(), raising=False)

        from pyghidra_backend import _iter_blocks
        rows = list(_iter_blocks(FakeProgram()))
        assert [r["func_ea"] for r in rows] == [0x401000, 0x401000]
        assert [r["start_ea"] for r in rows] == [0x401000, 0x401020]


class TestIterXrefs:
    def test_containing_function_is_cached_across_consecutive_refs(self):
        """Consecutive refs in the same function must not each pay a manager
        lookup; the containing function is cached and re-tested by body."""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))
        from pyghidra_backend import _iter_xrefs

        class FakeAddr:
            def __init__(self, off): self._off = off
            def getOffset(self): return self._off

        class FakeType:
            def isCall(self): return True
            def isJump(self): return False
            def isData(self): return False

        class FakeRef:
            def __init__(self, frm, to):
                self._f = FakeAddr(frm)
                self._t = FakeAddr(to)
            def getFromAddress(self): return self._f
            def getToAddress(self): return self._t
            def getReferenceType(self): return FakeType()

        class FakeBody:
            def contains(self, addr): return 0x401000 <= addr.getOffset() < 0x402000

        class FakeFunc:
            def getBody(self): return FakeBody()
            def getEntryPoint(self): return FakeAddr(0x401000)

        class FakeRefIter:
            def __init__(self, refs): self._r = list(refs)
            def hasNext(self): return bool(self._r)
            def next(self): return self._r.pop(0)

        class FakeRefMgr:
            def getReferenceIterator(self, addr):
                return FakeRefIter([FakeRef(0x401010, 0x500000), FakeRef(0x401030, 0x500004)])

        calls = {"n": 0}

        class FakeFuncMgr:
            def getFunctionContaining(self, addr):
                calls["n"] += 1
                return FakeFunc()

        class FakeProgram:
            def getReferenceManager(self): return FakeRefMgr()
            def getFunctionManager(self): return FakeFuncMgr()
            def getMinAddress(self): return FakeAddr(0)

        rows = list(_iter_xrefs(FakeProgram()))
        assert len(rows) == 2
        assert all(r["from_func"] == 0x401000 for r in rows)
        assert calls["n"] == 1  # second ref served from cache


class TestExportCLIDbPath:
    def test_export_db_defaults_to_project_dir(self, tmp_path, monkeypatch):
        """`export --project patches/MyGame` (no --db) must write to
        patches/MyGame/index.db, not patches/<binary-stem>/index.db."""
        import pyghidra_backend
        captured = {}
        monkeypatch.setattr(
            pyghidra_backend, "export",
            lambda ghidra_dir, binary, db_path: captured.update(db=db_path) or "ok",
        )
        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        proj = tmp_path / "patches" / "MyGame"
        sys.argv = ["pyghidra_backend", "export", str(binary), "--project", str(proj)]
        with pytest.raises(SystemExit):
            pyghidra_backend.main()
        assert captured["db"] == str(proj / "index.db")


class _Addr:
    def __init__(self, off): self._off = off
    def getOffset(self): return self._off


class _FakeBody:
    def __init__(self, start, end, n):
        self._max = _Addr(end)
        self._n = n
    def getMaxAddress(self): return self._max
    def getNumAddresses(self): return self._n


class _FakeSig:
    def getPrototypeString(self): return "void Foo(void)"


class _FakeFunc:
    def __init__(self, ep, name):
        self._ep = _Addr(ep)
        self._name = name
    def getEntryPoint(self): return self._ep
    def getName(self): return self._name
    def getBody(self): return _FakeBody(self._ep.getOffset(), self._ep.getOffset() + 0x40, 0x40)
    def getSignature(self): return _FakeSig()


class _FakeSym:
    """str(getSymbolType()) / str(getSource()) mirror Ghidra's toString: 'Label', 'IMPORTED'.

    getName(True) prefixes the parent namespace like Ghidra's Symbol.getName(includeNamespace).
    """
    def __init__(self, addr, name, sym_type, source, namespace=""):
        self._addr, self._name, self._type, self._source = _Addr(addr), name, sym_type, source
        self._namespace = namespace
    def getAddress(self): return self._addr
    def getName(self, include_namespace=False):
        return f"{self._namespace}::{self._name}" if include_namespace and self._namespace else self._name
    def getSymbolType(self): return self._type
    def getSource(self): return self._source


class _Iter:
    def __init__(self, items): self._items = list(items)
    def hasNext(self): return bool(self._items)
    def next(self): return self._items.pop(0)


class _RefType:
    def __init__(self, kind): self._kind = kind
    def isCall(self): return self._kind == "call"
    def isJump(self): return self._kind == "jump"
    def isData(self): return self._kind == "data"


class _Ref:
    def __init__(self, frm, to, kind):
        self._f, self._t, self._k = _Addr(frm), _Addr(to), _RefType(kind)
    def getFromAddress(self): return self._f
    def getToAddress(self): return self._t
    def getReferenceType(self): return self._k


def _export(tmp_path, program):
    from index import GameIndex
    from pyghidra_backend import _export_program

    gi = GameIndex(str(tmp_path / "index.db"))
    counts = _export_program(program, gi, xrefs=[], blocks=[])
    names = sorted(gi._conn.execute("SELECT address, name, source FROM names").fetchall())
    funcs = gi._conn.execute("SELECT name, prototype, source FROM funcs").fetchall()
    gi.close()
    return counts, names, funcs


def _fake_program(funcs, symbols=()):
    class FuncMgr:
        def getFunctions(self, forward): return list(funcs)

    class SymTab:
        def getSymbolIterator(self, forward): return list(symbols)

    class Program:
        def getFunctionManager(self): return FuncMgr()
        def getSymbolTable(self): return SymTab()

    return Program()


def _ref_program(refs, funcs):
    """funcs: (entry, end) ranges; a ref outside every range has no containing function."""
    class Body:
        def __init__(self, lo, hi): self.lo, self.hi = lo, hi
        def contains(self, addr): return self.lo <= addr.getOffset() < self.hi

    class Func:
        def __init__(self, lo, hi): self.lo, self.hi = lo, hi
        def getBody(self): return Body(self.lo, self.hi)
        def getEntryPoint(self): return _Addr(self.lo)

    class FuncMgr:
        def getFunctionContaining(self, addr):
            return next((Func(lo, hi) for lo, hi in funcs if lo <= addr.getOffset() < hi), None)

    class RefMgr:
        def getReferenceIterator(self, addr): return _Iter(refs)

    class Program:
        def getReferenceManager(self): return RefMgr()
        def getFunctionManager(self): return FuncMgr()
        def getMinAddress(self): return _Addr(0)

    return Program()


class TestExport:
    def _setup(self, tmp_path, monkeypatch, analyzed=True, routed=None):
        import pyghidra_backend as pb
        monkeypatch.setattr(pb, "is_analyzed", lambda proj, name: analyzed)
        sent = []
        monkeypatch.setattr(pb, "_route_daemon", lambda proj, cmd, timeout=None: sent.append(cmd) or routed)
        return pb, sent

    def test_unanalyzed_binary_is_an_error(self, tmp_path, monkeypatch):
        pb, sent = self._setup(tmp_path, monkeypatch, analyzed=False)
        assert pb.export("proj", "C:/g/game.exe", "x.db") == "[error] no analyzed project for game.exe in proj"
        assert sent == []

    def test_daemon_result_is_reported(self, tmp_path, monkeypatch):
        pb, sent = self._setup(tmp_path, monkeypatch, routed={"ok": True, "counts": {"funcs": 2, "names": 3}})
        assert pb.export("proj", "game.exe", "x.db") == "Export complete: funcs=2, names=3 -> x.db"
        assert sent == [{"cmd": "export", "binary": "game.exe", "db": "x.db"}]

    def test_daemon_error_is_reported(self, tmp_path, monkeypatch):
        pb, _ = self._setup(tmp_path, monkeypatch, routed={"ok": False, "error": "boom"})
        assert pb.export("proj", "game.exe", "x.db") == "[error] boom"

    def test_cold_path_needs_pyghidra_and_ghidra_dir(self, tmp_path, monkeypatch):
        pb, _ = self._setup(tmp_path, monkeypatch)
        monkeypatch.setattr(pb, "_import_pyghidra", lambda: None)
        assert pb.export("proj", "game.exe", "x.db") == "[error] pyghidra is not installed"
        monkeypatch.setattr(pb, "_import_pyghidra", lambda: object())
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        assert pb.export("proj", "game.exe", "x.db") == "[error] GHIDRA_INSTALL_DIR environment variable not set"

    def test_cold_path_exports_the_opened_program(self, tmp_path, monkeypatch):
        pb, _ = self._setup(tmp_path, monkeypatch)
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
        opened = []
        program = _fake_program([_FakeFunc(0x401000, "Foo")])

        class Ctx:
            def __enter__(self):
                return type("Flat", (), {"getCurrentProgram": lambda self: program})()
            def __exit__(self, *a): pass

        class Pg:
            def start(self): pass
            def open_program(self, binary, **kw):
                opened.append((binary, kw))
                return Ctx()

        monkeypatch.setattr(pb, "_import_pyghidra", lambda: Pg())
        monkeypatch.setattr(pb, "_iter_xrefs", lambda p: iter(()))
        monkeypatch.setattr(pb, "_iter_blocks", lambda p: iter(()))
        db = str(tmp_path / "index.db")
        out = pb.export(str(tmp_path / "proj"), "C:/g/game.exe", db)
        assert out == f"Export complete: funcs=1, names=1, xrefs=0, blocks=0 -> {db}"
        assert opened == [("C:/g/game.exe", {"project_location": str(tmp_path / "proj"),
                                              "project_name": "game", "analyze": False})]


class TestExportFuncRows:
    def test_function_end_is_one_past_its_last_address(self, tmp_path):
        from index import GameIndex
        from pyghidra_backend import _export_program
        gi = GameIndex(str(tmp_path / "index.db"))
        _export_program(_fake_program([_FakeFunc(0x401000, "Foo")]), gi, xrefs=[], blocks=[])
        row = gi._conn.execute("SELECT address, end_ea, size FROM funcs").fetchone()
        gi.close()
        assert row == (0x401000, 0x401041, 0x40)   # _FakeBody's last address is entry + 0x40


class TestIterBlockRows:
    def test_block_end_is_exclusive_and_size_is_the_span(self, monkeypatch):
        import types
        for name in ("ghidra", "ghidra.program", "ghidra.program.model",
                     "ghidra.program.model.block", "ghidra.util", "ghidra.util.task"):
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))

        class Block:
            def __init__(self, start, last): self._s, self._m = _Addr(start), _Addr(last)
            def getFirstStartAddress(self): return self._s
            def getMaxAddress(self): return self._m

        class Model:
            def __init__(self, program): pass
            def getCodeBlocks(self, monitor): return _Iter([Block(0x401000, 0x40101F)])

        class FuncMgr:
            def getFunctionContaining(self, addr): return None

        class Program:
            def getFunctionManager(self): return FuncMgr()

        monkeypatch.setattr(sys.modules["ghidra.program.model.block"], "BasicBlockModel", Model, raising=False)
        monkeypatch.setattr(sys.modules["ghidra.util.task"], "ConsoleTaskMonitor", lambda: None, raising=False)
        from pyghidra_backend import _iter_blocks
        assert list(_iter_blocks(Program())) == [
            {"func_ea": 0x401000, "start_ea": 0x401000, "end_ea": 0x401020, "size": 0x20}]


class TestIterXrefRows:
    def test_rows_carry_kind_code_flag_and_containing_function(self):
        from pyghidra_backend import _iter_xrefs
        refs = [_Ref(0x401010, 0x402000, "call"), _Ref(0x401020, 0x401080, "jump"),
                _Ref(0x401030, 0x500000, "data"), _Ref(0x300000, 0x402000, "call"),
                _Ref(0x402010, 0x401000, "call")]
        rows = list(_iter_xrefs(_ref_program(refs, [(0x401000, 0x401100), (0x402000, 0x402100)])))
        assert rows == [
            {"from_ea": 0x401010, "to_ea": 0x402000, "type": "call", "is_code": 1, "from_func": 0x401000},
            {"from_ea": 0x401020, "to_ea": 0x401080, "type": "jump", "is_code": 1, "from_func": 0x401000},
            {"from_ea": 0x401030, "to_ea": 0x500000, "type": "data", "is_code": 0, "from_func": 0x401000},
            {"from_ea": 0x402010, "to_ea": 0x401000, "type": "call", "is_code": 1, "from_func": 0x402000},
        ]


class TestKbApplyUnparsedPrototype:
    def test_a_prototype_the_parser_returns_nothing_for_is_skipped(self, monkeypatch):
        import sys
        import types
        from pyghidra_backend import _kb_apply_program
        from kb import parse_kb

        for name in ("ghidra", "ghidra.program", "ghidra.program.model", "ghidra.program.model.symbol",
                     "ghidra.app", "ghidra.app.util", "ghidra.app.util.parser", "ghidra.util",
                     "ghidra.util.task", "ghidra.app.cmd", "ghidra.app.cmd.function"):
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        commands = []

        class Parser:
            def __init__(self, dtm, service): pass
            def parse(self, original, text): return None

        class Program:
            def getAddressFactory(self):
                space = types.SimpleNamespace(getAddress=lambda off: off)
                return types.SimpleNamespace(getDefaultAddressSpace=lambda: space)
            def getListing(self):
                func = types.SimpleNamespace(setName=lambda name, src: None, getSignature=lambda: None)
                return types.SimpleNamespace(getFunctionContaining=lambda addr: func)
            def getSymbolTable(self): return None
            def getDataTypeManager(self): return None

        monkeypatch.setattr(sys.modules["ghidra.program.model.symbol"], "SourceType",
                            types.SimpleNamespace(USER_DEFINED=object()), raising=False)
        monkeypatch.setattr(sys.modules["ghidra.app.util.parser"], "FunctionSignatureParser", Parser, raising=False)
        monkeypatch.setattr(sys.modules["ghidra.util.task"], "ConsoleTaskMonitor", lambda: None, raising=False)
        monkeypatch.setattr(sys.modules["ghidra.app.cmd.function"], "ApplyFunctionSignatureCmd",
                            lambda *args: commands.append(args), raising=False)

        counts = _kb_apply_program(Program(), parse_kb("@ 0x401000 void Foo(int a);\n"), apply_types=False)
        assert commands == []
        assert (counts["functions"], counts["prototypes"], counts["skipped"]) == (1, 0, 1)
