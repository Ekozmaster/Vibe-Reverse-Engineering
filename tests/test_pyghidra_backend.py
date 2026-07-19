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

    def test_cold_env_returns_none(self, monkeypatch):
        from pyghidra_backend import _route_daemon
        import ghidra_client

        monkeypatch.setenv("RETOOLS_GHIDRA_COLD", "1")
        # Even a daemon that would answer "alive" must not be reached.
        monkeypatch.setattr(ghidra_client, "is_daemon_alive", lambda project_dir: True)
        assert _route_daemon("TestGame", {"cmd": "decompile"}) is None

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
