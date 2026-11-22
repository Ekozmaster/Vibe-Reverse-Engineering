"""Tests for retools/ghidra_server.py -- daemon dispatch, identity, lifecycle.

These exercise the pure socket/dispatch logic; no Ghidra program is opened
(status/shutdown need none), so they run without a JDK.
"""

import json
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestIdentityHandshake:
    def test_rejects_foreign_game(self):
        import ghidra_server
        d = ghidra_server.GhidraDaemon("GameA")
        resp = d.handle({"cmd": "status", "game": "GameB"})
        assert resp == {"ok": False, "wrong_project": True, "error": "daemon serves 'GameA', not 'GameB'"}

    def test_accepts_matching_game(self):
        import ghidra_server
        d = ghidra_server.GhidraDaemon("GameA")
        resp = d.handle({"cmd": "status", "game": "GameA"})
        assert resp["ok"] is True

    def test_accepts_missing_game(self):
        import ghidra_server
        d = ghidra_server.GhidraDaemon("GameA")
        resp = d.handle({"cmd": "status"})
        assert resp["ok"] is True

    def test_unknown_command(self):
        import ghidra_server
        d = ghidra_server.GhidraDaemon("GameA")
        resp = d.handle({"cmd": "nope", "game": "GameA"})
        assert resp == {"ok": False, "error": "unknown command: nope"}


class TestServeLifecycle:
    def test_status_then_shutdown_over_socket(self, tmp_path, monkeypatch):
        import ghidra_server
        import ghidra_client

        # Ephemeral port so the test never collides with a real daemon.
        monkeypatch.setattr(ghidra_server, "PORT", 0)

        d = ghidra_server.GhidraDaemon("GameA", idle=30.0)
        d.project_dir = str(tmp_path / "ghidra")

        t = threading.Thread(target=d.serve, daemon=True)
        t.start()

        # Wait for the state file (written once the socket is bound).
        sp = ghidra_client.state_path(d.project_dir)
        for _ in range(200):
            if sp.exists():
                break
            time.sleep(0.01)
        assert sp.exists(), "daemon never wrote its state file"
        state = json.loads(sp.read_text())
        assert state["port"] != 0  # real bound port recorded, not the sentinel

        resp = ghidra_client.send_command(d.project_dir, {"cmd": "status", "game": "GameA"})
        assert resp["ok"] is True
        assert resp["game"] == "GameA"

        ghidra_client.send_command(d.project_dir, {"cmd": "shutdown", "game": "GameA"})
        t.join(timeout=5)
        assert not t.is_alive()
        assert not sp.exists()  # cleanup removed the state file

    def test_bad_frame_gets_error_response(self, tmp_path, monkeypatch):
        import socket
        import struct
        import ghidra_server
        import ghidra_client

        monkeypatch.setattr(ghidra_server, "PORT", 0)
        d = ghidra_server.GhidraDaemon("GameA", idle=30.0)
        d.project_dir = str(tmp_path / "ghidra")
        t = threading.Thread(target=d.serve, daemon=True)
        t.start()

        sp = ghidra_client.state_path(d.project_dir)
        for _ in range(200):
            if sp.exists():
                break
            time.sleep(0.01)
        port = json.loads(sp.read_text())["port"]

        # Send a length-prefixed frame whose body is not valid JSON.
        s = socket.create_connection((ghidra_client.HOST, port), timeout=5)
        junk = b"not json"
        s.sendall(struct.pack("!I", len(junk)) + junk)
        reply = ghidra_client._recv_raw(s)
        s.close()
        resp = json.loads(reply)
        assert resp["ok"] is False  # error response, not a silent hang

        ghidra_client.send_command(d.project_dir, {"cmd": "shutdown", "game": "GameA"})
        t.join(timeout=5)


class TestClientStalePid:
    def test_dead_pid_marks_not_alive_even_when_port_is_open(self, tmp_path, monkeypatch):
        """The cross-project hazard: a foreign daemon holds the port while a
        stale state file points at a dead pid. Checking the pid first rejects it
        instead of routing this project's commands into the foreign daemon."""
        import socket
        import ghidra_client

        # A live listener on some port (stands in for a foreign daemon).
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        open_port = srv.getsockname()[1]

        payload = {"pid": 999999, "port": open_port, "project": "G", "binary": "g.exe", "started": 0}
        sp = ghidra_client.state_path(str(tmp_path))
        sp.write_text(json.dumps(payload))
        monkeypatch.setattr(ghidra_client, "_pid_alive", lambda pid: False)
        try:
            assert ghidra_client.is_daemon_alive(str(tmp_path)) is False
            assert not sp.exists()  # stale state file cleaned up
        finally:
            srv.close()


def _daemon(tmp_path):
    import ghidra_server
    d = ghidra_server.GhidraDaemon("GameA")
    d.project_dir = str(tmp_path / "ghidra")
    return d


class _FakeCtx:
    def __init__(self, pg, binary):
        self.pg, self.binary, self.exits = pg, binary, []
        self.program = object()

    def __enter__(self):
        flat = type("Flat", (), {})()
        flat.getCurrentProgram = lambda: self.program
        return flat

    def __exit__(self, *args):
        self.exits.append(args)


class _FakePyghidra:
    def __init__(self):
        self.opened = []   # (binary, kwargs, ctx)

    def start(self):
        pass

    def open_program(self, binary, **kwargs):
        ctx = _FakeCtx(self, binary)
        self.opened.append((binary, kwargs, ctx))
        return ctx


@pytest.fixture
def fake_pg(monkeypatch):
    import pyghidra_backend as pb
    pg = _FakePyghidra()
    monkeypatch.setattr(pb, "_import_pyghidra", lambda: pg)
    return pg


class TestIdleTimeout:
    def test_an_idle_daemon_stops_and_removes_its_state(self, tmp_path, monkeypatch):
        import types
        import ghidra_server
        import ghidra_client
        monkeypatch.setattr(ghidra_server, "PORT", 0)
        monkeypatch.setattr(ghidra_server, "time", types.SimpleNamespace(
            sleep=lambda s: time.sleep(0.01), monotonic=time.monotonic, time=time.time))
        d = ghidra_server.GhidraDaemon("GameA", idle=0.0)
        d.project_dir = str(tmp_path / "ghidra")
        t = threading.Thread(target=d.serve, daemon=True)
        t.start()
        t.join(timeout=5)
        assert not t.is_alive()
        assert not ghidra_client.state_path(d.project_dir).exists()

    def test_activity_within_the_idle_window_keeps_it_running(self, monkeypatch):
        import types
        import ghidra_server
        ticks = []

        def sleep(s):
            ticks.append(s)
            if len(ticks) == 3:
                d._running = False
        monkeypatch.setattr(ghidra_server, "time", types.SimpleNamespace(sleep=sleep, monotonic=time.monotonic))
        d = ghidra_server.GhidraDaemon("GameA", idle=600.0)
        d._idle_watch()
        assert len(ticks) == 3   # stopped by the flag, not by the idle check


class TestMain:
    def test_main_serves_the_named_game_and_stops_on_signals(self, monkeypatch):
        import signal
        import ghidra_server
        made, handlers = [], {}

        class Fake:
            def __init__(self, game, idle):
                made.append((game, idle))
                self._running = True

            def serve(self):
                handlers[signal.SIGINT](signal.SIGINT, None)
                made.append(("served", self._running))

        monkeypatch.setattr(ghidra_server, "GhidraDaemon", Fake)
        monkeypatch.setattr(ghidra_server.signal, "signal", lambda sig, h: handlers.__setitem__(sig, h))
        monkeypatch.setattr(sys, "argv", ["ghidra_server", "GameA", "--idle", "12.5"])
        ghidra_server.main()
        assert made == [("GameA", 12.5), ("served", False)]
        assert set(handlers) == {signal.SIGINT, signal.SIGTERM}


class TestProgramLifecycle:
    def test_project_dir_is_the_games_ghidra_folder(self):
        import ghidra_server
        d = ghidra_server.GhidraDaemon("GameA")
        assert Path(d.project_dir) == Path(ghidra_server.__file__).resolve().parent.parent / "patches" / "GameA" / "ghidra"

    def test_open_keeps_a_warm_program_and_swaps_on_another_binary(self, tmp_path, fake_pg):
        d = _daemon(tmp_path)
        assert d.handle({"cmd": "open", "binary": "C:/g/a.exe"}) == {"ok": True, "binary": "C:/g/a.exe"}
        assert d.handle({"cmd": "open", "binary": "C:/g/a.exe"}) == {"ok": True, "binary": "C:/g/a.exe",
                                                                     "already": True}
        (binary, kwargs, first), = fake_pg.opened
        assert kwargs == {"project_location": d.project_dir, "project_name": "a", "analyze": False}
        assert d.handle({"cmd": "status"}) == {"ok": True, "game": "GameA", "binary": "C:/g/a.exe", "open": True}

        assert d.handle({"cmd": "open", "binary": "C:/g/b.exe"})["ok"] is True
        assert first.exits == [(None, None, None)]
        assert [b for b, _, _ in fake_pg.opened] == ["C:/g/a.exe", "C:/g/b.exe"]

    def test_close_disposes_the_decompiler_and_exits_the_program(self, tmp_path, fake_pg):
        d = _daemon(tmp_path)
        d.handle({"cmd": "open", "binary": "a.exe"})
        disposed = []
        d._decomp = type("Ifc", (), {"dispose": lambda self: disposed.append(1)})()
        assert d.handle({"cmd": "close"}) == {"ok": True}
        assert disposed == [1] and d._decomp is None
        assert fake_pg.opened[0][2].exits == [(None, None, None)]
        assert d.handle({"cmd": "status"})["open"] is False

    def test_decompile_answers_from_the_warm_program(self, tmp_path, fake_pg, monkeypatch):
        import pyghidra_backend as pb
        d = _daemon(tmp_path)
        seen = []
        monkeypatch.setattr(pb, "_decompile_open", lambda prog, va, ifc: seen.append((prog, va, ifc)) or "int f();")
        monkeypatch.setattr(d, "_decompiler", lambda: "IFC")
        assert d.handle({"cmd": "decompile", "binary": "a.exe", "va": "4198400"}) == {"ok": True, "text": "int f();"}
        assert seen == [(fake_pg.opened[0][2].program, 0x401000, "IFC")]

    def test_export_writes_the_program_into_the_named_db(self, tmp_path, fake_pg, monkeypatch):
        import pyghidra_backend as pb
        d = _daemon(tmp_path)
        seen = []
        monkeypatch.setattr(pb, "_export_program", lambda prog, gi: seen.append(prog) or {"funcs": 2})
        db = str(tmp_path / "index.db")
        assert d.handle({"cmd": "export", "binary": "a.exe", "db": db}) == {"ok": True, "counts": {"funcs": 2}}
        assert seen == [fake_pg.opened[0][2].program]
        assert Path(db).is_file()

    def test_kb_apply_closes_the_program_to_save_it(self, tmp_path, fake_pg, monkeypatch):
        import pyghidra_backend as pb
        d = _daemon(tmp_path)
        kb = tmp_path / "kb.h"
        kb.write_text("@ 0x401000 void __cdecl Foo();\n")
        seen = []
        monkeypatch.setattr(pb, "_kb_apply_txn",
                            lambda prog, k: seen.append([f.name for f in k.functions]) or {"functions": 1})
        assert d.handle({"cmd": "kb_apply", "binary": "a.exe", "kb": str(kb)}) == {"ok": True,
                                                                                   "counts": {"functions": 1}}
        assert seen == [["Foo"]]
        assert fake_pg.opened[0][2].exits == [(None, None, None)]
        assert d.handle({"cmd": "status"})["open"] is False

    @pytest.mark.parametrize("cmd", [{"cmd": "open"}, {"cmd": "decompile", "va": "1"},
                                     {"cmd": "export", "db": "x.db"}, {"cmd": "kb_apply", "kb": "kb.h"}])
    def test_without_pyghidra_every_program_command_fails(self, tmp_path, monkeypatch, cmd):
        import pyghidra_backend as pb
        monkeypatch.setattr(pb, "_import_pyghidra", lambda: None)
        d = _daemon(tmp_path)
        assert d.handle({**cmd, "binary": "a.exe"}) == {"ok": False, "error": "pyghidra not installed"}
        assert d.handle({"cmd": "status"})["open"] is False

    def test_a_failing_command_answers_with_its_error(self, tmp_path, monkeypatch):
        d = _daemon(tmp_path)
        monkeypatch.setattr(d, "_ensure_open", lambda binary: (_ for _ in ()).throw(RuntimeError("boom")))
        assert d.handle({"cmd": "open", "binary": "a.exe"}) == {"ok": False, "error": "boom"}
