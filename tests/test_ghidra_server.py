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
        assert resp["ok"] is False
        assert resp.get("wrong_project") is True

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
        assert resp["ok"] is False


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
