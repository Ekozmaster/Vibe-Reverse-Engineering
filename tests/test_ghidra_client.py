"""Tests for retools/ghidra_client.py -- state file + TCP protocol helpers."""

import json
import socket
import struct
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestPort:
    def test_port_is_27043(self):
        import ghidra_client
        assert ghidra_client.PORT == 27043  # livetools owns 27042


class TestState:
    def test_read_state_missing(self, tmp_path):
        import ghidra_client
        assert ghidra_client.read_state(str(tmp_path)) is None

    def test_read_state_roundtrip(self, tmp_path):
        import ghidra_client
        payload = {"pid": 1, "port": 27043, "project": "G", "binary": "g.exe", "started": 0}
        ghidra_client.state_path(str(tmp_path)).write_text(json.dumps(payload))
        assert ghidra_client.read_state(str(tmp_path))["project"] == "G"


class TestSendCommand:
    def test_roundtrip_against_echo_server(self, tmp_path):
        import ghidra_client

        def _recv(sock):
            hdr = b""
            while len(hdr) < 4:
                hdr += sock.recv(4 - len(hdr))
            length = struct.unpack("!I", hdr)[0]
            buf = b""
            while len(buf) < length:
                buf += sock.recv(length - len(buf))
            return buf

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def serve():
            conn, _ = srv.accept()
            req = json.loads(_recv(conn))
            resp = json.dumps({"ok": True, "echo": req["cmd"]}).encode()
            conn.sendall(struct.pack("!I", len(resp)) + resp)
            conn.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        payload = {"pid": 1, "port": port, "project": "G", "binary": "g.exe", "started": 0}
        ghidra_client.state_path(str(tmp_path)).write_text(json.dumps(payload))
        resp = ghidra_client.send_command(str(tmp_path), {"cmd": "status"})
        srv.close()
        assert resp["ok"] is True
        assert resp["echo"] == "status"
