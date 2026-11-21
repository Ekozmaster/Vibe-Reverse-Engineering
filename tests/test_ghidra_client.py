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


class _ChunkSocket:
    """Delivers a byte stream at most *step* bytes per recv, like a slow TCP peer."""

    def __init__(self, data: bytes, step: int):
        self.data, self.step = data, step

    def recv(self, n):
        chunk, self.data = self.data[:min(n, self.step)], self.data[min(n, self.step):]
        return chunk


class TestIsDaemonAlive:
    def _state(self, tmp_path, **fields):
        import ghidra_client
        ghidra_client.state_path(str(tmp_path)).write_text(json.dumps(fields))

    def test_live_pid_and_listening_port(self, tmp_path):
        import os
        import ghidra_client
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            self._state(tmp_path, pid=os.getpid(), port=srv.getsockname()[1])
            assert ghidra_client.is_daemon_alive(str(tmp_path)) is True
        finally:
            srv.close()

    def test_live_pid_without_a_listener(self, tmp_path):
        import os
        import ghidra_client
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        self._state(tmp_path, pid=os.getpid(), port=closed_port)
        assert ghidra_client.is_daemon_alive(str(tmp_path)) is False

    def test_no_state_file(self, tmp_path):
        import ghidra_client
        assert ghidra_client.is_daemon_alive(str(tmp_path)) is False


class TestPidAlive:
    def test_own_process_is_alive_and_no_pid_is_not(self):
        import os
        import ghidra_client
        assert ghidra_client._pid_alive(os.getpid()) is True
        assert ghidra_client._pid_alive(None) is False
        assert ghidra_client._pid_alive(0) is False
        assert ghidra_client._pid_alive(0x7FFFFFF0) is False   # no such process

    def test_an_exited_process_is_not_alive(self):
        import subprocess
        import ghidra_client
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()                    # Popen still holds the process handle
        assert ghidra_client._pid_alive(proc.pid) is False


class TestRecvRaw:
    def _frame(self, body: bytes) -> bytes:
        return struct.pack("!I", len(body)) + body

    def test_frames_arrive_whole_from_small_chunks(self):
        import ghidra_client
        sock = _ChunkSocket(self._frame(b"ten bytes!") + self._frame(b"second"), step=3)
        assert ghidra_client._recv_raw(sock) == b"ten bytes!"   # 3 + 3 + 3 + 1
        assert ghidra_client._recv_raw(sock) == b"second"

    def test_back_to_back_frames_from_one_buffer(self):
        import ghidra_client
        sock = _ChunkSocket(self._frame(b"a" * 10) + self._frame(b"b" * 5), step=1 << 30)
        assert ghidra_client._recv_raw(sock) == b"a" * 10
        assert ghidra_client._recv_raw(sock) == b"b" * 5

    def test_an_empty_frame(self):
        import ghidra_client
        assert ghidra_client._recv_raw(_ChunkSocket(self._frame(b""), step=4)) == b""

    def test_a_closed_peer_mid_header_or_mid_body_is_an_error(self):
        import pytest
        import ghidra_client
        with pytest.raises(ConnectionError):
            ghidra_client._recv_raw(_ChunkSocket(b"\x00\x00", step=1))
        with pytest.raises(ConnectionError):
            ghidra_client._recv_raw(_ChunkSocket(self._frame(b"abcdef")[:7], step=2))
