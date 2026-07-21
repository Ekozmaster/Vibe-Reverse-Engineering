"""TCP client + state-file helpers for the per-project Ghidra daemon.

Mirrors livetools/client.py, but the daemon is per-project: the state file
lives under the project's ghidra dir, not next to this module. Port 27043
(livetools owns 27042).
"""

from __future__ import annotations

import json
import os
import socket
import struct
from json import JSONDecodeError
from pathlib import Path

HOST = "127.0.0.1"
PORT = 27043
RECV_BUF = 1 << 20


def state_path(project_dir: str) -> Path:
    return Path(project_dir) / ".state.json"


def read_state(project_dir: str) -> dict | None:
    p = state_path(project_dir)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, JSONDecodeError):
        return None


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if h:
            kernel32.CloseHandle(h)
            return True
        return False
    except Exception:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def is_daemon_alive(project_dir: str) -> bool:
    """Whether this project's own daemon is running.

    The recorded pid is checked first: all projects share one port, so a hard
    kill can leave a stale state file while a *different* project's daemon holds
    the port. Verifying the pid before connecting stops this project's commands
    from being routed into that foreign daemon; a dead pid also prunes the
    stale state file.
    """
    state = read_state(project_dir)
    if state is None:
        return False
    if not _pid_alive(state.get("pid")):
        state_path(project_dir).unlink(missing_ok=True)
        return False
    try:
        s = socket.create_connection((HOST, state.get("port", PORT)), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def _send_raw(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recv_raw(sock: socket.socket) -> bytes:
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("daemon closed connection")
        hdr += chunk
    length = struct.unpack("!I", hdr)[0]
    parts, remaining = [], length
    while remaining > 0:
        chunk = sock.recv(min(remaining, RECV_BUF))
        if not chunk:
            raise ConnectionError("daemon closed connection")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def send_command(project_dir: str, cmd: dict, timeout: float | None = None) -> dict:
    state = read_state(project_dir)
    port = state.get("port", PORT) if state else PORT
    sock = socket.create_connection((HOST, port), timeout=5)
    if timeout is not None:
        sock.settimeout(timeout + 10)
    try:
        _send_raw(sock, json.dumps(cmd).encode())
        return json.loads(_recv_raw(sock))
    finally:
        sock.close()
