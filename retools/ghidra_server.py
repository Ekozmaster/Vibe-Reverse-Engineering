"""Per-project Ghidra daemon holding one warm open_program handle.

Cloned from livetools/server.py. Binds 127.0.0.1:27043, 4-byte big-endian
length-prefixed JSON, dict-dispatched _cmd_*, idle-timeout thread. Keeps the
program open so repeat decompiles skip the ~3s JVM cold start.

Usage:
    python -m retools.ghidra_server <Game> [--idle 600]
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ghidra_client import HOST, PORT, state_path
import pyghidra_backend as pb

_PROJECT = Path(__file__).resolve().parent.parent


class GhidraDaemon:
    def __init__(self, game: str, idle: float = 600.0):
        self.game = game
        self.project_dir = str(_PROJECT / "patches" / game / "ghidra")
        self.binary = None
        self.idle = idle
        self._pyghidra = None
        self._ctx = None          # open_program context manager
        self._flat_api = None
        self._program = None
        self._running = True
        self._last_activity = time.monotonic()
        self._lock = threading.Lock()
        self._conn_threads = []

    # -- program lifecycle ---------------------------------------------------

    def _open(self, binary: str) -> dict:
        pg = pb._import_pyghidra()
        if pg is None:
            return {"ok": False, "error": "pyghidra not installed"}
        pg.start()
        self._pyghidra = pg
        self.binary = binary
        stem = Path(binary).stem
        self._ctx = pg.open_program(
            binary, project_location=self.project_dir, project_name=stem, analyze=False)
        self._flat_api = self._ctx.__enter__()
        self._program = self._flat_api.getCurrentProgram()
        return {"ok": True, "binary": binary}

    def _ensure_open(self, binary: str) -> dict:
        """Open *binary*, swapping out a warm program for a different one.

        Callers run inside ``handle()``'s lock, so a binary switch closes the
        stale program via the no-lock ``_close_program_locked`` (the
        lock-acquiring ``_close_program`` would deadlock here).
        """
        if self._program is not None and self.binary != binary:
            self._close_program_locked()
        if self._program is None:
            return self._open(binary)
        return {"ok": True, "binary": self.binary, "already": True}

    def _close_program_locked(self) -> None:
        """Tear down the open program. Caller must already hold ``self._lock``."""
        if self._ctx is not None:
            try:
                self._ctx.__exit__(None, None, None)
            except Exception:
                pass
        self._ctx = self._flat_api = self._program = None

    def _close_program(self) -> None:
        """Tear down the open program, waiting for any in-flight command first.

        Acquires ``self._lock`` so this cannot run concurrently with a
        command still executing inside ``handle()`` -- otherwise a
        long-running decompile could be closed out from under it (crash /
        ``.rep`` corruption). Only call this from outside ``handle()``
        (e.g. ``_cleanup``); command handlers already hold the lock and
        must use ``_close_program_locked`` directly.
        """
        with self._lock:
            self._close_program_locked()

    # -- commands ------------------------------------------------------------

    def _cmd_status(self, cmd):
        return {"ok": True, "game": self.game, "binary": self.binary,
                "open": self._program is not None}

    def _cmd_open(self, cmd):
        return self._ensure_open(cmd["binary"])

    def _cmd_decompile(self, cmd):
        r = self._ensure_open(cmd["binary"])
        if not r.get("ok"):
            return r
        va = int(cmd["va"])
        return {"ok": True, "text": pb._decompile_open(self._program, va)}

    def _cmd_export(self, cmd):
        r = self._ensure_open(cmd["binary"])
        if not r.get("ok"):
            return r
        from index import GameIndex
        gi = GameIndex(cmd["db"])
        try:
            counts = pb._export_program(self._program, gi)
        finally:
            gi.close()
        return {"ok": True, "counts": counts}

    def _cmd_kb_apply(self, cmd):
        r = self._ensure_open(cmd["binary"])
        if not r.get("ok"):
            return r
        from kb import parse_kb
        kb = parse_kb(Path(cmd["kb"]))
        txn = self._program.startTransaction("kb_apply")
        try:
            counts = pb._kb_apply_program(self._program, kb, self._flat_api)
        finally:
            self._program.endTransaction(txn, True)
        self._program.save("kb_apply", None)
        return {"ok": True, "counts": counts}

    def _cmd_close(self, cmd):
        self._close_program_locked()
        return {"ok": True}

    def _cmd_shutdown(self, cmd):
        self._close_program_locked()
        self._running = False
        return {"ok": True}

    # -- dispatch + serve ----------------------------------------------------

    def handle(self, cmd: dict) -> dict:
        self._last_activity = time.monotonic()
        op = cmd.get("cmd", "")
        handler = getattr(self, f"_cmd_{op}", None)
        if handler is None:
            return {"ok": False, "error": f"unknown command: {op}"}
        with self._lock:
            try:
                return handler(cmd)
            except Exception as exc:
                return {"ok": False, "error": str(exc)}

    def _idle_watch(self):
        while self._running:
            time.sleep(5)
            if time.monotonic() - self._last_activity > self.idle:
                self._running = False
                try:
                    socket.create_connection((HOST, PORT), timeout=1).close()  # unblock accept
                except OSError:
                    pass
                return

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(4)
        srv.settimeout(1.0)

        sp = state_path(self.project_dir)
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps({
            "pid": os.getpid(), "port": PORT, "project": self.game,
            "binary": self.binary, "started": int(time.time()),
        }))
        print(f"[ghidra daemon] listening on {HOST}:{PORT}, project={self.game}")
        threading.Thread(target=self._idle_watch, daemon=True).start()

        try:
            while self._running:
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
                t.start()
                self._conn_threads.append(t)
        finally:
            srv.close()
            # Drain in-flight connection handlers before tearing down the
            # program; _close_program's lock acquisition is the actual
            # correctness guarantee below, this just avoids leaving threads
            # dangling on a closed socket.
            for t in self._conn_threads:
                t.join(timeout=5.0)
            self._cleanup()

    def _handle_conn(self, conn):
        try:
            conn.settimeout(300)
            hdr = b""
            while len(hdr) < 4:
                chunk = conn.recv(4 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            length = struct.unpack("!I", hdr)[0]
            buf = b""
            while len(buf) < length:
                chunk = conn.recv(min(length - len(buf), 1 << 20))
                if not chunk:
                    return
                buf += chunk
            resp = self.handle(json.loads(buf))
            data = json.dumps(resp).encode()
            conn.sendall(struct.pack("!I", len(data)) + data)
        except Exception:
            pass
        finally:
            conn.close()

    def _cleanup(self):
        self._close_program()
        state_path(self.project_dir).unlink(missing_ok=True)
        print("[ghidra daemon] stopped")


def main():
    p = argparse.ArgumentParser(prog="retools.ghidra_server")
    p.add_argument("game", help="Game/project name (patches/<game>/ghidra)")
    p.add_argument("--idle", type=float, default=600.0, help="Idle timeout seconds")
    args = p.parse_args()

    daemon = GhidraDaemon(args.game, idle=args.idle)

    def _shutdown(sig, frame):
        daemon._running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    daemon.serve()  # serve() guarantees cleanup in its own try/finally


if __name__ == "__main__":
    main()
