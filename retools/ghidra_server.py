"""Per-project Ghidra daemon holding one warm open_program handle.

Binds 127.0.0.1:27043, 4-byte big-endian length-prefixed JSON (framing shared
with ghidra_client), dict-dispatched _cmd_*, idle-timeout thread. Keeps the
program open so repeat decompiles skip the ~3s JVM cold start.

Connections are served one at a time on the accept loop -- Ghidra's program and
decompiler are single-threaded and every command mutates or reads that one warm
handle, so there is nothing to gain from concurrency and no lock to reason about.

Usage:
    python -m retools.ghidra_server <Game> [--idle 600]
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
import time
from json import JSONDecodeError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ghidra_client import HOST, PORT, state_path, _recv_raw, _send_raw
import pyghidra_backend as pb

_PROJECT = Path(__file__).resolve().parent.parent


class GhidraDaemon:
    def __init__(self, game: str, idle: float = 600.0):
        self.game = game
        self.project_dir = str(_PROJECT / "patches" / game / "ghidra")
        self.binary = None
        self.port = PORT
        self.idle = idle
        self._pyghidra = None
        self._ctx = None          # open_program context manager
        self._flat_api = None
        self._program = None
        self._decomp = None       # warm DecompInterface for the open program
        self._running = True
        self._last_activity = time.monotonic()

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
        """Open *binary*, swapping out a warm program for a different one."""
        if self._program is not None and self.binary != binary:
            self._close_program()
        if self._program is None:
            return self._open(binary)
        return {"ok": True, "binary": self.binary, "already": True}

    def _decompiler(self):
        """Return the warm DecompInterface, opening it against the program once."""
        if self._decomp is None:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions
            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.openProgram(self._program)
            self._decomp = ifc
        return self._decomp

    def _close_program(self) -> None:
        if self._decomp is not None:
            try:
                self._decomp.dispose()
            except Exception:
                pass
            self._decomp = None
        if self._ctx is not None:
            try:
                self._ctx.__exit__(None, None, None)
            except Exception:
                pass
        self._ctx = self._flat_api = self._program = None

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
        return {"ok": True, "text": pb._decompile_open(self._program, va, self._decompiler())}

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
        counts = pb._kb_apply_txn(self._program, kb)
        # Persist by closing the program: pyghidra's open_program runs
        # project.save(program) on exit (an explicit save mid-context is
        # rejected). The next command reopens the saved program.
        self._close_program()
        return {"ok": True, "counts": counts}

    def _cmd_close(self, cmd):
        self._close_program()
        return {"ok": True}

    def _cmd_shutdown(self, cmd):
        self._close_program()
        self._running = False
        return {"ok": True}

    # -- dispatch + serve ----------------------------------------------------

    def handle(self, cmd: dict) -> dict:
        self._last_activity = time.monotonic()
        game = cmd.get("game")
        if game is not None and game != self.game:
            return {"ok": False, "wrong_project": True,
                    "error": f"daemon serves '{self.game}', not '{game}'"}
        op = cmd.get("cmd", "")
        handler = getattr(self, f"_cmd_{op}", None)
        if handler is None:
            return {"ok": False, "error": f"unknown command: {op}"}
        try:
            return handler(cmd)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _idle_watch(self):
        while self._running:
            time.sleep(5)
            if time.monotonic() - self._last_activity > self.idle:
                self._running = False  # accept() polls _running every second
                return

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # No SO_REUSEADDR: a second daemon must fail to bind an occupied port
        # rather than silently sharing it and corrupting the other's project.
        srv.bind((HOST, PORT))
        srv.listen(4)
        srv.settimeout(1.0)
        self.port = srv.getsockname()[1]

        sp = state_path(self.project_dir)
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps({
            "pid": os.getpid(), "port": self.port, "project": self.game,
            "binary": self.binary, "started": int(time.time()),
        }))
        print(f"[ghidra daemon] listening on {HOST}:{self.port}, project={self.game}")

        import threading
        threading.Thread(target=self._idle_watch, daemon=True).start()

        try:
            while self._running:
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._handle_conn(conn)
        finally:
            srv.close()
            self._cleanup()

    def _handle_conn(self, conn):
        try:
            conn.settimeout(300)
            try:
                cmd = json.loads(_recv_raw(conn))
            except (ConnectionError, OSError, JSONDecodeError, ValueError) as exc:
                # Malformed/short frame: answer with an error so the client sees
                # a failure instead of hanging until its own timeout.
                self._try_send(conn, {"ok": False, "error": f"bad request: {exc}"})
                return
            self._try_send(conn, self.handle(cmd))
        finally:
            conn.close()

    @staticmethod
    def _try_send(conn, resp):
        try:
            _send_raw(conn, json.dumps(resp).encode())
        except OSError:
            pass  # client already gone; nothing to deliver

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
