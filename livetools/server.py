"""Livetools daemon -- attaches Frida to a target and serves commands over TCP.

Run as:  python -m livetools.server <target_name_or_pid>
The CLI's ``attach`` command spawns this as a detached background process.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import frida

HOST = "127.0.0.1"
PORT = 27042
STATE_FILE = Path(__file__).parent / ".state.json"
AGENT_JS = Path(__file__).parent / "agent.js"
WORKSPACE = Path(__file__).resolve().parent.parent


class Daemon:
    def __init__(self, target: str, *, spawn: bool = False):
        self.target = target
        self.spawn_mode = spawn
        self.dev: frida.core.Device | None = None
        self.session: frida.core.Session | None = None
        self.script: frida.core.Script | None = None
        self.api = None
        self.pid: int | None = None
        self.target_name = target
        self._cleaned_up = False

        self._hit: dict | None = None
        self._hit_event = threading.Event()
        self._lock = threading.Lock()
        self._running = True

        self._trace_batches: dict[int, list] = {}
        self._trace_done: dict[int, bool] = {}
        self._trace_events: dict[int, threading.Event] = {}

        self._steptrace_event = threading.Event()

    # ── Frida setup ────────────────────────────────────────────────────────

    def attach(self) -> None:
        self.dev = frida.get_local_device()

        if self.spawn_mode:
            exe_dir = str(Path(self.target).resolve().parent)
            self.pid = self.dev.spawn([self.target], cwd=exe_dir)
            self.target_name = Path(self.target).name
            print(f"[livetools daemon] spawned {self.target_name} (pid {self.pid}), suspended")
            self.session = self.dev.attach(self.pid)
        else:
            try:
                pid = int(self.target)
            except ValueError:
                pid = None

            if pid is not None:
                self.session = frida.attach(pid)
                self.pid = pid
            else:
                for proc in self.dev.enumerate_processes():
                    if proc.name.lower() == self.target.lower():
                        self.pid = proc.pid
                        break
                if self.pid is None:
                    raise RuntimeError(f"Process '{self.target}' not found")
                self.session = frida.attach(self.pid)
                self.target_name = self.target

        self.session.on("detached", self._on_session_detached)

        try:
            js_code = AGENT_JS.read_text(encoding="utf-8")
            self.script = self.session.create_script(js_code)
            self.script.on("message", self._on_message)
            self.script.load()
            self.api = self.script.exports_sync
        except Exception:
            if self.spawn_mode:
                # Don't leave process suspended forever
                try:
                    self.dev.resume(self.pid)
                except Exception:
                    pass
            raise

        if self.spawn_mode:
            self.dev.resume(self.pid)
            print(f"[livetools daemon] resumed pid {self.pid}")

    def _on_session_detached(self, reason: str, crash) -> None:
        print(f"[livetools daemon] target detached: {reason}", file=sys.stderr)
        self.session = None
        self.script = None
        self.api = None
        self._running = False

    def _on_message(self, message: dict, data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            ptype = payload.get("type", "")

            if ptype == "bp_hit":
                with self._lock:
                    self._hit = payload
                    self._hit_event.set()

            elif ptype == "trace_batch":
                tid = payload.get("traceId", 0)
                samples = payload.get("samples", [])
                with self._lock:
                    self._trace_batches.setdefault(tid, []).extend(samples)
                    ev = self._trace_events.get(tid)
                    if ev:
                        ev.set()

            elif ptype == "trace_done":
                tid = payload.get("traceId", 0)
                with self._lock:
                    self._trace_done[tid] = True
                    ev = self._trace_events.get(tid)
                    if ev:
                        ev.set()

            elif ptype == "trace_error":
                print(f"[agent trace_error] {payload}", file=sys.stderr)

            elif ptype == "steptrace_done":
                self._steptrace_event.set()

        elif message.get("type") == "error":
            print(f"[agent error] {message.get('description', '?')}", file=sys.stderr)

    # ── helpers ────────────────────────────────────────────────────────────

    def _base_resp(self) -> dict:
        api = self.api
        bp_list = api.list_bps() if api else []
        is_frozen = api.is_frozen() if api else False
        frozen_addr = api.get_frozen_addr() if is_frozen else None
        return {
            "target": self.target_name,
            "pid": self.pid,
            "state": "FROZEN" if is_frozen else "RUNNING",
            "frozenAddr": frozen_addr,
            "bpCount": len(bp_list),
        }

    def _resolve_output_path(self, filename: str) -> Path:
        exe = Path(self.target_name).stem
        traces_dir = WORKSPACE / "patches" / exe / "traces"
        traces_dir.mkdir(parents=True, exist_ok=True)
        return traces_dir / filename

    # ── command dispatch ───────────────────────────────────────────────────

    def handle(self, cmd: dict) -> dict:
        op = cmd.get("cmd", "")
        try:
            handler = getattr(self, f"_cmd_{op}", None)
            if handler is None:
                return {**self._base_resp(), "ok": False, "error": f"unknown command: {op}"}
            return handler(cmd)
        except Exception as exc:
            return {**self._base_resp(), "ok": False, "error": str(exc)}

    # ── existing commands (unchanged) ──────────────────────────────────────

    def _cmd_status(self, cmd: dict) -> dict:
        return {**self._base_resp(), "ok": True}

    def _cmd_bp_add(self, cmd: dict) -> dict:
        addr = cmd["addr"]
        result = self.api.install_bp(addr)
        resp = {**self._base_resp(), "ok": result.get("ok", False)}
        resp["bpId"] = result.get("id")
        resp["msg"] = result.get("msg", "")
        return resp

    def _cmd_bp_del(self, cmd: dict) -> dict:
        addr = cmd["addr"]
        if self.api.is_frozen() and self.api.get_frozen_addr() == addr:
            self.script.post({"type": "resume"})
            time.sleep(0.05)
        result = self.api.remove_bp(addr)
        return {**self._base_resp(), **result}

    def _cmd_bp_list(self, cmd: dict) -> dict:
        bps = self.api.list_bps()
        return {**self._base_resp(), "ok": True, "breakpoints": bps}

    def _cmd_watch(self, cmd: dict) -> dict:
        timeout = cmd.get("timeout", 60)
        deadline = time.time() + timeout
        with self._lock:
            if self._hit is not None:
                return self._consume_hit()
        self._hit_event.clear()
        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            self._hit_event.wait(timeout=min(remaining, 0.5))
            with self._lock:
                if self._hit is not None:
                    return self._consume_hit()
            try:
                if self.api.is_frozen():
                    time.sleep(0.15)
                    with self._lock:
                        if self._hit is not None:
                            return self._consume_hit()
                    return self._build_snapshot_direct()
            except Exception:
                pass
        return {**self._base_resp(), "ok": False, "timeout": True}

    def _consume_hit(self) -> dict:
        hit = self._hit
        self._hit = None
        self._hit_event.clear()
        snap = self.api.get_snapshot(8, 8)
        return {**self._base_resp(), "ok": True, "snapshot": snap,
                "hitCount": hit.get("hitCount", 0) if hit else 0}

    def _build_snapshot_direct(self) -> dict:
        snap = self.api.get_snapshot(8, 8)
        if snap is None:
            return {**self._base_resp(), "ok": False, "error": "frozen but snapshot unavailable"}
        return {**self._base_resp(), "ok": True, "snapshot": snap, "hitCount": 0}

    def _cmd_regs(self, cmd: dict) -> dict:
        regs = self.api.get_registers()
        if regs is None:
            return {**self._base_resp(), "ok": False, "error": "not frozen"}
        return {**self._base_resp(), "ok": True, "regs": regs}

    def _cmd_stack(self, cmd: dict) -> dict:
        count = cmd.get("count", 16)
        entries = self.api.read_stack(count)
        if not entries:
            return {**self._base_resp(), "ok": False, "error": "not frozen"}
        return {**self._base_resp(), "ok": True, "stack": entries}

    def _cmd_mem_read(self, cmd: dict) -> dict:
        addr, size = cmd["addr"], cmd["size"]
        raw = self.api.read_memory(addr, size)
        if raw is None:
            return {**self._base_resp(), "ok": False, "error": "read failed"}
        return {**self._base_resp(), "ok": True, "addr": addr,
                "hex": bytes(raw).hex(), "size": len(raw)}

    def _cmd_mem_write(self, cmd: dict) -> dict:
        result = self.api.write_memory(cmd["addr"], cmd["hex"])
        return {**self._base_resp(), **result}

    def _cmd_mem_alloc(self, cmd: dict) -> dict:
        result = self.api.alloc_memory(cmd["size"])
        return {**self._base_resp(), **result}

    def _cmd_disasm(self, cmd: dict) -> dict:
        addr = cmd.get("addr")
        if addr is None:
            if not self.api.is_frozen():
                return {**self._base_resp(), "ok": False, "error": "not frozen and no addr given"}
            regs = self.api.get_registers()
            ip_key = "rip" if regs.get("_arch") == "x64" else "eip"
            addr = "0x" + regs[ip_key]
        count = cmd.get("count", 16)
        lines = self.api.disasm_at(addr, count)
        return {**self._base_resp(), "ok": True, "disasm": lines}

    def _cmd_bt(self, cmd: dict) -> dict:
        frames = self.api.backtrace()
        if not frames:
            return {**self._base_resp(), "ok": False, "error": "not frozen or backtrace failed"}
        return {**self._base_resp(), "ok": True, "frames": frames}

    def _cmd_resume(self, cmd: dict) -> dict:
        if not self.api.is_frozen():
            return {**self._base_resp(), "ok": False, "error": "not frozen"}
        self.script.post({"type": "resume"})
        time.sleep(0.05)
        return {**self._base_resp(), "ok": True}

    def _cmd_step(self, cmd: dict) -> dict:
        mode = cmd.get("mode", "over")
        if not self.api.is_frozen():
            return {**self._base_resp(), "ok": False, "error": "not frozen"}
        regs = self.api.get_registers()
        is_x64 = regs.get("_arch") == "x64"
        eip = "0x" + regs["rip" if is_x64 else "eip"]
        esp = "0x" + regs["rsp" if is_x64 else "esp"]
        ptr_size = 8 if is_x64 else 4
        insns = self.api.disasm_at(eip, 2)
        if not insns:
            return {**self._base_resp(), "ok": False, "error": "disasm failed at EIP"}
        current = insns[0]
        mnemonic = current.get("mnemonic", "")
        size = current.get("size", 0)
        op_str = current.get("opStr", "")
        eip_int = int(eip, 16)
        next_seq = f"0x{eip_int + size:08X}"

        def _resolve():
            try:
                return f"0x{int(op_str, 16):08X}"
            except ValueError:
                return None

        is_call = mnemonic == "call"
        is_uncond_jmp = mnemonic == "jmp"
        is_cond_jmp = mnemonic.startswith("j") and not is_uncond_jmp
        secondary_addr = None

        if mode == "over":
            if is_call:
                next_addr = next_seq
            elif is_uncond_jmp:
                t = _resolve()
                next_addr = t if t else next_seq
            elif is_cond_jmp:
                t = _resolve()
                next_addr = next_seq
                if t:
                    self.api.install_bp(t)
                    secondary_addr = t
            else:
                next_addr = next_seq
        elif mode == "into":
            if is_call or is_uncond_jmp:
                t = _resolve()
                next_addr = t if t else next_seq
            else:
                next_addr = next_seq
        elif mode == "out":
            ret_raw = self.api.read_memory(esp, ptr_size)
            if ret_raw is None:
                return {**self._base_resp(), "ok": False, "error": "cannot read return address"}
            ret_addr = int.from_bytes(bytes(ret_raw), "little")
            next_addr = f"0x{ret_addr:08X}"
        else:
            return {**self._base_resp(), "ok": False, "error": f"unknown step mode: {mode}"}

        self.api.install_bp(next_addr)
        with self._lock:
            self._hit = None
            self._hit_event.clear()
        self.script.post({"type": "resume"})

        deadline = time.time() + 10
        hit = None
        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            self._hit_event.wait(timeout=min(remaining, 0.5))
            with self._lock:
                if self._hit is not None:
                    hit = self._hit
                    self._hit = None
                    self._hit_event.clear()
                    break
            try:
                if self.api.is_frozen():
                    time.sleep(0.1)
                    with self._lock:
                        if self._hit is not None:
                            hit = self._hit
                            self._hit = None
                            self._hit_event.clear()
                    break
            except Exception:
                pass

        self.api.remove_bp(next_addr)
        if secondary_addr:
            self.api.remove_bp(secondary_addr)
        if hit is None and not self.api.is_frozen():
            return {**self._base_resp(), "ok": False, "error": "step timed out (10s)"}
        snap = self.api.get_snapshot(8, 8)
        return {**self._base_resp(), "ok": True, "snapshot": snap}

    def _cmd_scan(self, cmd: dict) -> dict:
        pattern = cmd["pattern"]
        start, size = cmd.get("start"), cmd.get("size")
        if start and size:
            results = self.api.scan_sync(start, size, pattern)
        else:
            return {**self._base_resp(), "ok": False,
                    "error": "scan requires --range START:SIZE for now"}
        return {**self._base_resp(), "ok": True, "results": results}

    def _cmd_detach(self, cmd: dict) -> dict:
        try:
            if self.api and self.api.is_frozen():
                self.script.post({"type": "resume"})
                time.sleep(0.05)
        except Exception:
            pass
        self._running = False
        return {**self._base_resp(), "ok": True, "msg": "detaching"}

    # ── NEW: trace ─────────────────────────────────────────────────────────

    def _cmd_trace(self, cmd: dict) -> dict:
        addr = cmd["addr"]
        config = {
            "readEnter": cmd.get("read", ""),
            "readLeave": cmd.get("readLeave", ""),
            "filter": cmd.get("filter", ""),
            "count": cmd.get("count", 10),
            "label": cmd.get("label", ""),
        }
        result = self.api.install_trace(addr, config)
        if not result.get("ok"):
            return {**self._base_resp(), "ok": False,
                    "error": result.get("error", "install_trace failed")}

        trace_id = result["traceId"]
        timeout = cmd.get("timeout", 30)
        count = config["count"]

        ev = threading.Event()
        with self._lock:
            self._trace_batches.setdefault(trace_id, [])
            self._trace_done.setdefault(trace_id, False)
            self._trace_events[trace_id] = ev

        deadline = time.time() + timeout
        while time.time() < deadline:
            ev.wait(timeout=min(0.5, max(0.1, deadline - time.time())))
            ev.clear()
            with self._lock:
                if self._trace_done.get(trace_id):
                    break
            status = self.api.flush_traces(trace_id)
            if status.get("done"):
                break

        self.api.remove_trace(trace_id)

        with self._lock:
            samples = self._trace_batches.pop(trace_id, [])
            self._trace_done.pop(trace_id, None)
            self._trace_events.pop(trace_id, None)

        output = cmd.get("output")
        if output:
            p = Path(output) if os.path.isabs(output) else self._resolve_output_path(output)
            with open(p, "w", encoding="utf-8") as f:
                for s in samples:
                    f.write(json.dumps(s) + "\n")

        hook_diag = {"addr": addr, "hookVerified": result.get("hookVerified"),
                     "prologue": result.get("prologue")}
        return {**self._base_resp(), "ok": True, "samples": samples,
                "count": len(samples), "output": str(output) if output else None,
                "hookDiag": hook_diag}

    # ── NEW: collect ───────────────────────────────────────────────────────

    def _cmd_collect(self, cmd: dict) -> dict:
        addrs = cmd.get("addrs", [])
        if not addrs:
            return {**self._base_resp(), "ok": False, "error": "no addresses given"}

        duration = cmd.get("duration", 10)
        max_records = cmd.get("maxRecords", 0)
        read_specs = cmd.get("readSpecs", {})
        labels = cmd.get("labels", {})
        fence_addr = cmd.get("fence")
        fence_every = cmd.get("fenceEvery", 0)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"collect_{ts}.jsonl"
        output = cmd.get("output") or default_name
        out_path = Path(output) if os.path.isabs(output) else self._resolve_output_path(output)

        if fence_addr:
            self.api.install_fence(fence_addr)

        trace_ids = []
        all_events = {}
        hook_diags: list[dict] = []
        for addr in addrs:
            config = {
                "readEnter": read_specs.get(addr, cmd.get("read", "")),
                "readLeave": cmd.get("readLeave", ""),
                "filter": cmd.get("filter", ""),
                "count": max_records if max_records > 0 else 0,
                "label": labels.get(addr, ""),
            }
            result = self.api.install_trace(addr, config)
            if result.get("ok"):
                tid = result["traceId"]
                trace_ids.append(tid)
                ev = threading.Event()
                with self._lock:
                    self._trace_batches.setdefault(tid, [])
                    self._trace_done.setdefault(tid, False)
                    self._trace_events[tid] = ev
                all_events[tid] = ev
                hook_diags.append({"addr": addr, "ok": True,
                                   "hookVerified": result.get("hookVerified", None),
                                   "prologue": result.get("prologue")})
            else:
                hook_diags.append({"addr": addr, "ok": False,
                                   "error": result.get("error", "unknown")})

        total_collected = 0
        deadline = time.time() + duration

        with open(out_path, "w", encoding="utf-8") as f:
            while time.time() < deadline:
                time.sleep(0.3)

                for tid in trace_ids:
                    self.api.flush_traces(tid)

                with self._lock:
                    for tid in trace_ids:
                        batch = self._trace_batches.get(tid, [])
                        if batch:
                            for s in batch:
                                f.write(json.dumps(s) + "\n")
                                total_collected += 1
                            self._trace_batches[tid] = []
                            f.flush()

                all_done = all(self._trace_done.get(t) for t in trace_ids)
                if all_done:
                    break
                if max_records > 0 and total_collected >= max_records:
                    break

        for tid in trace_ids:
            self.api.remove_trace(tid)
        if fence_addr:
            self.api.remove_fence()

        with self._lock:
            for tid in trace_ids:
                remaining = self._trace_batches.pop(tid, [])
                if remaining:
                    with open(out_path, "a", encoding="utf-8") as f:
                        for s in remaining:
                            f.write(json.dumps(s) + "\n")
                            total_collected += 1
                self._trace_done.pop(tid, None)
                self._trace_events.pop(tid, None)

        return {**self._base_resp(), "ok": True, "output": str(out_path),
                "totalRecords": total_collected,
                "fenceCount": self.api.get_fence_counter(),
                "hookDiags": hook_diags}

    # ── NEW: steptrace ─────────────────────────────────────────────────────

    def _cmd_steptrace(self, cmd: dict) -> dict:
        addr = cmd["addr"]
        config = {
            "maxInsn": cmd.get("maxInsn", 1000),
            "callDepth": cmd.get("callDepth", 0),
            "detail": cmd.get("detail", "branches"),
        }

        self._steptrace_event.clear()
        result = self.api.install_step_trace(addr, config)
        if not result.get("ok"):
            return {**self._base_resp(), "ok": False, "error": "install_step_trace failed"}

        timeout = cmd.get("timeout", 30)
        self._steptrace_event.wait(timeout=timeout)

        trace_data = self.api.get_step_trace_result()
        if trace_data is None:
            return {**self._base_resp(), "ok": False, "error": "steptrace timed out or failed"}

        output = cmd.get("output")
        if output:
            p = Path(output) if os.path.isabs(output) else self._resolve_output_path(output)
            with open(p, "w", encoding="utf-8") as f:
                f.write(json.dumps(trace_data) + "\n")

        return {**self._base_resp(), "ok": True, "trace": trace_data,
                "output": str(output) if output else None}

    # ── NEW: modules ───────────────────────────────────────────────────────

    def _cmd_modules(self, cmd: dict) -> dict:
        modules = self.api.enumerate_modules()
        filt = (cmd.get("filter") or "").lower()
        if filt:
            modules = [m for m in modules if filt in m["name"].lower()
                       or filt in m.get("path", "").lower()]
        return {**self._base_resp(), "ok": True, "modules": modules}

    # ── visibility override ────────────────────────────────────────────────

    def _cmd_vishook_on(self, cmd: dict) -> dict:
        threshold = cmd["threshold"]
        jmp_site = cmd["jmpSite"]
        orig_target = cmd["origTarget"]
        result = self.api.install_vis_override(threshold, jmp_site, orig_target)
        return {**self._base_resp(), **result}

    def _cmd_vishook_off(self, cmd: dict) -> dict:
        result = self.api.remove_vis_override()
        return {**self._base_resp(), **result}

    def _cmd_vishook_stats(self, cmd: dict) -> dict:
        result = self.api.get_vis_stats()
        return {**self._base_resp(), "ok": True, **result}

    # ── DIP counter ────────────────────────────────────────────────────────

    def _cmd_dipcnt_on(self, cmd: dict) -> dict:
        dev_ptr_addr = cmd["devPtrAddr"]
        result = self.api.install_dip_counter(dev_ptr_addr)
        return {**self._base_resp(), **result}

    def _cmd_dipcnt_off(self, cmd: dict) -> dict:
        result = self.api.remove_dip_counter()
        return {**self._base_resp(), **result}

    def _cmd_dipcnt_read(self, cmd: dict) -> dict:
        result = self.api.get_dip_count()
        return {**self._base_resp(), "ok": True, **result}

    def _cmd_dipcnt_callers(self, cmd: dict) -> dict:
        count = cmd.get("count", 200)
        result = self.api.sample_dip_callers(count)
        return {**self._base_resp(), "ok": True, **result}

    # ── memory write watchpoint ─────────────────────────────────────────────

    def _cmd_memwatch_start(self, cmd: dict) -> dict:
        addr = cmd["addr"]
        size = cmd.get("size", 4)
        max_hits = cmd.get("maxHits", 20)
        result = self.api.watch_mem_write(addr, size, max_hits)
        return {**self._base_resp(), **result}

    def _cmd_memwatch_stop(self, cmd: dict) -> dict:
        result = self.api.stop_mem_watch()
        return {**self._base_resp(), **result}

    def _cmd_memwatch_read(self, cmd: dict) -> dict:
        result = self.api.get_mem_watch_hits()
        return {**self._base_resp(), **result}

    # ── TCP server ─────────────────────────────────────────────────────────

    def serve(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(4)
        srv.settimeout(1.0)

        STATE_FILE.write_text(json.dumps({
            "pid": os.getpid(), "port": PORT,
            "target": self.target_name, "targetPid": self.pid,
        }))

        print(f"[livetools daemon] listening on {HOST}:{PORT}, "
              f"target={self.target_name} pid={self.pid}")

        while self._running:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

        srv.close()
        self._cleanup()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(300)
            data = self._recv_raw(conn)
            cmd = json.loads(data)
            resp = self.handle(cmd)
            self._send_raw(conn, json.dumps(resp).encode())
        except Exception as exc:
            try:
                self._send_raw(conn, json.dumps({"ok": False, "error": str(exc)}).encode())
            except Exception:
                pass
        finally:
            conn.close()

    @staticmethod
    def _send_raw(sock: socket.socket, data: bytes) -> None:
        sock.sendall(struct.pack("!I", len(data)) + data)

    @staticmethod
    def _recv_raw(sock: socket.socket) -> bytes:
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("client disconnected")
            hdr += chunk
        length = struct.unpack("!I", hdr)[0]
        parts, remaining = [], length
        while remaining > 0:
            chunk = sock.recv(min(remaining, 1 << 20))
            if not chunk:
                raise ConnectionError("client disconnected")
            parts.append(chunk)
            remaining -= len(chunk)
        return b"".join(parts)

    def _cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        try:
            if self.script:
                self.script.unload()
                self.script = None
        except Exception:
            pass
        try:
            if self.session:
                self.session.detach()
                self.session = None
        except Exception:
            pass
        self.api = None
        STATE_FILE.unlink(missing_ok=True)
        print("[livetools daemon] stopped")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m livetools.server <target_name_or_pid> [--spawn]",
              file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    spawn = "--spawn" in sys.argv[2:]
    daemon = Daemon(target, spawn=spawn)

    def _shutdown(sig, frame):
        daemon._running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        daemon.attach()
        daemon.serve()
    except Exception as exc:
        print(f"[livetools daemon] fatal: {exc}", file=sys.stderr)
    finally:
        daemon._cleanup()


if __name__ == "__main__":
    main()
