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

_FUNCTION_HOOK_ON_A_CALL = (
    "{addr} is a call instruction ({insn}), not a function entry. {command} hooks a "
    "function's entry and its return, and finds the return through the top stack slot. "
    "At a call instruction that slot is not a return address (on x86 it is the first "
    "stack argument): the hook would overwrite it and record nothing. {remedy}"
)
_REMEDY = {
    "trace": "Add --probe to record at this instruction, or pass the entry of the function it calls.",
    "collect": "Add --probe to record at the given instructions, or pass the entry of the function it calls.",
    "steptrace": "Pass the entry of the function it calls.",
}
_PROBE_SEES_NO_RETURN = (
    "--read-leave cannot be combined with --probe: a probe records at its instruction "
    "and never sees a return."
)

_STEP_MODES = ("into", "over", "out")
_STEP_GIVEN_UP = (
    "step did not end within {timeout} s and was given up: the call being stepped over, "
    "or the function being stepped out of, has not returned. The thread is running. To "
    "stop it later, set a breakpoint where it will arrive and wait with watch."
)
_STEP_INTERRUPTED = (
    "thread {other} reached a breakpoint before thread {stepped} finished its step. The step "
    "was ended: thread {other} is the one frozen now, and thread {stepped} is running."
)
_STEP_CUT_SHORT = (
    "the thread reached the breakpoint at {addr} before its step ended. The step was ended "
    "there."
)

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
        self._stepping = False
        self._step_failure: str | None = None
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

            elif ptype == "step_failed":
                with self._lock:
                    if self._stepping:
                        self._step_failure = payload.get("error", "step failed")
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

            elif ptype in ("trace_error", "agent_error"):
                print(f"[agent {ptype}] {payload}", file=sys.stderr)

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

    # ── commands ───────────────────────────────────────────────────────────

    def _cmd_status(self, cmd: dict) -> dict:
        return {**self._base_resp(), "ok": True}

    def _cmd_bp_add(self, cmd: dict) -> dict:
        addr = cmd["addr"]
        result = self.api.install_bp(addr)
        resp = {**self._base_resp(), "ok": result.get("ok", False)}
        resp["bpId"] = result.get("id")
        resp["msg"] = result.get("msg", "")
        if "error" in result:
            resp["error"] = result["error"]
        return resp

    def _cmd_bp_del(self, cmd: dict) -> dict:
        """Remove a breakpoint. The agent releases a thread frozen at it as well."""
        result = self.api.remove_bp(cmd["addr"])
        return {**self._base_resp(), **result}

    def _cmd_bp_list(self, cmd: dict) -> dict:
        bps = self.api.list_bps()
        return {**self._base_resp(), "ok": True, "breakpoints": bps}

    def _cmd_watch(self, cmd: dict) -> dict:
        """Wait until a thread is frozen and return its snapshot.

        A bp_hit message whose thread has been released since describes no
        stop any more; it is dropped and the wait goes on.
        """
        timeout = cmd.get("timeout", 60)
        deadline = time.time() + timeout
        while True:
            with self._lock:
                hit_reported = self._hit is not None
            if hit_reported or self.api.is_frozen():
                reply = self._consume_hit()
                if reply["ok"]:
                    return reply
            remaining = deadline - time.time()
            if remaining <= 0:
                return {**self._base_resp(), "ok": False, "timeout": True}
            self._hit_event.wait(timeout=min(remaining, 0.5))

    def _consume_hit(self) -> dict:
        """Drop the reported hit and return the snapshot of the thread frozen now, if any."""
        with self._lock:
            self._hit = None
            self._hit_event.clear()
        snap = self.api.get_snapshot(8, 8)
        if snap is None:
            return {**self._base_resp(), "ok": False, "error": "not frozen"}
        return {**self._base_resp(), "ok": True, "snapshot": snap, "hitCount": snap["hitCount"]}

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
        if not self.api.unfreeze(None):
            return {**self._base_resp(), "ok": False, "error": "not frozen"}
        return {**self._base_resp(), "ok": True}

    def _cmd_step(self, cmd: dict) -> dict:
        """Run the frozen thread for one step and report where it froze again.

        into: one instruction. over: one instruction, but a call (or a repeated
        string instruction) runs to its end. out: until the current function
        has returned to its caller. A step that outlasts the timeout is given
        up, so nothing is left waiting to freeze the thread later.
        """
        mode = cmd.get("mode", "over")
        if mode not in _STEP_MODES:
            return {**self._base_resp(), "ok": False, "error": f"unknown step mode: {mode}"}
        before = self.api.get_snapshot(1, 1)
        with self._lock:
            self._hit = None
            self._step_failure = None
            self._stepping = True
            self._hit_event.clear()
        try:
            if before is None or not self.api.unfreeze(mode):
                return {**self._base_resp(), "ok": False, "error": "not frozen"}
            timeout = cmd.get("timeout", 10)
            if not self._hit_event.wait(timeout=timeout):
                self.api.cancel_step()
        finally:
            with self._lock:
                self._stepping = False
                failure = self._step_failure
        if failure is not None:
            return {**self._base_resp(), "ok": False, "error": failure}
        # A thread may have frozen just as the step was given up; it is reported.
        reply = self._consume_hit()
        if not reply["ok"]:
            return {**self._base_resp(), "ok": False,
                    "error": _STEP_GIVEN_UP.format(timeout=timeout)}
        stepped = before["threadId"]
        snapshot = reply["snapshot"]
        if snapshot["threadId"] != stepped:
            reply["stepInterrupted"] = _STEP_INTERRUPTED.format(
                stepped=stepped, other=snapshot["threadId"])
        elif snapshot.get("stepCut"):
            reply["stepInterrupted"] = _STEP_CUT_SHORT.format(addr=snapshot["addr"])
        return reply

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
        """Stop the daemon. Unloading the agent removes its breakpoints and
        releases a frozen thread."""
        self._running = False
        return {**self._base_resp(), "ok": True, "msg": "detaching"}

    # ── hook placement ─────────────────────────────────────────────────────

    def _function_hook_refusal(self, addrs: list[str], command: str) -> str | None:
        """Why *command* must not hook *addrs* as functions, or None if it may.

        A function hook traps the return through the slot on top of the stack
        at the hooked address, which holds a return address only at a function
        entry. A ``call`` instruction is the one kind of non-entry address that
        its own bytes give away. The agent reports the program's instruction,
        not a jump or int3 of its own written over it.
        """
        for addr in addrs:
            insn = self.api.original_instruction(addr)
            if insn["isCall"]:
                return _FUNCTION_HOOK_ON_A_CALL.format(
                    addr=addr, insn=insn["str"], command=command, remedy=_REMEDY[command])
        return None

    def _trace_hook_refusal(self, cmd: dict, addrs: list[str]) -> str | None:
        """Why the hooks a trace or collect command asks for must not be installed."""
        if not cmd.get("probe"):
            return self._function_hook_refusal(addrs, cmd["cmd"])
        if cmd.get("readLeave"):
            return _PROBE_SEES_NO_RETURN
        return None

    # ── trace ──────────────────────────────────────────────────────────────

    def _cmd_trace(self, cmd: dict) -> dict:
        addr = cmd["addr"]
        refusal = self._trace_hook_refusal(cmd, [addr])
        if refusal:
            return {**self._base_resp(), "ok": False, "error": refusal}
        config = {
            "readEnter": cmd.get("read", ""),
            "readLeave": cmd.get("readLeave", ""),
            "filter": cmd.get("filter", ""),
            "count": cmd.get("count", 10),
            "label": cmd.get("label", ""),
            "probe": bool(cmd.get("probe")),
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

    # ── collect ────────────────────────────────────────────────────────────

    def _cmd_collect(self, cmd: dict) -> dict:
        addrs = cmd.get("addrs", [])
        if not addrs:
            return {**self._base_resp(), "ok": False, "error": "no addresses given"}
        refusal = self._trace_hook_refusal(cmd, addrs)
        if refusal:
            return {**self._base_resp(), "ok": False, "error": refusal}

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
                "probe": bool(cmd.get("probe")),
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

    # ── steptrace ──────────────────────────────────────────────────────────

    def _cmd_steptrace(self, cmd: dict) -> dict:
        addr = cmd["addr"]
        refusal = self._function_hook_refusal([addr], "steptrace")
        if refusal:
            return {**self._base_resp(), "ok": False, "error": refusal}
        config = {
            "maxInsn": cmd.get("maxInsn", 1000),
            "callDepth": cmd.get("callDepth", 0),
            "detail": cmd.get("detail", "branches"),
        }

        self._steptrace_event.clear()
        result = self.api.install_step_trace(addr, config)
        if not result.get("ok"):
            return {**self._base_resp(), "ok": False,
                    "error": result.get("error", "install_step_trace failed")}

        timeout = cmd.get("timeout", 30)
        if not self._steptrace_event.wait(timeout=timeout):
            self.api.cancel_step_trace()

        trace_data = self.api.get_step_trace_result()
        if trace_data is None:
            return {**self._base_resp(), "ok": False,
                    "error": f"steptrace: the function at {addr} was not called, or did not "
                             f"return, within {timeout} s. The steptrace was removed."}

        output = cmd.get("output")
        if output:
            p = Path(output) if os.path.isabs(output) else self._resolve_output_path(output)
            with open(p, "w", encoding="utf-8") as f:
                f.write(json.dumps(trace_data) + "\n")

        return {**self._base_resp(), "ok": True, "trace": trace_data,
                "output": str(output) if output else None}

    # ── modules ────────────────────────────────────────────────────────────

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

    # ── memory access watch ────────────────────────────────────────────────

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
        # One daemon per port. On Windows SO_REUSEADDR would let a second
        # daemon bind beside a live one and receive half of its commands.
        if sys.platform == "win32":
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
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
