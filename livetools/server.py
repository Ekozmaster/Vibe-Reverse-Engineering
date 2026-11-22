"""Livetools daemon -- attaches Frida to a target and serves commands over TCP.

Run as:  python -m livetools.server <target_name_or_pid>
The CLI's ``attach`` command spawns this as a detached background process.
"""

from __future__ import annotations

import functools
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable
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


class _RecordFile:
    """The JSON-lines file a trace or a collect writes its records to.

    Opening it proves the path can be written, before anything is hooked, and
    changes nothing a refused command would have to undo: what the file held
    is replaced only by ``start()``, which is called once a hook is in, and a
    file this created is deleted again if ``start()`` never was.

    Attributes:
        started: Whether the file now holds this command's records.
    """

    def __init__(self, path: Path):
        self._path = path
        self._created = not path.exists()
        self._file = open(path, "a", encoding="utf-8")
        self.started = False

    def __enter__(self) -> "_RecordFile":
        return self

    def __exit__(self, *exc_info) -> None:
        self._file.close()
        if self._created and not self.started:
            self._path.unlink()

    def start(self) -> None:
        """Empty the file for this command's records, the first time it is called."""
        if not self.started:
            self._file.truncate(0)
            self.started = True

    def write(self, records: list) -> None:
        """Append *records*, one JSON line each, where a reader of the file sees them at once."""
        for record in records:
            self._file.write(json.dumps(record) + "\n")
        self._file.flush()


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
_DETACH_WAITS_FOR_STEP = (
    "detach is waiting for thread {threads} to raise the single-step exception it was sent on "
    "with. Unloading the agent first would leave that exception without a handler and crash "
    "{target}, so the daemon (pid {daemon}) stays until the thread has run. Its breakpoints are "
    "removed already. Killing the daemon leaves the agent in {target} to wait for the thread."
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
        self._wrote_state_file = False

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

        self._shutdown_failures_reported: set[str] = set()

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
                return {**self._base_resp(), "ok": False,
                        "error": self.api.freeze_refusal() or "not frozen"}
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
        """Take the agent's changes out of the target and stop the daemon.

        The reply carries what the agent could not undo (``shutdown``) and, if a
        thread still owes a single-step exception, why the daemon has not gone
        yet (``waitingOn``): it unloads the agent only once that thread has run.
        """
        try:
            failures, waiting = self._shut_agent_down(self.api) if self.api else ([], None)
        finally:
            self._running = False
        reply = {**self._base_resp(), "ok": True, "msg": "detaching", "shutdown": failures}
        if waiting is not None:
            reply["waitingOn"] = waiting
        return reply

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
        timeout = cmd.get("timeout", 30)
        output = cmd.get("output")
        if not output:
            return self._trace(addr, config, timeout)
        path = Path(output) if os.path.isabs(output) else self._resolve_output_path(output)
        with _RecordFile(path) as records:
            reply = self._trace(addr, config, timeout)
            if reply["ok"]:
                records.start()
                records.write(reply["samples"])
                reply["output"] = str(output)
        return reply

    def _trace(self, addr: str, config: dict, timeout: float) -> dict:
        """Hook *addr*, wait for the trace to fill up or *timeout* to pass, and unhook.

        The hook comes out however the wait ends. Its removal reports how many
        bytes its jump replaced, or None where that could not be read.
        """
        result = self.api.install_trace(addr, config)
        if not result.get("ok"):
            return {**self._base_resp(), "ok": False,
                    "error": result.get("error", "install_trace failed")}

        trace_id = result["traceId"]
        arrived = self._expect_trace(trace_id)
        try:
            try:
                self._await_trace(trace_id, arrived, timeout)
            finally:
                removed = self.api.remove_trace(trace_id)
        finally:
            samples = self._take_trace_records([trace_id])

        hook_diag = {"addr": addr, "bytesTaken": removed.get("bytesTaken"),
                     "followedTo": result.get("followedTo"), "prologue": result.get("prologue")}
        return {**self._base_resp(), "ok": True, "samples": samples,
                "count": len(samples), "output": None, "hookDiag": hook_diag}

    def _await_trace(self, trace_id: int, ev: threading.Event, timeout: float) -> None:
        """Wait until trace *trace_id* has all the records it was to take, or *timeout* has passed."""
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

    # ── collect ────────────────────────────────────────────────────────────

    def _cmd_collect(self, cmd: dict) -> dict:
        addrs = cmd.get("addrs", [])
        if not addrs:
            return {**self._base_resp(), "ok": False, "error": "no addresses given"}
        refusal = self._trace_hook_refusal(cmd, addrs)
        if refusal:
            return {**self._base_resp(), "ok": False, "error": refusal}

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"collect_{ts}.jsonl"
        output = cmd.get("output") or default_name
        out_path = Path(output) if os.path.isabs(output) else self._resolve_output_path(output)

        trace_ids: list[int] = []
        hook_diags: list[dict] = []
        removals: list[Callable[[], object]] = []
        total_collected = 0
        failure: Exception | None = None
        # Every hook is removed on the way out, whether or not the hooks after
        # it went in or another came out.
        with _RecordFile(out_path) as records:
            try:
                total_collected = self._collect_into(
                    records, cmd, addrs, trace_ids, hook_diags, removals)
            except Exception as exc:
                failure = exc
            unremoved = self._remove_hooks(removals)
            remaining = self._take_trace_records(trace_ids)
            if failure is not None:
                also = f" Removing the hooks failed as well: {'; '.join(unremoved)}" if unremoved else ""
                raise RuntimeError(f"{failure}{also}") from failure
            if unremoved:
                raise RuntimeError("; ".join(unremoved))
            records.write(remaining)
            total_collected += len(remaining)

        return {**self._base_resp(), "ok": True,
                "output": str(out_path) if records.started else None,
                "totalRecords": total_collected,
                "fenceCount": self.api.get_fence_counter(),
                "hookDiags": hook_diags}

    def _collect_into(self, records: _RecordFile, cmd: dict, addrs: list[str], trace_ids: list[int],
                      hook_diags: list[dict], removals: list[Callable[[], object]]) -> int:
        """Hook *addrs* and write what they record to *records* until the collect is over.

        Each hook's removal is appended to *removals* as soon as the hook is
        in, its trace id to *trace_ids* and what it reported to *hook_diags*,
        so the caller has them however this ends. *records* is started once
        the first hook is in.

        Returns:
            How many records were written.
        """
        duration = cmd.get("duration", 10)
        max_records = cmd.get("maxRecords", 0)
        read_specs = cmd.get("readSpecs", {})
        labels = cmd.get("labels", {})
        fence_addr = cmd.get("fence")
        total_collected = 0
        if fence_addr:
            self.api.install_fence(fence_addr)
            removals.append(self.api.remove_fence)
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
            diag = self._collect_hook_diag(addr, result)
            hook_diags.append(diag)
            if result.get("ok"):
                trace_ids.append(result["traceId"])
                removals.append(functools.partial(self._remove_collect_hook, result["traceId"], diag))
                self._expect_trace(result["traceId"])
                records.start()

        deadline = time.time() + duration
        while time.time() < deadline:
            time.sleep(0.3)

            for tid in trace_ids:
                self.api.flush_traces(tid)

            with self._lock:
                for tid in trace_ids:
                    batch = self._trace_batches.get(tid, [])
                    if batch:
                        records.write(batch)
                        total_collected += len(batch)
                        self._trace_batches[tid] = []

            all_done = all(self._trace_done.get(t) for t in trace_ids)
            if all_done:
                break
            if max_records > 0 and total_collected >= max_records:
                break
        return total_collected

    def _remove_collect_hook(self, trace_id: int, diag: dict) -> None:
        """Remove trace *trace_id* and note in *diag* how many bytes its removal counted."""
        diag["bytesTaken"] = self.api.remove_trace(trace_id).get("bytesTaken")

    @staticmethod
    def _remove_hooks(removals: list[Callable[[], object]]) -> list[str]:
        """Run every removal, last hook first, and return what the ones that failed raised."""
        unremoved = []
        for remove in reversed(removals):
            try:
                remove()
            except Exception as exc:
                unremoved.append(str(exc))
        return unremoved

    def _take_trace_records(self, trace_ids: list[int]) -> list:
        """Forget the traces *trace_ids* and return the records of theirs not yet written."""
        remaining = []
        with self._lock:
            for tid in trace_ids:
                remaining.extend(self._trace_batches.pop(tid, []))
                self._trace_done.pop(tid, None)
                self._trace_events.pop(tid, None)
        return remaining

    @staticmethod
    def _collect_hook_diag(addr: str, result: dict) -> dict:
        """What collect reports about the hook it asked for at *addr*."""
        if not result.get("ok"):
            return {"addr": addr, "ok": False, "error": result.get("error", "unknown")}
        return {"addr": addr, "ok": True, "bytesTaken": None,
                "followedTo": result.get("followedTo"), "prologue": result.get("prologue")}

    def _expect_trace(self, trace_id: int) -> threading.Event:
        """Make room for the records of trace *trace_id*; the event is set when some arrive."""
        arrived = threading.Event()
        with self._lock:
            self._trace_batches.setdefault(trace_id, [])
            self._trace_done.setdefault(trace_id, False)
            self._trace_events[trace_id] = arrived
        return arrived

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

    def run(self) -> None:
        """Take the port, attach to the target and serve commands until told to stop.

        The port comes first: where another daemon is live, this one fails
        before it has touched the target or the state file.

        Raises:
            OSError: The port is taken.
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # One daemon per port. On Windows SO_REUSEADDR would let a second
            # daemon bind beside a live one and receive half of its commands.
            if sys.platform == "win32":
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((HOST, PORT))
            srv.listen(4)
            srv.settimeout(1.0)
            self.attach()
            self._serve(srv)
        finally:
            srv.close()
            self._cleanup()

    def _serve(self, srv: socket.socket) -> None:
        STATE_FILE.write_text(json.dumps({
            "pid": os.getpid(), "port": PORT,
            "target": self.target_name, "targetPid": self.pid,
        }))
        self._wrote_state_file = True

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
            except OSError:
                pass  # the client has gone; nobody is left to tell
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
        """Unload the agent, drop the session and remove the state file this daemon wrote."""
        if self._cleaned_up:
            return
        self._cleaned_up = True
        # A target that exits clears both from Frida's thread, at any moment.
        script, session = self.script, self.session
        self.script = self.session = self.api = None
        try:
            if script is not None:
                self._unload(script)
        finally:
            try:
                if session is not None:
                    session.detach()
            finally:
                if self._wrote_state_file:
                    STATE_FILE.unlink(missing_ok=True)
                print("[livetools daemon] stopped")

    def _unload(self, script: frida.core.Script) -> None:
        """Have the agent undo its changes to the target, and unload it once that is safe.

        While a thread owes a single-step exception the agent stays loaded and
        is asked again; each time it is asked, it waits for that thread itself.
        """
        try:
            logged = None
            while True:
                _, waiting = self._shut_agent_down(script.exports_sync)
                if waiting is None:
                    break
                if waiting != logged:
                    print(f"[livetools daemon] {waiting}", file=sys.stderr)
                    logged = waiting
            script.unload()
        except frida.InvalidOperationError:
            pass  # the target exited and took the script with it

    def _shut_agent_down(self, api) -> tuple[list[str], str | None]:
        """Ask the agent once to take its changes out of the target.

        Returns:
            What it could not undo, each failure also logged the first time it
            is reported, and why the agent cannot be unloaded yet, or None if it can.
        """
        result = api.shutdown()
        for failure in result["failures"]:
            if failure not in self._shutdown_failures_reported:
                self._shutdown_failures_reported.add(failure)
                print(f"[livetools daemon] shutdown: {failure}", file=sys.stderr)
        owing = result["owedSteps"]
        if not owing:
            return result["failures"], None
        return result["failures"], _DETACH_WAITS_FOR_STEP.format(
            threads=", ".join(str(thread) for thread in owing),
            target=self.target_name, daemon=os.getpid())


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
        daemon.run()
    except Exception as exc:
        print(f"[livetools daemon] fatal: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
