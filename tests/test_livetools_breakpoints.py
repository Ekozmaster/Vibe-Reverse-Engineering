"""livetools breakpoints and single-stepping on a real process.

A breakpoint stops a thread before the instruction at its address, with the
process's code and stack exactly as the program left them. ``step`` then runs
the program one instruction at a time from wherever a thread is frozen.
"""

import contextlib
import os
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

frida = pytest.importorskip("frida")

from live_target import ARGS, REP_COUNT, RESULT, hex_addr
from livetools import server

_INT3 = 0xCC
_LOOP_BODY = 0x30  # bytes from the loop label that cover every instruction a test breaks on
_PC = {"x86": "eip", "x64": "rip"}
_RESULT_REGISTER = {"x86": "eax", "x64": "rax"}


def _pc(snapshot: dict, arch: str) -> int:
    return int(snapshot["regs"][_PC[arch]], 16)


def _at(target, label: str) -> int:
    return int(target.addr(label), 16)


def _freeze_at(target, label: str) -> dict:
    """Set a breakpoint at *label*, wait for the loop to reach it, return the snapshot."""
    target.run({"cmd": "bp_add", "addr": target.addr(label)})
    reply = target.run({"cmd": "watch", "timeout": 5})
    assert reply["ok"], reply
    return reply["snapshot"]


def _step(target, mode: str) -> dict:
    reply = target.run({"cmd": "step", "mode": mode})
    assert reply["ok"], reply
    return reply["snapshot"]


def _hit_counts(target) -> dict[int, int]:
    return {int(b["addr"], 16): b["hitCount"] for b in target.run({"cmd": "bp_list"})["breakpoints"]}


def _offset(target, label: str, delta: int) -> str:
    return hex_addr(_at(target, label) + delta)


def _detach(target, timeout: float = 20.0) -> None:
    """Detach the daemon from *target*, failing if that takes longer than *timeout*."""
    detaching = threading.Thread(target=target.detach_daemon, daemon=True)
    detaching.start()
    detaching.join(timeout)
    assert not detaching.is_alive(), "the daemon is still detaching"


def _wait_until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not met in time"
        time.sleep(0.05)


_ALLOCATE_AT_JS = r"""
var virtualAlloc = new NativeFunction(
    Process.getModuleByName('kernel32.dll').getExportByName('VirtualAlloc'),
    'pointer', ['pointer', 'size_t', 'uint32', 'uint32']);
rpc.exports = {
    allocateAt: function (address, size) {
        return virtualAlloc(ptr(address), size, 0x3000, 0x40).toString();
    }
};
"""


# Parks one thread inside a call of an export (of kernel32.dll unless a module
# is named), where the agent has let go of its script lock, so a test can run a
# command at exactly that point. ``open()`` lets the thread go and unhooks the
# export; ``release()`` only lets the thread go.
_GATE_JS = r"""
var kernel32 = Process.getModuleByName('kernel32.dll');
var createEvent = new NativeFunction(kernel32.getExportByName('CreateEventW'),
    'pointer', ['pointer', 'int', 'int', 'pointer']);
var setEvent = new NativeFunction(kernel32.getExportByName('SetEvent'), 'int', ['pointer']);
var waitForSingleObject = new NativeFunction(kernel32.getExportByName('WaitForSingleObject'),
    'uint32', ['pointer', 'uint32']);
var gate = createEvent(NULL, 1, 0, NULL);
var listener = null;
var parked = false;

rpc.exports = {
    park: function (exportName, threadId, when, moduleName) {
        var module = moduleName ? Process.getModuleByName(moduleName) : kernel32;
        var callbacks = {};
        callbacks[when] = function () {
            if (parked || this.threadId !== threadId) return;
            parked = true;
            waitForSingleObject(gate, 0xFFFFFFFF);
        };
        listener = Interceptor.attach(module.getExportByName(exportName), callbacks);
    },
    parked: function () {
        return parked;
    },
    release: function () {
        setEvent(gate);
    },
    open: function () {
        setEvent(gate);
        if (listener !== null) listener.detach();
        listener = null;
    }
};
"""


# Wraps the agent so that a call it makes fails on request: ``fail(name, times)``
# makes the next ``times`` calls of ``Memory.patchCode``, ``Instruction.parse``,
# ``Interceptor.flush``, the kernel32 function ``CreateEventW`` or a hook's
# ``detach`` throw; given a thread id as well, only calls made on that thread
# count. A failing ``detach`` has unhooked first. ``attachCount()`` is how many
# hooks the agent has asked Frida for.
_FAULTY_JS = r"""
var faults = {};
var attachCount = 0;

function fails(name) {
    var fault = faults[name];
    if (fault === undefined || fault.times <= 0) return false;
    if (fault.threadId !== null && fault.threadId !== Process.getCurrentThreadId()) return false;
    fault.times--;
    return true;
}

function failing(object, objectName) {
    var copy = {};
    Object.getOwnPropertyNames(object).forEach(function (property) {
        var value = object[property];
        if (typeof value !== 'function') {
            copy[property] = value;
            return;
        }
        copy[property] = function () {
            var name = objectName + '.' + property;
            if (fails(name)) throw new Error('injected failure of ' + name);
            return value.apply(object, arguments);
        };
    });
    return copy;
}

var failingDetach = {
    flush: function () {
        if (fails('Interceptor.flush')) throw new Error('injected failure of Interceptor.flush');
        Interceptor.flush();
    },
    attach: function (address, callbacks) {
        attachCount++;
        var listener = Interceptor.attach(address, callbacks);
        return {
            detach: function () {
                listener.detach();
                if (fails('detach')) throw new Error('injected failure of detach');
            }
        };
    }
};

var createEvent = Process.getModuleByName('kernel32.dll').getExportByName('CreateEventW');

function FailingNativeFunction(address, returns, parameters, options) {
    var call = options === undefined ? new NativeFunction(address, returns, parameters)
                                     : new NativeFunction(address, returns, parameters, options);
    if (!address.equals(createEvent)) return call;
    return function () {
        if (fails('CreateEventW')) throw new Error('injected failure of CreateEventW');
        return call.apply(null, arguments);
    };
}

(function (Memory, Instruction, Interceptor, NativeFunction) { %s
})(failing(Memory, 'Memory'), failing(Instruction, 'Instruction'), failingDetach, FailingNativeFunction);

rpc.exports.fail = function (name, times, threadId) {
    faults[name] = { times: times, threadId: threadId === undefined ? null : threadId };
};
rpc.exports.attachCount = function () { return attachCount; };
"""


@pytest.fixture
def faulty_target(fresh_target, tmp_path, monkeypatch):
    """A target of its own whose agent fails a call when told to: ``daemon.api.fail(name, times)``."""
    agent = tmp_path / "faulty_agent.js"
    agent.write_text(_FAULTY_JS % server.AGENT_JS.read_text(encoding="utf-8"), encoding="utf-8")
    fresh_target.detach_daemon()
    monkeypatch.setattr(server, "AGENT_JS", agent)
    fresh_target.attach_daemon()
    return fresh_target


@pytest.fixture
def gate(target):
    """``park(export, thread, "onEnter" | "onLeave")`` holds that thread's next call until ``open()``."""
    script = target.daemon.session.create_script(_GATE_JS)
    script.load()
    yield script.exports_sync
    script.exports_sync.open()
    script.unload()


@pytest.fixture
def own_gate(fresh_target):
    """A gate in a session of its own, which stays when the daemon detaches from the target.

    It parks threads in ``NtContinue``, which does not return. Frida never
    sees a call of it end, and waits for that before any script is unloaded
    once the hook is taken out, so the hook and its session stay until the
    target is gone.
    """
    session = frida.attach(fresh_target.pid)
    script = session.create_script(_GATE_JS)
    script.load()
    yield script.exports_sync
    # A target that died took the session with it.
    with contextlib.suppress(frida.InvalidOperationError):
        script.exports_sync.release()


# Longer than any wait the agent bounds while it takes its changes out of a target.
_HELD_SECONDS = 5

# nop; nop; xor eax, eax; return from a thread routine
_RETURNS_AT_ONCE = {"x86": bytes.fromhex("9090 31C0 C20400"), "x64": bytes.fromhex("9090 31C0 C3")}

# 00 jmp 08   08 xor eax, eax   0A inc eax   0C cmp eax, 3   0F ret
_JUMP_THEN_ITS_TARGET = bytes.fromhex("EB06 909090909090 31C0 FFC0 83F803 C3")


_THREADS_JS = r"""
var kernel32 = Process.getModuleByName('kernel32.dll');
var createThread = new NativeFunction(kernel32.getExportByName('CreateThread'),
    'pointer', ['pointer', 'size_t', 'pointer', 'pointer', 'uint32', 'pointer']);
var waitForSingleObject = new NativeFunction(kernel32.getExportByName('WaitForSingleObject'),
    'uint32', ['pointer', 'uint32']);
rpc.exports = {
    start: function (entry) {
        return createThread(NULL, 0, ptr(entry), NULL, 0, NULL).toString();
    },
    hasExited: function (thread, withinMilliseconds) {
        return waitForSingleObject(ptr(thread), withinMilliseconds) === 0;
    }
};
"""

_SLEEP_SECONDS = 5


def _threads(target):
    """RPC exports that start a thread and wait for one to exit."""
    script = target.daemon.session.create_script(_THREADS_JS)
    script.load()
    return script.exports_sync


def _write_x64_sleeper(target) -> tuple[str, str]:
    """Write a thread routine that sleeps ``_SLEEP_SECONDS`` in one system call of its own.

    Returns:
        The routine's entry and its ``syscall`` instruction, which no other thread executes.
    """
    stub = target.helper.export_address("ntdll.dll", "NtDelayExecution")
    reply = target.run({"cmd": "mem_read", "addr": stub, "size": 8})
    service = bytes.fromhex(reply["hex"])[4:8]                          # mov r10, rcx; mov eax, <service>
    code = bytes.fromhex("31C9")                                        # 00 xor ecx, ecx
    code += bytes.fromhex("488D150B000000")                             # 02 lea rdx, [interval]
    code += bytes.fromhex("4C8BD1 B8") + service                       # 09 mov r10, rcx; mov eax, <service>
    code += bytes.fromhex("0F05 C3")                                    # 11 syscall; ret
    code += struct.pack("<q", -_SLEEP_SECONDS * 10_000_000)             # 14 interval, in 100 ns units
    entry = int(target.helper.allocate(len(code)), 16)
    target.run({"cmd": "mem_write", "addr": hex_addr(entry), "hex": code.hex()})
    return hex_addr(entry), hex_addr(entry + 0x11)


# Wraps the agent so that it sees a process with no Win32: the platform is
# another one and kernel32.dll is not loaded.
_OFF_WINDOWS_JS = r"""
var offWindows = new Proxy(Process, {
    get: function (process, name) {
        if (name === 'platform') return 'linux';
        if (name === 'getModuleByName') {
            return function (module) {
                if (module.toLowerCase() === 'kernel32.dll') {
                    throw new Error("unable to find module 'kernel32.dll'");
                }
                return process.getModuleByName(module);
            };
        }
        var value = process[name];
        return typeof value === 'function' ? value.bind(process) : value;
    }
});
(function (Process) { %s
})(offWindows);
"""


@pytest.fixture
def agent_off_windows(target):
    """RPC exports of a second copy of the agent, loaded as if the process were not a Windows one."""
    script = target.daemon.session.create_script(
        _OFF_WINDOWS_JS % server.AGENT_JS.read_text(encoding="utf-8"))
    script.load()
    yield script.exports_sync
    script.unload()


def _allocate_alias(target, address: int) -> int:
    """Commit a page whose address differs from *address* by exactly 4 GiB.

    The two addresses agree in their low 32 bits, so an offset between them
    truncated to 32 bits is zero. Skips if neither neighbour can be allocated.
    """
    script = target.daemon.session.create_script(_ALLOCATE_AT_JS)
    script.load()
    page = address & ~0xFFFF
    for alias_page in (page + (1 << 32), page - (1 << 32)):
        if alias_page <= 0:
            continue
        if int(script.exports_sync.allocate_at(hex_addr(alias_page), 0x10000), 16) == alias_page:
            return alias_page + (address - page)
    pytest.skip("no page exactly 4 GiB from the loop could be allocated")


class TestBreakpoint:
    def test_on_a_call_instruction_freezes_with_the_arguments_in_place(self, target):
        with target.stays_correct():
            snapshot = _freeze_at(target, "call_site")
            target.run({"cmd": "bp_del", "addr": target.addr("call_site")})

        assert _pc(snapshot, target.arch) == _at(target, "call_site")
        if target.arch == "x86":
            assert tuple(int(slot, 16) for slot in snapshot["stack"][:3]) == ARGS
        else:
            assert tuple(int(snapshot["regs"][r], 16) for r in ("rcx", "rdx", "r8")) == ARGS

    def test_frozen_snapshot_shows_the_programs_own_instruction(self, target):
        snapshot = _freeze_at(target, "callee")

        first = snapshot["disasm"][0]["str"]
        assert first == {"x86": "mov eax, dword ptr [esp + 4]", "x64": "lea eax, [rcx + rdx]"}[target.arch]

    def test_stays_set_across_resumes(self, target):
        with target.stays_correct():
            _freeze_at(target, "loop")
            for _ in range(2):
                target.run({"cmd": "resume"})
                snapshot = target.run({"cmd": "watch", "timeout": 5})["snapshot"]
            (breakpoint,) = target.run({"cmd": "bp_list"})["breakpoints"]
            target.run({"cmd": "bp_del", "addr": target.addr("loop")})

        assert breakpoint["hitCount"] == 3
        assert snapshot["bpId"] == breakpoint["id"] and snapshot["hitCount"] == 3

    def test_deleting_it_while_frozen_there_releases_the_thread(self, target):
        _freeze_at(target, "loop")

        reply = target.run({"cmd": "bp_del", "addr": target.addr("loop")})

        assert reply["ok"] and reply["state"] == "RUNNING" and reply["bpCount"] == 0
        target.wait_for_iterations(3)

    def test_deleted_while_a_thread_is_about_to_freeze_there_lets_the_thread_run(self, target, gate):
        thread = _freeze_at(target, "loop")["threadId"]
        gate.park("CreateEventW", thread, "onEnter")
        target.run({"cmd": "resume"})
        _wait_until(gate.parked)

        reply = target.run({"cmd": "bp_del", "addr": target.addr("loop")})
        gate.open()

        assert reply["ok"] and reply["state"] == "RUNNING"
        target.wait_for_iterations(3)
        assert target.run({"cmd": "status"})["state"] == "RUNNING"

    def test_removal_restores_the_original_bytes(self, target):
        built = target.loop.built_bytes("loop", 8)
        target.run({"cmd": "bp_add", "addr": target.addr("after_call")})
        target.run({"cmd": "watch", "timeout": 5})

        target.run({"cmd": "bp_del", "addr": target.addr("after_call")})

        assert target.loop.live_bytes("loop", 8) == built
        assert target.loop.live_bytes("after_call", 3) == target.loop.built_bytes("after_call", 3)

    def test_deleting_it_after_its_memory_was_unmapped_succeeds(self, target):
        gone = target.write_code(bytes.fromhex("90C3"))
        target.run({"cmd": "bp_add", "addr": hex_addr(gone)})
        target.release(gone)

        reply = target.run({"cmd": "bp_del", "addr": hex_addr(gone)})

        assert reply["ok"] and reply["bpCount"] == 0, reply

    def test_that_cannot_be_written_is_not_set(self, faulty_target):
        site = faulty_target.addr("after_call")
        faulty_target.daemon.api.fail("Memory.patchCode", 2)

        failed = [faulty_target.run({"cmd": "bp_add", "addr": site}) for _ in range(2)]
        reply = faulty_target.run({"cmd": "bp_add", "addr": site})

        assert [attempt["ok"] for attempt in failed] == [False, False], failed
        assert reply["ok"] and reply["bpCount"] == 1
        assert faulty_target.run({"cmd": "watch", "timeout": 5})["ok"]

    def test_whose_thread_cannot_be_sent_on_is_removed(self, faulty_target):
        loop = faulty_target.loop
        _freeze_at(faulty_target, "after_call")
        faulty_target.daemon.api.fail("Instruction.parse", 1)

        faulty_target.run({"cmd": "resume"})

        _wait_until(lambda: faulty_target.run({"cmd": "bp_list"})["breakpoints"] == [])
        loop.wait_for_iterations(3)
        assert loop.live_bytes("loop", _LOOP_BODY) == loop.built_bytes("loop", _LOOP_BODY)
        assert loop.bad == 0

    def test_whose_instruction_cannot_be_put_back_for_its_thread_is_removed(
            self, faulty_target, capfd):
        code = _RETURNS_AT_ONCE[faulty_target.arch]
        entry = faulty_target.write_code(code)
        faulty_target.run({"cmd": "bp_add", "addr": hex_addr(entry)})
        threads = _threads(faulty_target)
        faulty_target.daemon.api.fail("Memory.patchCode", 1)

        thread = threads.start(hex_addr(entry))

        assert threads.has_exited(thread, 5000)
        assert faulty_target.alive
        assert faulty_target.run({"cmd": "bp_list"})["breakpoints"] == []
        live = faulty_target.run({"cmd": "mem_read", "addr": hex_addr(entry), "size": len(code)})
        assert bytes.fromhex(live["hex"]) == code
        assert "injected failure of Memory.patchCode" in capfd.readouterr().err

    def test_that_can_neither_stop_its_thread_nor_be_removed_stays_set(self, faulty_target, capfd):
        entry = faulty_target.write_code(_RETURNS_AT_ONCE[faulty_target.arch])
        faulty_target.run({"cmd": "bp_add", "addr": hex_addr(entry)})
        threads = _threads(faulty_target)
        faulty_target.daemon.api.fail("CreateEventW", 1)
        faulty_target.daemon.api.fail("Memory.patchCode", 1)

        thread = threads.start(hex_addr(entry))
        hit = faulty_target.run({"cmd": "watch", "timeout": 5})
        faulty_target.run({"cmd": "resume"})

        assert hit["ok"] and int(hit["snapshot"]["addr"], 16) == entry, hit
        assert threads.has_exited(thread, 5000)
        _detach(faulty_target)
        reported = capfd.readouterr().err
        assert "injected failure of CreateEventW" in reported
        assert "injected failure of Memory.patchCode" in reported
        assert "still in the breakpoint handler" not in reported
        assert faulty_target.alive

    def test_passed_before_an_arrival_that_fails_fires_again(self, faulty_target):
        loop = faulty_target.loop
        thread = _freeze_at(faulty_target, "loop")["threadId"]
        faulty_target.run({"cmd": "bp_add", "addr": loop.addr("second")})
        faulty_target.daemon.api.fail("CreateEventW", 1, thread)

        faulty_target.run({"cmd": "resume"})
        hit = faulty_target.run({"cmd": "watch", "timeout": 5})

        assert hit["ok"] and int(hit["snapshot"]["addr"], 16) == _at(faulty_target, "loop"), hit
        assert set(_hit_counts(faulty_target)) == {_at(faulty_target, "loop")}
        assert loop.live_bytes("second", 1) == loop.built_bytes("second", 1)

    def test_on_a_breakpoint_instruction_is_refused(self, target):
        padding = f"0x{_at(target, 'callee') - 1:08X}"

        reply = target.run({"cmd": "bp_add", "addr": padding})

        assert not reply["ok"]
        assert "int3" in reply["error"]

    def test_other_threads_run_through_breakpoints_while_one_is_frozen(self, target):
        other = target.start_loop()
        _freeze_at(target, "loop")

        target.run({"cmd": "bp_add", "addr": other.addr("loop")})
        with other.stays_correct():
            other.wait_for_iterations(5)

        status = target.run({"cmd": "status"})
        assert status["state"] == "FROZEN"
        assert int(status["frozenAddr"], 16) == _at(target, "loop")
        assert _hit_counts(target)[int(other.addr("loop"), 16)] >= 5

    def test_other_threads_pass_the_breakpoint_a_thread_is_frozen_at_uncounted(self, target):
        shared = target.start_loop()
        shared.start_thread()
        target.run({"cmd": "bp_add", "addr": shared.addr("loop")})
        snapshot = target.run({"cmd": "watch", "timeout": 5})["snapshot"]
        hits_at_freeze = _hit_counts(target)[int(shared.addr("loop"), 16)]

        with shared.stays_correct():
            shared.wait_for_iterations(5)

        assert int(snapshot["addr"], 16) == int(shared.addr("loop"), 16)
        assert _hit_counts(target)[int(shared.addr("loop"), 16)] == hits_at_freeze


class TestStep:
    def test_into_executes_exactly_one_instruction(self, target):
        _freeze_at(target, "loop")

        snapshot = _step(target, "into")

        assert _pc(snapshot, target.arch) == _at(target, "second")

    def test_into_enters_the_called_function(self, target):
        _freeze_at(target, "call_site")

        snapshot = _step(target, "into")

        assert _pc(snapshot, target.arch) == _at(target, "callee")

    def test_over_runs_a_call_to_its_return(self, target):
        _freeze_at(target, "call_site")

        snapshot = _step(target, "over")

        assert _pc(snapshot, target.arch) == _at(target, "after_call")
        assert int(snapshot["regs"][_RESULT_REGISTER[target.arch]], 16) == RESULT

    def test_over_executes_one_instruction_when_it_is_not_a_call(self, target):
        _freeze_at(target, "loop")

        snapshot = _step(target, "over")

        assert _pc(snapshot, target.arch) == _at(target, "second")

    def test_out_returns_to_the_caller(self, target):
        _freeze_at(target, "callee_second")

        snapshot = _step(target, "out")

        assert _pc(snapshot, target.arch) == _at(target, "after_call")
        assert int(snapshot["regs"][_RESULT_REGISTER[target.arch]], 16) == RESULT

    def test_repeated_steps_follow_the_program_and_leave_it_correct(self, target):
        with target.stays_correct():
            _freeze_at(target, "call_site")
            visited = [_pc(_step(target, "into"), target.arch) for _ in range(3)]
            target.run({"cmd": "bp_del", "addr": target.addr("call_site")})
            target.run({"cmd": "resume"})

        assert visited[:2] == [_at(target, "callee"), _at(target, "callee_second")]

    def test_over_a_call_leaves_no_breakpoint_behind(self, target):
        with target.stays_correct():
            _freeze_at(target, "call_site")
            _step(target, "over")
            assert target.run({"cmd": "bp_del", "addr": target.addr("call_site")})["state"] == "FROZEN"
            target.run({"cmd": "resume"})

        assert target.run({"cmd": "bp_list"})["breakpoints"] == []
        assert target.loop.live_bytes("after_call", 3) == target.loop.built_bytes("after_call", 3)

    def test_out_of_a_function_that_does_not_return_is_given_up(self, target):
        _freeze_at(target, "loop")
        _step(target, "into")
        target.run({"cmd": "bp_del", "addr": target.addr("loop")})

        with target.stays_correct():
            reply = target.run({"cmd": "step", "mode": "out", "timeout": 1})

        assert not reply["ok"] and "given up" in reply["error"]
        assert reply["state"] == "RUNNING"
        assert target.loop.live_bytes("loop", _LOOP_BODY) == target.loop.built_bytes("loop", _LOOP_BODY)

    def test_over_stopped_by_a_breakpoint_in_the_callee_says_so(self, target):
        _freeze_at(target, "call_site")
        target.run({"cmd": "bp_add", "addr": target.addr("callee_second")})

        reply = target.run({"cmd": "step", "mode": "over"})

        assert reply["ok"], reply
        assert _pc(reply["snapshot"], target.arch) == _at(target, "callee_second")
        assert "breakpoint" in reply["stepInterrupted"]

    def test_over_a_call_whose_return_site_is_hooked_is_refused(self, target):
        _freeze_at(target, "call_site")
        target.daemon.api.install_fence(target.addr("after_call"))
        try:
            reply = target.run({"cmd": "step", "mode": "over"})
        finally:
            target.daemon.api.remove_fence()

        assert not reply["ok"] and "fence hook" in reply["error"], reply
        target.run({"cmd": "bp_del", "addr": target.addr("call_site")})
        target.wait_for_iterations(3)
        assert target.loop.live_bytes("loop", _LOOP_BODY) == target.loop.built_bytes("loop", _LOOP_BODY)

    def test_without_a_frozen_thread_is_an_error(self, target):
        reply = target.run({"cmd": "step", "mode": "over"})

        assert not reply["ok"] and reply["error"] == "not frozen"

    def test_ended_by_another_threads_breakpoint_says_so(self, target):
        other = target.start_loop()
        stepping = _freeze_at(target, "loop")["threadId"]
        _step(target, "into")
        target.run({"cmd": "bp_del", "addr": target.addr("loop")})
        target.run({"cmd": "bp_add", "addr": other.addr("loop")})

        reply = target.run({"cmd": "step", "mode": "out", "timeout": 5})

        assert reply["ok"], reply
        assert reply["snapshot"]["threadId"] != stepping
        assert int(reply["snapshot"]["addr"], 16) == int(other.addr("loop"), 16)
        assert f"thread {stepping} is running" in reply["stepInterrupted"]
        target.wait_for_iterations(3)

    def test_ended_by_another_threads_breakpoint_before_it_starts_is_not_taken_later(self, target, gate):
        other = target.start_loop()
        stepping = _freeze_at(target, "call_site")["threadId"]
        gate.park("WaitForSingleObject", stepping, "onLeave")
        target.run({"cmd": "resume"})
        assert target.run({"cmd": "watch", "timeout": 5})["ok"]
        target.run({"cmd": "bp_add", "addr": other.addr("loop")})

        reply = target.run({"cmd": "step", "mode": "over", "timeout": 5})
        assert reply["ok"] and reply["snapshot"]["threadId"] != stepping, reply
        _wait_until(gate.parked)
        target.run({"cmd": "bp_del", "addr": other.addr("loop")})
        target.run({"cmd": "bp_del", "addr": target.addr("call_site")})
        gate.open()

        target.wait_for_iterations(3)
        assert target.run({"cmd": "status"})["state"] == "RUNNING"

    def test_given_up_while_its_thread_is_about_to_freeze_leaves_the_thread_running(self, target, gate):
        stepping = _freeze_at(target, "loop")["threadId"]
        gate.park("CreateEventW", stepping, "onEnter")

        reply = target.run({"cmd": "step", "mode": "into", "timeout": 1})
        target.run({"cmd": "bp_del", "addr": target.addr("loop")})
        gate.open()

        assert not reply["ok"] and "given up" in reply["error"], reply
        target.wait_for_iterations(3)
        assert target.run({"cmd": "status"})["state"] == "RUNNING"

    def test_interrupted_single_step_leaves_the_stepped_thread_running(self, target):
        stepped = target.start_loop()
        size = 8 << 20
        stepped.set_repeat(int(target.helper.allocate(size), 16), size)
        stepped.start_repeater()
        before_rep = hex_addr(int(stepped.addr("rep"), 16) - 2)
        target.run({"cmd": "bp_add", "addr": before_rep})
        assert target.run({"cmd": "watch", "timeout": 5})["ok"]
        _step(target, "into")
        target.run({"cmd": "bp_del", "addr": before_rep})
        target.run({"cmd": "bp_add", "addr": target.addr("loop")})

        reply = target.run({"cmd": "step", "mode": "into", "timeout": 5})

        assert reply["ok"], reply
        assert _pc(reply["snapshot"], target.arch) == _at(target, "loop")
        assert "stepInterrupted" in reply
        target.run({"cmd": "bp_del", "addr": target.addr("loop")})
        reps = stepped.reps
        _wait_until(lambda: stepped.reps >= reps + 2)
        assert target.run({"cmd": "status"})["state"] == "RUNNING"

    def test_whose_arrival_fails_reports_why_at_once(self, faulty_target):
        thread = _freeze_at(faulty_target, "loop")["threadId"]
        faulty_target.daemon.api.fail("CreateEventW", 1, thread)

        reply = faulty_target.run({"cmd": "step", "mode": "into", "timeout": 5})

        assert not reply["ok"] and "injected failure of CreateEventW" in reply["error"], reply
        assert faulty_target.run({"cmd": "watch", "timeout": 5})["ok"]

    def test_that_its_thread_cannot_start_reports_why_at_once(self, faulty_target):
        thread = _freeze_at(faulty_target, "loop")["threadId"]
        faulty_target.daemon.api.fail("Instruction.parse", 1, thread)

        reply = faulty_target.run({"cmd": "step", "mode": "into", "timeout": 5})

        assert not reply["ok"] and "injected failure of Instruction.parse" in reply["error"], reply
        faulty_target.loop.wait_for_iterations(3)

    def test_over_a_call_whose_return_cannot_be_met_reports_why_at_once(self, faulty_target):
        loop = faulty_target.loop
        thread = _freeze_at(faulty_target, "call_site")["threadId"]
        faulty_target.daemon.api.fail("CreateEventW", 1, thread)

        reply = faulty_target.run({"cmd": "step", "mode": "over", "timeout": 5})

        assert not reply["ok"] and "injected failure of CreateEventW" in reply["error"], reply
        assert loop.live_bytes("after_call", 1) == loop.built_bytes("after_call", 1)
        assert faulty_target.run({"cmd": "watch", "timeout": 5})["ok"]

_COUNT_REGISTER = {"x86": "ecx", "x64": "rcx"}


class TestRepeatedInstruction:
    """A rep string instruction runs every iteration in place, with the pc left on it."""

    @pytest.fixture(autouse=True)
    def _repeater(self, target):
        target.loop.start_repeater()

    def test_one_resume_from_a_breakpoint_on_it_is_one_hit(self, target):
        first = _freeze_at(target, "rep")
        reps = target.loop.reps

        target.run({"cmd": "resume"})
        second = target.run({"cmd": "watch", "timeout": 5})["snapshot"]

        assert second["hitCount"] == first["hitCount"] + 1
        assert target.loop.reps == reps + 1

    def test_resume_from_a_breakpoint_on_it_passes_it_when_the_next_instruction_is_hooked(self, target):
        first = _freeze_at(target, "rep")
        probe = {}
        probing = threading.Thread(target=lambda: probe.update(target.run(
            {"cmd": "trace", "addr": target.addr("after_rep"), "count": 1, "timeout": 5,
             "probe": True})))
        probing.start()
        _wait_until(lambda: target.loop.live_bytes("after_rep", 1) == b"\xE9")

        target.run({"cmd": "resume"})
        second = target.run({"cmd": "watch", "timeout": 5})
        probing.join()

        assert second["ok"] and second["snapshot"]["hitCount"] == first["hitCount"] + 1
        assert probe["ok"] and probe["count"] == 1

    def test_step_over_from_a_breakpoint_on_it_runs_it_to_the_end(self, target):
        frozen = _freeze_at(target, "rep")

        snapshot = _step(target, "over")

        assert int(frozen["regs"][_COUNT_REGISTER[target.arch]], 16) == REP_COUNT
        assert _pc(snapshot, target.arch) == _at(target, "after_rep")
        assert int(snapshot["regs"][_COUNT_REGISTER[target.arch]], 16) == 0
        assert _hit_counts(target)[_at(target, "rep")] == frozen["hitCount"]

    def test_step_into_runs_it_to_the_end(self, target):
        target.run({"cmd": "bp_add", "addr": _offset(target, "rep", -2)})
        target.run({"cmd": "watch", "timeout": 5})
        assert _pc(_step(target, "into"), target.arch) == _at(target, "rep")

        snapshot = _step(target, "into")

        assert _pc(snapshot, target.arch) == _at(target, "after_rep")
        assert int(snapshot["regs"][_COUNT_REGISTER[target.arch]], 16) == 0


class TestForeignExceptions:
    def test_the_programs_own_int3_and_single_step_reach_its_handler(self, target):
        other = target.start_loop()
        before = target.helper.own_exceptions()

        with other.stays_correct():
            target.helper.plant_own_trap(other.addr("spare"))
            other.wait_for_iterations(3)

        after = target.helper.own_exceptions()
        assert after["breakpoint"] - before["breakpoint"] >= 3
        assert after["singleStep"] - before["singleStep"] >= 3


class TestHookConflicts:
    def test_trace_on_a_breakpointed_address_is_refused(self, target):
        _freeze_at(target, "callee")

        reply = target.run({"cmd": "trace", "addr": target.addr("callee"), "count": 1, "timeout": 1})

        assert not reply["ok"]
        assert "breakpoint" in reply["error"]

    def test_probe_on_a_breakpointed_call_site_is_refused(self, target):
        _freeze_at(target, "call_site")

        reply = target.run({"cmd": "trace", "addr": target.addr("call_site"), "count": 1,
                            "timeout": 1, "probe": True})

        assert not reply["ok"]
        assert "breakpoint" in reply["error"]

    def test_fence_on_a_breakpointed_address_is_refused(self, target, tmp_path):
        _freeze_at(target, "call_site")

        reply = target.run({"cmd": "collect", "addrs": [target.addr("callee")], "duration": 1,
                            "fence": target.addr("call_site"),
                            "output": str(tmp_path / "fenced.jsonl")})

        assert not reply["ok"]
        assert "breakpoint" in reply["error"]

    def test_breakpoint_inside_the_bytes_of_a_hook_is_refused(self, target):
        target.daemon.api.install_fence(target.addr("callee"))
        try:
            reply = target.run({"cmd": "bp_add", "addr": target.addr("callee_second")})
        finally:
            target.daemon.api.remove_fence()

        assert not reply["ok"]
        assert "hook" in reply["error"]

    def test_probe_overlapping_the_bytes_of_another_hook_is_refused(self, target):
        target.daemon.api.install_fence(target.addr("dormant"))
        try:
            reply = target.run({"cmd": "trace", "addr": _offset(target, "dormant", 2),
                                "count": 1, "timeout": 1, "probe": True})
        finally:
            target.daemon.api.remove_fence()

        assert not reply["ok"]
        assert "overlap" in reply["error"], reply
        assert target.loop.live_bytes("dormant", 16) == target.loop.built_bytes("dormant", 16)

    def test_hook_whose_removal_fails_gives_its_bytes_up(self, faulty_target):
        site = faulty_target.addr("call_site")
        faulty_target.daemon.api.fail("detach", 1)

        trace = faulty_target.run({"cmd": "trace", "addr": site, "count": 0, "timeout": 0.5,
                                   "probe": True})
        reply = faulty_target.run({"cmd": "bp_add", "addr": site})

        assert not trace["ok"] and "injected failure of detach" in trace["error"], trace
        assert reply["ok"], reply

    def test_probe_on_a_jump_is_refused_before_frida_is_asked_for_a_hook(self, faulty_target):
        code = faulty_target.write_code(_JUMP_THEN_ITS_TARGET)
        asked = faulty_target.daemon.api.attach_count()

        reply = faulty_target.run({"cmd": "trace", "addr": hex_addr(code), "count": 1,
                                   "timeout": 0.2, "probe": True})

        assert not reply["ok"] and "bp add" in reply["error"], reply
        assert hex_addr(code + 8)[2:] in reply["error"], reply
        assert faulty_target.daemon.api.attach_count() == asked

    def test_hook_that_fails_once_frida_has_placed_it_is_taken_out_again(self, faulty_target):
        loop = faulty_target.loop
        faulty_target.daemon.api.fail("Interceptor.flush", 1)

        trace = faulty_target.run({"cmd": "trace", "addr": loop.addr("callee"), "count": 1,
                                   "timeout": 1})
        after = loop.live_bytes("callee", 8)
        reply = faulty_target.run({"cmd": "bp_add", "addr": loop.addr("callee")})

        assert not trace["ok"] and "injected failure of Interceptor.flush" in trace["error"], trace
        assert after == loop.built_bytes("callee", 8)
        assert reply["ok"], reply

    def test_two_hooks_at_one_address_both_run(self, target, tmp_path):
        with target.stays_correct():
            reply = target.run({"cmd": "collect", "addrs": [target.addr("callee")],
                                "duration": 5, "maxRecords": 3, "fence": target.addr("callee"),
                                "output": str(tmp_path / "shared.jsonl")})

        assert reply["ok"] and reply["totalRecords"] >= 3 and reply["fenceCount"] >= 3, reply

    def test_steptrace_is_refused_while_a_breakpoint_is_set(self, target):
        _freeze_at(target, "loop")

        reply = target.run({"cmd": "steptrace", "addr": target.addr("callee"), "timeout": 1})

        assert not reply["ok"]
        assert "breakpoint" in reply["error"]

    def test_steptrace_that_times_out_leaves_breakpoints_allowed(self, target):
        reply = target.run({"cmd": "steptrace", "addr": target.addr("dormant"), "timeout": 1})
        assert not reply["ok"] and "removed" in reply["error"]

        assert target.run({"cmd": "bp_add", "addr": target.addr("loop")})["ok"]
        assert target.loop.live_bytes("dormant", 16) == target.loop.built_bytes("dormant", 16)

    def test_function_hook_on_a_probed_call_site_is_refused(self, target):
        target.daemon.api.install_fence(target.addr("call_site"))
        try:
            with target.stays_correct():
                reply = target.run({"cmd": "trace", "addr": target.addr("call_site"),
                                    "count": 1, "timeout": 1})
        finally:
            target.daemon.api.remove_fence()

        assert not reply["ok"] and "call instruction" in reply["error"], reply

    def test_mem_write_keeps_the_page_protection(self, target):
        target.helper.make_read_execute(target.addr("dormant"), 1)

        reply = target.run({"cmd": "mem_write", "addr": _offset(target, "dormant", 1), "hex": "90"})

        assert reply["ok"], reply
        assert target.helper.protection(target.addr("dormant")) == "r-x"

    def test_mem_write_over_a_breakpoint_is_refused(self, target):
        target.run({"cmd": "bp_add", "addr": _offset(target, "dormant", 2)})

        reply = target.run({"cmd": "mem_write", "addr": target.addr("dormant"), "hex": "C3C3C3C3"})

        assert not reply["ok"] and "breakpoint" in reply["error"]
        assert target.loop.live_bytes("dormant", 2) == target.loop.built_bytes("dormant", 2)

    @pytest.mark.parametrize("label", ["dormant", "page"])
    def test_empty_mem_write_succeeds_without_changing_protection(self, target, label):
        address = hex_addr(_at(target, "dormant") & ~0xFFF) if label == "page" else target.addr(label)

        reply = target.run({"cmd": "mem_write", "addr": address, "hex": ""})

        assert reply["ok"], reply
        assert target.helper.protection(address) == "r-x"

    @pytest.mark.parametrize("hex_bytes", ["9", "909", "zz"])
    def test_malformed_hex_mem_write_is_refused(self, target, hex_bytes):
        reply = target.run({"cmd": "mem_write", "addr": target.addr("dormant"), "hex": hex_bytes})

        assert not reply["ok"] and "hex" in reply["error"]
        assert target.loop.live_bytes("dormant", 2) == target.loop.built_bytes("dormant", 2)

    def test_original_instruction_ignores_a_breakpoint_exactly_4gib_away(self, target):
        if target.arch != "x64":
            pytest.skip("needs a 64-bit address space")
        dormant = _at(target, "dormant")
        alias = _allocate_alias(target, dormant)
        target.run({"cmd": "bp_add", "addr": hex_addr(alias)})

        insn = target.daemon.api.original_instruction(target.addr("dormant"))

        assert insn["str"] == "nop"

class TestOffWindows:
    def test_memory_is_readable(self, target, agent_off_windows):
        live = agent_off_windows.read_memory(target.addr("dormant"), 16)

        assert bytes(live) == target.loop.built_bytes("dormant", 16)

    def test_breakpoint_is_refused(self, target, agent_off_windows):
        reply = agent_off_windows.install_bp(target.addr("dormant"))

        assert not reply["ok"] and "Windows" in reply["error"], reply
        assert target.loop.live_bytes("dormant", 16) == target.loop.built_bytes("dormant", 16)


@pytest.fixture
def x86_target(target):
    """The shared target, for the 32-bit-only vishook."""
    if target.arch != "x86":
        pytest.skip("vishook builds 32-bit code")
    return target


def _vishook_on(target, site: str) -> dict:
    return target.run({"cmd": "vishook_on", "threshold": "500000", "jmpSite": site,
                       "origTarget": target.addr("dormant")})


class TestVishook:
    def test_is_refused_in_a_64_bit_process(self, target):
        if target.arch != "x64":
            pytest.skip("the refusal is for 64-bit processes")

        reply = _vishook_on(target, target.addr("dormant"))

        assert not reply["ok"] and "64-bit" in reply["error"]

    def test_over_a_breakpoint_is_refused(self, x86_target):
        x86_target.run({"cmd": "bp_add", "addr": _offset(x86_target, "dormant", 4)})

        reply = _vishook_on(x86_target, x86_target.addr("dormant"))

        assert not reply["ok"] and "breakpoint" in reply["error"]
        assert x86_target.loop.live_bytes("dormant", 4) == x86_target.loop.built_bytes("dormant", 4)

    def test_breakpoint_inside_its_jump_is_refused(self, x86_target):
        assert _vishook_on(x86_target, x86_target.addr("dormant"))["ok"]

        reply = x86_target.run({"cmd": "bp_add", "addr": _offset(x86_target, "dormant", 4)})

        assert not reply["ok"] and "(vishook off)" in reply["error"]

    def test_trace_over_its_jump_is_refused(self, x86_target):
        assert _vishook_on(x86_target, _offset(x86_target, "dormant", 2))["ok"]

        reply = x86_target.run({"cmd": "trace", "addr": x86_target.addr("dormant"), "count": 1,
                                "timeout": 1, "probe": True})

        assert not reply["ok"] and "vishook" in reply["error"]

    def test_mem_write_over_its_jump_is_refused(self, x86_target):
        assert _vishook_on(x86_target, x86_target.addr("dormant"))["ok"]

        reply = x86_target.run({"cmd": "mem_write", "addr": _offset(x86_target, "dormant", 4),
                                "hex": "90"})

        assert not reply["ok"] and "vishook" in reply["error"]

    def test_keeps_the_page_protection(self, x86_target):
        x86_target.helper.make_read_execute(x86_target.addr("dormant"), 1)
        assert _vishook_on(x86_target, x86_target.addr("dormant"))["ok"]
        on = x86_target.helper.protection(x86_target.addr("dormant"))

        x86_target.run({"cmd": "vishook_off"})

        assert on == "r-x"
        assert x86_target.helper.protection(x86_target.addr("dormant")) == "r-x"

    def test_off_restores_the_original_bytes(self, x86_target):
        _vishook_on(x86_target, x86_target.addr("dormant"))

        x86_target.run({"cmd": "vishook_off"})

        assert x86_target.loop.live_bytes("dormant", 16) == x86_target.loop.built_bytes("dormant", 16)


class TestUnload:
    def test_detach_restores_the_code_and_releases_a_frozen_thread(self, fresh_target):
        loop = fresh_target.loop
        _freeze_at(fresh_target, "loop")
        fresh_target.run({"cmd": "bp_add", "addr": loop.addr("after_call")})

        fresh_target.detach_daemon()
        fresh_target.attach_daemon()

        loop.wait_for_iterations(5)
        assert loop.live_bytes("loop", _LOOP_BODY) == loop.built_bytes("loop", _LOOP_BODY)
        assert loop.bad == 0

    def test_detach_restores_the_code_around_a_breakpoint_whose_memory_was_unmapped(
            self, fresh_target, capfd):
        loop = fresh_target.loop
        gone = fresh_target.write_code(bytes.fromhex("90C3"))
        fresh_target.run({"cmd": "bp_add", "addr": hex_addr(gone)})
        _freeze_at(fresh_target, "loop")
        fresh_target.run({"cmd": "bp_add", "addr": loop.addr("after_call")})
        fresh_target.release(gone)

        _detach(fresh_target)
        fresh_target.attach_daemon()

        loop.wait_for_iterations(5)
        assert loop.live_bytes("loop", _LOOP_BODY) == loop.built_bytes("loop", _LOOP_BODY)
        assert loop.bad == 0
        assert "shutdown:" not in capfd.readouterr().err

    def test_detach_reports_a_breakpoint_it_cannot_remove_and_removes_the_others(
            self, faulty_target, capfd):
        loop = faulty_target.loop
        stuck = faulty_target.write_code(bytes.fromhex("90C3"))
        faulty_target.run({"cmd": "bp_add", "addr": hex_addr(stuck)})
        _freeze_at(faulty_target, "after_call")
        faulty_target.daemon.api.fail("Memory.patchCode", 1)

        _detach(faulty_target)
        faulty_target.attach_daemon()

        (report,) = [line for line in capfd.readouterr().err.splitlines() if "shutdown:" in line]
        assert "breakpoint at" in report and f"{stuck:X}: injected failure" in report
        loop.wait_for_iterations(5)
        assert loop.live_bytes("loop", _LOOP_BODY) == loop.built_bytes("loop", _LOOP_BODY)

    @pytest.mark.skipif(
        os.environ.get("GITHUB_ACTIONS") == "true",
        reason="never returns for the x64 target on the GitHub Windows runner (which call blocks is not known)")
    def test_detach_reports_a_thread_that_does_not_leave_the_handler(self, fresh_target, capfd):
        loop = fresh_target.loop
        thread = _freeze_at(fresh_target, "loop")["threadId"]
        gate = fresh_target.daemon.session.create_script(_GATE_JS)
        gate.load()
        reported = []

        def report_seen() -> bool:
            reported.append(capfd.readouterr().err)
            return "1 thread still in the breakpoint handler" in "".join(reported)

        detaching = threading.Thread(target=fresh_target.detach_daemon, daemon=True)
        try:
            gate.exports_sync.park("CreateEventW", thread, "onEnter")
            fresh_target.run({"cmd": "resume"})
            _wait_until(gate.exports_sync.parked)
            detaching.start()
            _wait_until(report_seen, timeout=15)
        finally:
            # A thread left parked would block every later unload, the fixture's among them
            gate.exports_sync.open()
        detaching.join(15)

        assert not detaching.is_alive()
        fresh_target.attach_daemon()
        loop.wait_for_iterations(5)
        assert loop.live_bytes("loop", _LOOP_BODY) == loop.built_bytes("loop", _LOOP_BODY)

    def test_detach_waits_for_a_thread_that_still_owes_its_single_step(
            self, fresh_target, own_gate, capfd):
        loop = fresh_target.loop
        thread = _freeze_at(fresh_target, "loop")["threadId"]
        own_gate.park("NtContinue", thread, "onEnter", "ntdll.dll")
        fresh_target.run({"cmd": "resume"})
        _wait_until(own_gate.parked)
        agent = fresh_target.daemon.script
        reported = []

        def wait_reported() -> bool:
            reported.append(capfd.readouterr().err)
            return f"detach is waiting for thread {thread}" in "".join(reported)

        reply = fresh_target.run({"cmd": "detach"})
        detaching = threading.Thread(target=fresh_target.detach_daemon, daemon=True)
        detaching.start()
        try:
            _wait_until(wait_reported, timeout=10)
            agent_stays = detaching.is_alive() and not agent.is_destroyed
        finally:
            own_gate.release()
        detaching.join(15)

        assert agent_stays
        assert f"thread {thread}" in reply["waitingOn"]
        assert not detaching.is_alive()
        assert fresh_target.alive
        fresh_target.attach_daemon()
        loop.wait_for_iterations(5)
        assert loop.live_bytes("loop", _LOOP_BODY) == loop.built_bytes("loop", _LOOP_BODY)
        assert loop.bad == 0

    def test_a_daemon_that_dies_leaves_its_agent_for_a_thread_that_still_owes_its_single_step(
            self, fresh_target, own_gate, tmp_path):
        loop = fresh_target.loop
        tests_dir = Path(__file__).resolve().parent
        script = tmp_path / "second_daemon.py"
        script.write_text(
            "import sys, time\n"
            f"sys.path.insert(0, {str(tests_dir)!r})\n"
            "from live_target import server\n"
            f"daemon = server.Daemon({str(fresh_target.pid)!r})\n"
            "daemon.attach()\n"
            f"daemon.handle({{'cmd': 'bp_add', 'addr': {loop.addr('loop')!r}}})\n"
            "hit = daemon.handle({'cmd': 'watch', 'timeout': 5})\n"
            "print(hit['snapshot']['threadId'], flush=True)\n"
            "sys.stdin.readline()\n"
            "daemon.handle({'cmd': 'resume'})\n"
            "print('resumed', flush=True)\n"
            "time.sleep(600)\n"
        )
        second = subprocess.Popen([sys.executable, str(script)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
        try:
            thread = int(second.stdout.readline())
            own_gate.park("NtContinue", thread, "onEnter", "ntdll.dll")
            second.stdin.write("\n")
            second.stdin.flush()
            assert second.stdout.readline().strip() == "resumed"
            _wait_until(own_gate.parked)
        finally:
            second.kill()
            second.wait()
        time.sleep(_HELD_SECONDS)
        own_gate.release()

        loop.wait_for_iterations(5)
        assert fresh_target.alive
        assert loop.live_bytes("loop", _LOOP_BODY) == loop.built_bytes("loop", _LOOP_BODY)
        assert loop.bad == 0

    def test_detach_while_a_thread_runs_a_long_repeated_instruction_leaves_it_running(
            self, fresh_target):
        loop = fresh_target.loop
        size = 64 << 20
        loop.set_repeat(int(fresh_target.helper.allocate(size), 16), size)
        loop.start_repeater()
        _freeze_at(fresh_target, "rep")
        fresh_target.run({"cmd": "resume"})
        reps = loop.reps

        fresh_target.detach_daemon()
        fresh_target.attach_daemon()

        _wait_until(lambda: loop.reps > reps + 1)
        assert fresh_target.alive

    def test_detach_while_a_thread_blocks_in_the_instruction_it_was_sent_past_leaves_it_running(
            self, fresh_target):
        if fresh_target.arch != "x64":
            pytest.skip("the sleeping routine is x64 code")
        loop = fresh_target.loop
        _freeze_at(fresh_target, "spare")
        entry, enters_kernel = _write_x64_sleeper(fresh_target)
        fresh_target.run({"cmd": "bp_add", "addr": enters_kernel})
        sleeper = _threads(fresh_target).start(entry)
        _wait_until(lambda: _hit_counts(fresh_target)[int(enters_kernel, 16)] > 0)

        fresh_target.detach_daemon()
        fresh_target.attach_daemon()

        assert _threads(fresh_target).has_exited(sleeper, 2 * _SLEEP_SECONDS * 1000)
        assert fresh_target.alive
        loop.wait_for_iterations(3)

    def test_detach_removes_the_vishook(self, fresh_target):
        if fresh_target.arch != "x86":
            pytest.skip("vishook builds 32-bit code")
        loop = fresh_target.loop
        assert _vishook_on(fresh_target, loop.addr("dormant"))["ok"]
        assert loop.live_bytes("dormant", 1) == b"\xE9"

        fresh_target.detach_daemon()
        fresh_target.attach_daemon()

        assert loop.live_bytes("dormant", 16) == loop.built_bytes("dormant", 16)

    def test_a_daemon_that_dies_leaves_no_breakpoint_behind(self, fresh_target, tmp_path):
        loop = fresh_target.loop
        tests_dir = Path(__file__).resolve().parent
        script = tmp_path / "second_daemon.py"
        script.write_text(
            "import sys, time\n"
            f"sys.path.insert(0, {str(tests_dir)!r})\n"
            "from live_target import server\n"
            f"daemon = server.Daemon({str(fresh_target.pid)!r})\n"
            "daemon.attach()\n"
            f"daemon.handle({{'cmd': 'bp_add', 'addr': {loop.addr('loop')!r}}})\n"
            "daemon.handle({'cmd': 'watch', 'timeout': 5})\n"
            f"daemon.handle({{'cmd': 'bp_add', 'addr': {loop.addr('after_call')!r}}})\n"
            "print('frozen', flush=True)\n"
            "time.sleep(600)\n"
        )
        second = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, text=True)
        try:
            assert second.stdout.readline().strip() == "frozen"
            assert loop.live_bytes("after_call", 1)[0] == _INT3
        finally:
            second.kill()
            second.wait()

        _wait_until(lambda: loop.live_bytes("loop", _LOOP_BODY) == loop.built_bytes("loop", _LOOP_BODY))
        loop.wait_for_iterations(5)
        assert loop.bad == 0
