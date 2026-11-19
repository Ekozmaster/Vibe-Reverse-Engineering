"""livetools breakpoints and single-stepping on a real process.

A breakpoint stops a thread before the instruction at its address, with the
process's code and stack exactly as the program left them. ``step`` then runs
the program one instruction at a time from wherever a thread is frozen.
"""

import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("frida")

from live_target import ARGS, RESULT

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


def _wait_until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not met in time"
        time.sleep(0.05)


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

    def test_removal_restores_the_original_bytes(self, target):
        built = target.loop.built_bytes("loop", 8)
        target.run({"cmd": "bp_add", "addr": target.addr("after_call")})
        target.run({"cmd": "watch", "timeout": 5})

        target.run({"cmd": "bp_del", "addr": target.addr("after_call")})

        assert target.loop.live_bytes("loop", 8) == built
        assert target.loop.live_bytes("after_call", 3) == target.loop.built_bytes("after_call", 3)

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
        hits = {int(b["addr"], 16): b["hitCount"] for b in target.run({"cmd": "bp_list"})["breakpoints"]}
        assert hits[int(other.addr("loop"), 16)] >= 5


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
            target.run({"cmd": "bp_del", "addr": target.addr("call_site")})
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

    def test_without_a_frozen_thread_is_an_error(self, target):
        reply = target.run({"cmd": "step", "mode": "over"})

        assert not reply["ok"] and reply["error"] == "not frozen"


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

    def test_steptrace_is_refused_while_a_breakpoint_is_set(self, target):
        _freeze_at(target, "loop")

        reply = target.run({"cmd": "steptrace", "addr": target.addr("callee"), "timeout": 1})

        assert not reply["ok"]
        assert "breakpoint" in reply["error"]


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
