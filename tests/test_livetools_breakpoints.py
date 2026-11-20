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

from live_target import ARGS, REP_COUNT, RESULT, hex_addr

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
