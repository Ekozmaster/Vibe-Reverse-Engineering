"""What the livetools daemon asks of its agent, and how the CLI talks to the daemon.

The Frida agent is replaced by a stand-in that records what it is asked to
install, so these run on any platform. The hooks themselves are exercised
against a real process in test_livetools_live.py.
"""

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("frida")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import livetools.__main__ as cli
from livetools import client, server

ENTRY = "0x00401040"
CALL_SITE = "0x00401006"

_CODE = {ENTRY: "push ebp", CALL_SITE: "call 0x401040"}


class FakeAgent:
    """Stands in for the agent's RPC surface and records what it is asked to do.

    Attributes:
        frozen_addr: Where a thread is frozen, or None.
        calls: Names of the state-changing calls made, in order.
        on_unfreeze: Called with the step mode when the frozen thread is released.
    """

    def __init__(self):
        self.traces: list[tuple[str, dict]] = []
        self.fences: list[str] = []
        self.step_traces: list[str] = []
        self.frozen_addr: str | None = None
        self.frozen_thread = 100
        self.calls: list[str] = []
        self.frozen_checks = 0
        self.on_unfreeze = lambda step: None
        self.on_cancel_step = lambda: None
        self.bp_refusal: str | None = None
        self.step_trace_result: dict | None = {"addr": ENTRY, "insnCount": 0, "trace": []}

    def list_bps(self):
        return []

    def is_frozen(self):
        self.frozen_checks += 1
        return self.frozen_addr is not None

    def get_frozen_addr(self):
        return self.frozen_addr

    def install_bp(self, addr):
        if self.bp_refusal:
            return {"ok": False, "error": self.bp_refusal}
        return {"ok": True, "id": 1}

    def remove_bp(self, addr):
        self.calls.append("remove_bp")
        if self.frozen_addr is not None and int(self.frozen_addr, 16) == int(addr, 16):
            self.frozen_addr = None
        return {"ok": True}

    def unfreeze(self, step):
        self.calls.append("unfreeze")
        if self.frozen_addr is None:
            return False
        self.frozen_addr = None
        self.on_unfreeze(step)
        return True

    def cancel_step(self):
        self.calls.append("cancel_step")
        self.on_cancel_step()

    def get_snapshot(self, stack_count, disasm_count):
        if self.frozen_addr is None:
            return None
        return {"addr": self.frozen_addr, "threadId": self.frozen_thread, "hitCount": 0,
                "regs": {}, "stack": [], "disasm": []}

    def original_instruction(self, addr):
        return {"str": _CODE[addr], "isCall": _CODE[addr].startswith("call")}

    def install_trace(self, addr, config):
        self.traces.append((addr, config))
        return {"ok": True, "traceId": len(self.traces)}

    def flush_traces(self, trace_id):
        return {"ok": True, "done": True, "collected": 0}

    def remove_trace(self, trace_id):
        return {"ok": True}

    def install_fence(self, addr):
        self.fences.append(addr)
        return {"ok": True}

    def remove_fence(self):
        return {"ok": True}

    def get_fence_counter(self):
        return 0

    def install_step_trace(self, addr, config):
        self.step_traces.append(addr)
        return {"ok": True}

    def get_step_trace_result(self):
        return self.step_trace_result

    def cancel_step_trace(self):
        self.calls.append("cancel_step_trace")
        return {"ok": True}


@pytest.fixture
def agent():
    return FakeAgent()


@pytest.fixture
def daemon(agent):
    attached = server.Daemon("target.exe")
    attached.api = agent
    return attached


class TestTrace:
    def test_function_hook_at_an_entry_is_installed(self, daemon, agent):
        reply = daemon.handle({"cmd": "trace", "addr": ENTRY, "timeout": 0})

        assert reply["ok"]
        ((addr, config),) = agent.traces
        assert addr == ENTRY and not config["probe"]

    def test_function_hook_on_a_call_instruction_is_refused(self, daemon, agent):
        reply = daemon.handle({"cmd": "trace", "addr": CALL_SITE, "timeout": 0})

        assert not reply["ok"]
        assert CALL_SITE in reply["error"]
        assert "call instruction" in reply["error"] and "--probe" in reply["error"]
        assert agent.traces == []

    def test_probe_on_a_call_instruction_is_installed(self, daemon, agent):
        reply = daemon.handle({"cmd": "trace", "addr": CALL_SITE, "timeout": 0, "probe": True})

        assert reply["ok"]
        ((addr, config),) = agent.traces
        assert addr == CALL_SITE and config["probe"]

    def test_probe_cannot_read_at_return(self, daemon, agent):
        reply = daemon.handle({"cmd": "trace", "addr": CALL_SITE, "timeout": 0,
                               "probe": True, "readLeave": "eax"})

        assert not reply["ok"]
        assert "--read-leave" in reply["error"]
        assert agent.traces == []


class TestCollect:
    def test_one_call_instruction_refuses_the_whole_collect(self, daemon, agent, tmp_path):
        output = tmp_path / "out.jsonl"

        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY, CALL_SITE],
                               "duration": 0, "output": str(output)})

        assert not reply["ok"]
        assert CALL_SITE in reply["error"] and "--probe" in reply["error"]
        assert agent.traces == []
        assert not output.exists()

    def test_probe_applies_to_every_address(self, daemon, agent, tmp_path):
        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY, CALL_SITE], "duration": 0,
                               "probe": True, "output": str(tmp_path / "out.jsonl")})

        assert reply["ok"]
        assert [(addr, config["probe"]) for addr, config in agent.traces] == [
            (ENTRY, True), (CALL_SITE, True)]

    def test_fence_may_sit_on_a_call_instruction(self, daemon, agent, tmp_path):
        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY], "duration": 0,
                               "fence": CALL_SITE, "output": str(tmp_path / "out.jsonl")})

        assert reply["ok"]
        assert agent.fences == [CALL_SITE]


class TestStepTrace:
    def test_call_instruction_is_refused(self, daemon, agent):
        reply = daemon.handle({"cmd": "steptrace", "addr": CALL_SITE, "timeout": 0})

        assert not reply["ok"]
        assert CALL_SITE in reply["error"] and "call instruction" in reply["error"]
        assert agent.step_traces == []

    def test_that_times_out_is_removed(self, daemon, agent):
        agent.step_trace_result = None

        reply = daemon.handle({"cmd": "steptrace", "addr": ENTRY, "timeout": 0})

        assert not reply["ok"] and "removed" in reply["error"]
        assert agent.calls == ["cancel_step_trace"]


class TestBreakpoint:
    def test_delete_leaves_releasing_the_thread_frozen_there_to_the_agent(self, daemon, agent):
        agent.frozen_addr = "0x0000000000401040"

        reply = daemon.handle({"cmd": "bp_del", "addr": ENTRY})

        assert reply["ok"] and reply["state"] == "RUNNING"
        assert agent.calls == ["remove_bp"]

    def test_add_reports_why_the_agent_refused(self, daemon, agent):
        agent.bp_refusal = "the byte at this address is already an int3"

        reply = daemon.handle({"cmd": "bp_add", "addr": ENTRY})

        assert not reply["ok"]
        assert reply["error"] == agent.bp_refusal


class TestWatch:
    def test_a_hit_whose_thread_was_released_since_is_not_reported(self, daemon, agent):
        daemon._on_message({"type": "send", "payload": {"type": "bp_hit", "addr": ENTRY}}, None)

        reply = daemon.handle({"cmd": "watch", "timeout": 0})

        assert not reply["ok"] and reply["timeout"]

    def test_reports_the_frozen_thread(self, daemon, agent):
        agent.frozen_addr = ENTRY

        reply = daemon.handle({"cmd": "watch", "timeout": 0})

        assert reply["ok"] and reply["snapshot"]["addr"] == ENTRY


    def test_a_step_failure_reported_outside_a_step_does_not_wake_it(self, daemon, agent):
        daemon._on_message({"type": "send", "payload": {"type": "step_failed", "error": "late"}}, None)

        reply = daemon.handle({"cmd": "watch", "timeout": 0.3})

        assert not reply["ok"] and reply["timeout"]
        assert agent.frozen_checks < 20


class TestResume:
    def test_without_a_frozen_thread_is_an_error(self, daemon):
        reply = daemon.handle({"cmd": "resume"})

        assert not reply["ok"] and reply["error"] == "not frozen"


class TestStep:
    def test_reports_where_the_thread_froze_again(self, daemon, agent):
        agent.frozen_addr = ENTRY

        def freeze_again(step):
            agent.frozen_addr = CALL_SITE
            daemon._on_message({"type": "send", "payload": {"type": "bp_hit", "addr": CALL_SITE}}, None)

        agent.on_unfreeze = freeze_again

        reply = daemon.handle({"cmd": "step", "mode": "into"})

        assert reply["ok"] and reply["snapshot"]["addr"] == CALL_SITE

    def test_that_does_not_end_is_given_up(self, daemon, agent):
        agent.frozen_addr = ENTRY

        reply = daemon.handle({"cmd": "step", "mode": "over", "timeout": 0})

        assert not reply["ok"] and "given up" in reply["error"]
        assert agent.calls == ["unfreeze", "cancel_step"]

    def test_that_freezes_as_it_is_given_up_reports_where(self, daemon, agent):
        agent.frozen_addr = ENTRY

        def freeze_late():
            agent.frozen_addr = CALL_SITE
            daemon._on_message({"type": "send", "payload": {"type": "bp_hit", "addr": CALL_SITE}}, None)

        agent.on_cancel_step = freeze_late

        reply = daemon.handle({"cmd": "step", "mode": "over", "timeout": 0})

        assert reply["ok"] and reply["snapshot"]["addr"] == CALL_SITE

    def test_ended_by_another_threads_breakpoint_says_so(self, daemon, agent):
        agent.frozen_addr = ENTRY

        def other_thread_hits(step):
            agent.frozen_addr, agent.frozen_thread = CALL_SITE, 200
            daemon._on_message({"type": "send", "payload": {"type": "bp_hit", "addr": CALL_SITE}}, None)

        agent.on_unfreeze = other_thread_hits

        reply = daemon.handle({"cmd": "step", "mode": "into"})

        assert reply["ok"] and reply["snapshot"]["threadId"] == 200
        assert "thread 200" in reply["stepInterrupted"] and "thread 100" in reply["stepInterrupted"]

    def test_that_cannot_continue_reports_why_at_once(self, daemon, agent):
        agent.frozen_addr = ENTRY
        cause = "the byte after it is an int3 the program put there"
        agent.on_unfreeze = lambda step: daemon._on_message(
            {"type": "send", "payload": {"type": "step_failed", "error": cause}}, None)

        reply = daemon.handle({"cmd": "step", "mode": "over", "timeout": 30})

        assert not reply["ok"] and reply["error"] == cause
        assert agent.calls == ["unfreeze"]

    def test_unknown_mode_is_an_error(self, daemon, agent):
        agent.frozen_addr = ENTRY

        reply = daemon.handle({"cmd": "step", "mode": "sideways"})

        assert not reply["ok"] and "sideways" in reply["error"]
        assert agent.calls == []

    def test_without_a_frozen_thread_is_an_error(self, daemon):
        reply = daemon.handle({"cmd": "step", "mode": "over"})

        assert not reply["ok"] and reply["error"] == "not frozen"


class TestCommandLine:
    @pytest.fixture
    def sent(self, monkeypatch):
        commands: list[dict] = []

        def send_command(command, timeout=None):
            commands.append(command)
            return {"ok": False, "error": "stop here"}

        monkeypatch.setattr(client, "is_daemon_alive", lambda: True)
        monkeypatch.setattr(client, "send_command", send_command)
        return commands

    def test_trace_is_a_function_hook_by_default(self, sent):
        cli.cmd_trace(cli.build_parser().parse_args(["trace", ENTRY]))

        assert sent[0]["probe"] is False

    def test_trace_probe_flag_reaches_the_daemon(self, sent):
        cli.cmd_trace(cli.build_parser().parse_args(["trace", CALL_SITE, "--probe"]))

        assert sent[0]["probe"] is True

    def test_collect_probe_flag_reaches_the_daemon(self, sent):
        cli.cmd_collect(cli.build_parser().parse_args(["collect", CALL_SITE, "--probe"]))

        assert sent[0]["probe"] is True


class TestDetach:
    def test_a_daemon_whose_state_file_vanished_counts_as_gone(self, monkeypatch, capsys):
        monkeypatch.setattr(client, "is_daemon_alive", lambda: True)
        monkeypatch.setattr(client, "read_state", lambda: None)

        cli.cmd_detach(cli.build_parser().parse_args(["detach"]))

        assert "already gone" in capsys.readouterr().out


class TestFormatSnapshot:
    _SNAPSHOT = {"addr": "0x00401054", "regs": {"_arch": "x86"}, "stack": [], "disasm": []}

    def test_breakpoint_stop_names_the_breakpoint_and_its_hit_count(self):
        text = client.format_snapshot({**self._SNAPSHOT, "bpId": 1, "hitCount": 2})

        assert text.splitlines()[0] == "=== BREAKPOINT HIT === 0x00401054 (bp#1, hit #2)"

    def test_stop_away_from_a_breakpoint_names_only_the_address(self):
        text = client.format_snapshot({**self._SNAPSHOT, "bpId": 0, "hitCount": 0},
                                      header="STEP COMPLETE")

        assert text.splitlines()[0] == "=== STEP COMPLETE === 0x00401054"


class TestFormatTrace:
    def test_probe_record_is_shown_without_caller_or_leave(self):
        record = {"addr": CALL_SITE, "label": "", "interval": 0, "ts": 0,
                  "enter": {"regs": {"ecx": "00000001"},
                            "reads": [{"spec": "[esp]:4:uint32", "value": [1]}]}}

        text = client.format_trace({"samples": [record], "count": 1})

        assert "PROBE  ecx=00000001 [esp]:4:uint32=[1]" in text
        assert "caller" not in text and "LEAVE" not in text

    def test_function_record_shows_caller_enter_and_leave(self):
        record = {"addr": ENTRY, "label": "", "interval": 0, "ts": 0, "caller": "0040100B",
                  "enter": {"regs": {"ecx": "00000001"}, "reads": []},
                  "leave": {"eax": "00000006", "retval": "00000006", "reads": []}}

        text = client.format_trace({"samples": [record], "count": 1})

        assert "caller=0040100B" in text
        assert "ENTER  ecx=00000001" in text
        assert "LEAVE  eax=00000006 retval=00000006" in text


class TestProcessExit:
    """client.wait_for_exit and is_target_running, against real child processes."""

    def test_an_exited_process_whose_handle_is_still_held_is_not_running(self):
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()  # the Popen object keeps its process handle open

        assert not client.is_target_running(child.pid)
        assert client.wait_for_exit(child.pid, 0)

    def test_a_running_process_is_running_until_it_exits(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            assert client.is_target_running(child.pid)
            assert not client.wait_for_exit(child.pid, 0.1)
        finally:
            child.kill()

        assert client.wait_for_exit(child.pid, 10)
        child.wait()

    @pytest.mark.parametrize("stat_line, exited", [
        ("1234 (python3) Z 1 1234 1234 0 -1 4194304 0", True),
        ("1234 (my ) proc) Z 1 1234 1234 0 -1 4194304 0", True),
        ("1234 (my ) proc) X 1 1234 1234 0 -1 4194304 0", True),
        ("1234 (my ) proc) x 1 1234 1234 0 -1 4194304 0", True),
        ("1234 (my ) proc) S 1 1234 1234 0 -1 4194304 0", False),
        ("1234 (my ) proc) R 1 1234 1234 0 -1 4194304 0", False),
    ])
    def test_posix_wait_for_exit_parses_proc_stat_state(
            self, monkeypatch, tmp_path, stat_line, exited):
        stat_dir = tmp_path / "1234"
        stat_dir.mkdir()
        (stat_dir / "stat").write_text(stat_line, encoding="utf-8")

        monkeypatch.setattr(client.sys, "platform", "linux")
        monkeypatch.setattr(client, "_PROC_ROOT", tmp_path)
        monkeypatch.setattr(client.os, "kill", lambda pid, sig: None)

        assert client.wait_for_exit(1234, 0) is exited

    def test_posix_wait_for_exit_treats_vanished_proc_entry_as_exited(self, monkeypatch, tmp_path):
        monkeypatch.setattr(client.sys, "platform", "linux")
        monkeypatch.setattr(client, "_PROC_ROOT", tmp_path)
        monkeypatch.setattr(client.os, "kill", lambda pid, sig: None)

        assert client.wait_for_exit(9999, 0) is True

    def test_posix_wait_for_exit_treats_a_process_reaped_mid_read_as_exited(self, monkeypatch, tmp_path):
        (tmp_path / "1234").mkdir()
        (tmp_path / "1234" / "stat").write_text("1234 (python3) S 1", encoding="utf-8")
        monkeypatch.setattr(client.sys, "platform", "linux")
        monkeypatch.setattr(client, "_PROC_ROOT", tmp_path)

        def reaped(self, *args, **kwargs):
            raise ProcessLookupError(3, "No such process")

        monkeypatch.setattr(client.Path, "read_text", reaped)
        assert client.wait_for_exit(1234, 0) is True

    def test_posix_wait_for_exit_falls_back_to_kill_without_proc(self, monkeypatch, tmp_path):
        monkeypatch.setattr(client.sys, "platform", "darwin")
        monkeypatch.setattr(client, "_PROC_ROOT", tmp_path / "no-proc")

        def missing(pid, sig):
            raise ProcessLookupError

        monkeypatch.setattr(client.os, "kill", missing)
        assert client.wait_for_exit(1234, 0) is True

        monkeypatch.setattr(client.os, "kill", lambda pid, sig: None)
        assert client.wait_for_exit(1234, 0) is False

    def test_posix_wait_for_exit_treats_eperm_as_running_without_proc(self, monkeypatch, tmp_path):
        monkeypatch.setattr(client.sys, "platform", "darwin")
        monkeypatch.setattr(client, "_PROC_ROOT", tmp_path / "no-proc")

        def denied(pid, sig):
            raise PermissionError

        monkeypatch.setattr(client.os, "kill", denied)
        assert client.wait_for_exit(1234, 0) is False

