"""What the livetools daemon asks of its agent, and how the CLI talks to the daemon.

The Frida agent is replaced by a stand-in that records what it is asked to
install, so these run on any platform. The hooks themselves are exercised
against a real process in test_livetools_live.py.
"""

import socket
import subprocess
import sys
import threading
import time
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
        shutdown_rounds: What the coming calls of ``shutdown`` return, in order;
            once they are used up, nothing failed and no thread owes a step.
        trace_failures: Address -> the error ``install_trace`` raises there.
        removal_failure: The error ``remove_trace`` raises, or None.
    """

    def __init__(self):
        self.traces: list[tuple[str, dict]] = []
        self.fences: list[str] = []
        self.removed_traces: list[int] = []
        self.fences_removed = 0
        self.step_traces: list[str] = []
        self.frozen_addr: str | None = None
        self.frozen_thread = 100
        self.calls: list[str] = []
        self.frozen_checks = 0
        self.on_unfreeze = lambda step: None
        self.on_cancel_step = lambda: None
        self.bp_refusal: str | None = None
        self.cannot_freeze: str | None = None
        self.step_trace_result: dict | None = {"addr": ENTRY, "insnCount": 0, "trace": []}
        self.shutdown_rounds: list[dict] = []
        self.trace_failures: dict[str, str] = {}
        self.removal_failure: str | None = None

    def shutdown(self):
        self.calls.append("shutdown")
        if self.shutdown_rounds:
            return self.shutdown_rounds.pop(0)
        return {"failures": [], "owedSteps": []}

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

    def freeze_refusal(self):
        return self.cannot_freeze

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
        if addr in self.trace_failures:
            raise RuntimeError(self.trace_failures[addr])
        self.traces.append((addr, config))
        return {"ok": True, "traceId": len(self.traces)}

    def flush_traces(self, trace_id):
        return {"ok": True, "done": True, "collected": 0}

    def remove_trace(self, trace_id):
        self.removed_traces.append(trace_id)
        if self.removal_failure:
            raise RuntimeError(self.removal_failure)
        return {"ok": True}

    def install_fence(self, addr):
        self.fences.append(addr)
        return {"ok": True}

    def remove_fence(self):
        self.fences_removed += 1
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


class FakeScript:
    """Stands in for the loaded agent script: its exports are *agent*, which records the unload."""

    def __init__(self, agent: FakeAgent):
        self.exports_sync = agent
        self._agent = agent

    def unload(self):
        self._agent.calls.append("unload")


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

    def test_hook_that_cannot_go_in_is_reported_with_what_could_not_be_removed(
            self, daemon, agent, tmp_path):
        agent.trace_failures[CALL_SITE] = "the agent lost the target"
        agent.removal_failure = "no such trace"

        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY, CALL_SITE], "duration": 0,
                               "probe": True, "output": str(tmp_path / "out.jsonl")})

        assert not reply["ok"]
        assert "the agent lost the target" in reply["error"] and "no such trace" in reply["error"]
        assert agent.removed_traces == [1]
        assert (daemon._trace_batches, daemon._trace_done, daemon._trace_events) == ({}, {}, {})

    def test_fence_may_sit_on_a_call_instruction(self, daemon, agent, tmp_path):
        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY], "duration": 0,
                               "fence": CALL_SITE, "output": str(tmp_path / "out.jsonl")})

        assert reply["ok"]
        assert agent.fences == [CALL_SITE]

    def test_an_output_file_that_cannot_be_opened_hooks_nothing(self, daemon, agent, tmp_path):
        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY], "duration": 0, "fence": CALL_SITE,
                               "output": str(tmp_path / "no_such_folder" / "out.jsonl")})

        assert not reply["ok"]
        assert agent.traces == [] and agent.fences == []

    def test_hooks_are_removed_when_collecting_fails(self, daemon, agent, tmp_path):
        agent.flush_traces = lambda trace_id: 1 / 0

        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY], "duration": 5, "fence": CALL_SITE,
                               "output": str(tmp_path / "out.jsonl")})

        assert not reply["ok"]
        assert agent.removed_traces == [1] and agent.fences_removed == 1

    def test_hooks_are_removed_when_installing_one_fails(self, daemon, agent, tmp_path):
        install = agent.install_trace

        def install_two_then_fail(addr, config):
            if len(agent.traces) == 2:
                raise RuntimeError("the agent went away")
            return install(addr, config)

        agent.install_trace = install_two_then_fail

        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY, ENTRY, ENTRY], "duration": 5,
                               "fence": CALL_SITE, "output": str(tmp_path / "out.jsonl")})

        assert not reply["ok"]
        assert sorted(agent.removed_traces) == [1, 2] and agent.fences_removed == 1

    def test_a_hook_that_cannot_be_removed_does_not_keep_the_others_installed(
            self, daemon, agent, tmp_path):
        remove = agent.remove_trace

        def remove_all_but_the_second(trace_id):
            if trace_id == 2:
                raise RuntimeError("cannot unhook")
            return remove(trace_id)

        agent.remove_trace = remove_all_but_the_second

        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY, ENTRY, ENTRY], "duration": 0,
                               "fence": CALL_SITE, "output": str(tmp_path / "out.jsonl")})

        assert not reply["ok"] and "cannot unhook" in reply["error"]
        assert sorted(agent.removed_traces) == [1, 3] and agent.fences_removed == 1

    def test_a_fence_that_cannot_be_installed_leaves_nothing_to_remove(self, daemon, agent, tmp_path):
        agent.install_fence = lambda addr: 1 / 0

        reply = daemon.handle({"cmd": "collect", "addrs": [ENTRY], "duration": 5, "fence": CALL_SITE,
                               "output": str(tmp_path / "out.jsonl")})

        assert not reply["ok"]
        assert agent.traces == [] and agent.fences_removed == 0


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

    def test_where_no_thread_can_freeze_reports_why(self, daemon, agent):
        agent.cannot_freeze = "breakpoints and stepping need a Windows process"

        reply = daemon.handle({"cmd": "step", "mode": "over"})

        assert not reply["ok"] and reply["error"] == agent.cannot_freeze


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
    def test_a_daemon_whose_state_file_vanished_counts_as_gone(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(client, "STATE_FILE", tmp_path / "state.json")
        monkeypatch.setattr(client, "is_daemon_alive", lambda: True)
        monkeypatch.setattr(client, "read_state", lambda: None)

        cli.cmd_detach(cli.build_parser().parse_args(["detach"]))

        assert "already gone" in capsys.readouterr().out

    def test_reply_names_the_thread_whose_single_step_the_daemon_waits_for(self, daemon, agent):
        agent.shutdown_rounds = [{"failures": ["breakpoint at 0x401000: no access"],
                                  "owedSteps": [7]}]

        reply = daemon.handle({"cmd": "detach"})

        assert reply["ok"] and not daemon._running
        assert "thread 7" in reply["waitingOn"]
        assert reply["shutdown"] == ["breakpoint at 0x401000: no access"]

    def test_reply_of_a_detach_with_nothing_to_wait_for_names_no_thread(self, daemon):
        reply = daemon.handle({"cmd": "detach"})

        assert reply["ok"] and not daemon._running
        assert "waitingOn" not in reply and reply["shutdown"] == []

    def test_daemon_stops_when_the_agent_cannot_be_asked_to_shut_down(self, daemon, agent):
        agent.shutdown = lambda: (_ for _ in ()).throw(RuntimeError("the script is gone"))

        reply = daemon.handle({"cmd": "detach"})

        assert not reply["ok"] and "the script is gone" in reply["error"]
        assert not daemon._running

    def test_agent_stays_loaded_while_a_thread_owes_its_single_step(self, daemon, agent, capsys):
        agent.shutdown_rounds = [{"failures": [], "owedSteps": [7]},
                                 {"failures": [], "owedSteps": [7]}]
        script = FakeScript(agent)

        daemon._unload(script)

        assert agent.calls == ["shutdown", "shutdown", "shutdown", "unload"]
        waits = [line for line in capsys.readouterr().err.splitlines() if "waiting" in line]
        assert len(waits) == 1 and "thread 7" in waits[0]

    def test_cli_says_what_the_daemon_is_waiting_for(self, monkeypatch, capsys):
        waiting = "detach is waiting for thread 7"
        monkeypatch.setattr(client, "is_daemon_alive", lambda: True)
        monkeypatch.setattr(client, "read_state", lambda: {"pid": 4321})
        monkeypatch.setattr(client, "send_command", lambda command: {
            "ok": True, "state": "RUNNING", "shutdown": ["vishook: no access"],
            "waitingOn": waiting})
        monkeypatch.setattr(client, "wait_for_exit", lambda pid, timeout: False)

        with pytest.raises(SystemExit):
            cli.cmd_detach(cli.build_parser().parse_args(["detach"]))

        printed = capsys.readouterr()
        assert waiting in printed.out and "vishook: no access" in printed.out
        assert "thread 7" in printed.err and "4321" in printed.err


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((server.HOST, 0))
        return probe.getsockname()[1]


@pytest.fixture(autouse=True)
def _away_from_the_users_daemon(monkeypatch, tmp_path):
    """Give every test a port and a state file of its own.

    A daemon the user is running listens on the default port and is named by
    the default state file, and a test must not be able to reach either.
    """
    port = _free_port()
    state_file = tmp_path / "state.json"
    for module in (server, client):
        monkeypatch.setattr(module, "PORT", port)
        monkeypatch.setattr(module, "STATE_FILE", state_file)
    return state_file


class TestStartup:
    def test_serves_commands_until_detached_and_then_removes_its_state_file(
            self, monkeypatch, _away_from_the_users_daemon, agent):
        state_file = _away_from_the_users_daemon
        monkeypatch.setattr(server.Daemon, "attach", lambda self: setattr(self, "api", agent))
        daemon = server.Daemon("target.exe")
        serving = threading.Thread(target=daemon.run, daemon=True)
        serving.start()
        try:
            deadline = time.monotonic() + 5
            while client.read_state() is None:
                assert time.monotonic() < deadline, "the daemon wrote no state file"
                time.sleep(0.02)
            status = client.send_command({"cmd": "status"})
            client.send_command({"cmd": "detach"})
            serving.join(5)
            stopped_by_detach = not serving.is_alive()
        finally:
            daemon._running = False
            serving.join(5)

        assert status["ok"] and status["target"] == "target.exe"
        assert stopped_by_detach and not state_file.exists()

    def test_a_second_daemon_leaves_the_live_ones_target_and_state_file_alone(
            self, monkeypatch, tmp_path, capsys):
        live = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        live.bind((server.HOST, 0))
        live.listen()
        state_file = tmp_path / "state.json"
        state_file.write_text('{"pid": 1, "target": "first.exe"}')
        attached = []
        monkeypatch.setattr(server, "PORT", live.getsockname()[1])
        monkeypatch.setattr(server, "STATE_FILE", state_file)
        monkeypatch.setattr(server.Daemon, "attach", lambda self: attached.append(self.target))
        monkeypatch.setattr(server.signal, "signal", lambda signum, handler: None)
        monkeypatch.setattr(sys, "argv", ["livetools.server", "second.exe"])

        try:
            server.main()
        finally:
            live.close()

        assert "fatal" in capsys.readouterr().err
        assert attached == []
        assert state_file.read_text() == '{"pid": 1, "target": "first.exe"}'


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

    def test_shows_how_many_bytes_the_hook_replaced(self):
        text = client.format_trace({"samples": [], "count": 0,
                                    "hookDiag": {"addr": CALL_SITE, "bytesTaken": 5}})

        assert f"Hook at {CALL_SITE} replaced 5 bytes" in text

    def test_says_when_the_hook_went_where_a_jump_leads(self):
        text = client.format_trace({"samples": [], "count": 0, "hookDiag": {
            "addr": CALL_SITE, "bytesTaken": 6, "followedTo": ENTRY}})

        assert f"Hook at {CALL_SITE} sits at {ENTRY}" in text and "replaced 6 bytes there" in text


class TestFormatCollect:
    def test_shows_how_many_bytes_each_hook_replaced(self):
        text = client.format_collect({"totalRecords": 3, "hookDiags": [
            {"addr": ENTRY, "ok": True, "bytesTaken": 6},
            {"addr": CALL_SITE, "ok": False, "error": "refused"}]})

        assert f"Hook at {ENTRY} replaced 6 bytes" in text
        assert f"[HOOK FAILED] {CALL_SITE}: refused" in text


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

