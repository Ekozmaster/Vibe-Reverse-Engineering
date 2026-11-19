"""What the livetools daemon asks of its agent, and how the CLI talks to the daemon.

The Frida agent is replaced by a stand-in that records what it is asked to
install, so these run on any platform. The hooks themselves are exercised
against a real process in test_livetools_live.py.
"""

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
    """Stands in for the agent's RPC surface and records the hooks requested."""

    def __init__(self):
        self.traces: list[tuple[str, dict]] = []
        self.fences: list[str] = []
        self.step_traces: list[str] = []

    def list_bps(self):
        return []

    def is_frozen(self):
        return False

    def disasm_at(self, addr, count):
        mnemonic, _, operands = _CODE[addr].partition(" ")
        return [{"addr": addr, "mnemonic": mnemonic, "opStr": operands,
                 "size": 5, "str": _CODE[addr]}]

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
        return {"addr": ENTRY, "insnCount": 0, "trace": []}


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
