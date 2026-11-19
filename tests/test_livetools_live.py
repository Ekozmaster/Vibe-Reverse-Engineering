"""livetools hooks on a real process: which kind of hook may sit where.

A function hook (``trace``, ``collect`` and ``steptrace`` without ``--probe``)
traps the function's return through the slot on top of the stack at the hooked
address. That slot holds a return address only at a function entry. At a
``call`` instruction it holds the first stack argument, so a function hook
there hands the callee a corrupted argument and never sees a return.
"""

import json
import sys

import pytest

pytest.importorskip("frida")
pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or sys.maxsize < 2**32,
    reason="needs 64-bit Python on Windows to start the x86 and x64 host programs",
)

from live_target import ARGS, RESULT, LiveTarget, server

_READ_ARGS_AT_CALL = {"x86": "[esp]:12:uint32", "x64": "rcx; rdx; r8"}
_READ_ARGS_AT_ENTRY = {"x86": "[esp+4]:12:uint32", "x64": "rcx; rdx; r8"}


def _arguments(record: dict, arch: str) -> tuple:
    reads = record["enter"]["reads"]
    if arch == "x86":
        return tuple(reads[0]["value"])
    return tuple(int(read["value"], 16) for read in reads)


@pytest.fixture(scope="module", params=["x86", "x64"])
def target(request, tmp_path_factory):
    scratch = tmp_path_factory.mktemp("livetools")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(server, "STATE_FILE", scratch / "state.json")
        patch.setattr(server, "WORKSPACE", scratch)
        live = LiveTarget(request.param)
        try:
            yield live
        finally:
            live.close()


class TestFunctionHook:
    def test_at_an_entry_records_arguments_caller_and_return_value(self, target):
        with target.stays_correct():
            reply = target.run({"cmd": "trace", "addr": target.addr("callee"), "count": 3,
                                "timeout": 5, "read": _READ_ARGS_AT_ENTRY[target.arch]})

        assert reply["ok"] and reply["count"] == 3
        for record in reply["samples"]:
            assert _arguments(record, target.arch) == ARGS
            assert int(record["caller"], 16) == int(target.addr("after_call"), 16)
            assert int(record["leave"]["retval"], 16) == RESULT

    def test_at_a_call_instruction_is_refused(self, target):
        with target.stays_correct():
            reply = target.run({"cmd": "trace", "addr": target.addr("call_site"), "count": 3,
                                "timeout": 2})

        assert not reply["ok"]
        assert "call instruction" in reply["error"]
        assert "--probe" in reply["error"]


class TestProbe:
    def test_at_a_call_instruction_records_the_arguments(self, target):
        with target.stays_correct():
            reply = target.run({"cmd": "trace", "addr": target.addr("call_site"), "count": 3,
                                "timeout": 5, "probe": True,
                                "read": _READ_ARGS_AT_CALL[target.arch]})

        assert reply["ok"] and reply["count"] == 3
        assert [_arguments(record, target.arch) for record in reply["samples"]] == [ARGS] * 3

    def test_records_carry_no_caller_and_no_leave(self, target):
        reply = target.run({"cmd": "trace", "addr": target.addr("call_site"), "count": 1,
                            "timeout": 5, "probe": True})

        (record,) = reply["samples"]
        assert "caller" not in record
        assert "leave" not in record

    @pytest.mark.parametrize("first_argument, recorded", [(ARGS[0], 2), (99, 0)])
    def test_filter_selects_which_hits_are_recorded(self, target, first_argument, recorded):
        operand = {"x86": "[esp]:4:uint32", "x64": "rcx"}[target.arch]

        reply = target.run({"cmd": "trace", "addr": target.addr("call_site"), "count": 2,
                            "timeout": 1, "probe": True,
                            "filter": f"{operand}=={first_argument}"})

        assert reply["ok"] and reply["count"] == recorded


class TestCollect:
    def test_probe_at_a_call_instruction_writes_records(self, target, tmp_path):
        output = tmp_path / "probe.jsonl"

        with target.stays_correct():
            reply = target.run({"cmd": "collect", "addrs": [target.addr("call_site")],
                                "duration": 5, "maxRecords": 3, "probe": True,
                                "read": _READ_ARGS_AT_CALL[target.arch],
                                "output": str(output)})

        assert reply["ok"] and reply["totalRecords"] >= 3
        records = [json.loads(line) for line in output.read_text().splitlines()]
        assert all(_arguments(record, target.arch) == ARGS for record in records)

    def test_function_hook_at_a_call_instruction_is_refused(self, target, tmp_path):
        output = tmp_path / "refused.jsonl"

        with target.stays_correct():
            reply = target.run({"cmd": "collect",
                                "addrs": [target.addr("callee"), target.addr("call_site")],
                                "duration": 2, "output": str(output)})

        assert not reply["ok"]
        assert target.addr("call_site") in reply["error"]
        assert not output.exists()

    def test_fence_at_a_call_instruction_counts_intervals(self, target, tmp_path):
        with target.stays_correct():
            reply = target.run({"cmd": "collect", "addrs": [target.addr("callee")],
                                "duration": 5, "maxRecords": 3,
                                "fence": target.addr("call_site"),
                                "output": str(tmp_path / "fenced.jsonl")})

        assert reply["ok"] and reply["fenceCount"] >= 3


class TestStepTrace:
    def test_at_a_call_instruction_is_refused(self, target):
        with target.stays_correct():
            reply = target.run({"cmd": "steptrace", "addr": target.addr("call_site"),
                                "timeout": 2})

        assert not reply["ok"]
        assert "call instruction" in reply["error"]

