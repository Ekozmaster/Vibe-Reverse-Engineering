"""livetools hooks on a real process: which kind of hook may sit where.

A function hook (``trace``, ``collect`` and ``steptrace`` without ``--probe``)
traps the function's return through the slot on top of the stack at the hooked
address. That slot holds a return address only at a function entry. At a
``call`` instruction it holds the first stack argument, so a function hook
there hands the callee a corrupted argument and never sees a return.
"""

import json
import struct
import time

import pytest

pytest.importorskip("frida")

from live_target import ARGS, RESULT, hex_addr

_READ_ARGS_AT_CALL = {"x86": "[esp]:12:uint32", "x64": "rcx; rdx; r8"}
_READ_ARGS_AT_ENTRY = {"x86": "[esp+4]:12:uint32", "x64": "rcx; rdx; r8"}


# Bytes of whole instructions that the 5-byte jump of a hook replaces.
_JUMP_COVERS = {"call_site": {"x86": 5, "x64": 5}, "callee": {"x86": 8, "x64": 6}}

# 00 xor eax, eax   02 inc eax   04 cmp eax, 3   07 jne 02   09 ret
_LOOP_HEAD_INSIDE_THE_JUMP = bytes.fromhex("31C0 FFC0 83F803 75F9 C3")
# 00 nop   01 nop   02 ret
_RETURNS_AFTER_TWO_BYTES = bytes.fromhex("90 90 C3")
# 00 jmp 08   08 xor eax, eax   0A inc eax   0C cmp eax, 3   0F ret
_JUMP_THEN_ITS_TARGET = bytes.fromhex("EB06 909090909090 31C0 FFC0 83F803 C3")


# 00 xor eax, eax   02 nop   07 inc eax   09 nop   10 cmp eax, 3   13 jne 07   15 ret
_LOOP_HEAD_INSIDE_THE_LONG_JUMP = bytes.fromhex("31C0 0F1F440000 FFC0 0F1F8000000000 83F803 75F2 C3")
# 00 xor eax, eax   02 nop   07 inc eax   09 cmp eax, 3   0C nop   0E nop   10 ret
_STRAIGHT_PAST_THE_LONG_JUMP = bytes.fromhex("31C0 0F1F440000 FFC0 83F803 6690 6690 C3")
# 00 xor eax, eax   02 nop   07 inc eax   09 nop   0E add [rax], al   10 ret
# The long jump ends in the top bytes of an address, which are zero like the add.
_ZEROES_WHERE_THE_LONG_JUMP_ENDS = bytes.fromhex("31C0 0F1F440000 FFC0 0F1F440000 0000 C3")
_LONG_JUMP_BYTES = 16

# 00 stc   01 jb 04   03 hlt   04 nop   09 nop   10 return from a thread's start routine
_BRANCH_OVER_A_HALT = {arch: bytes.fromhex("F9 7201 F4 0F1F440000 0F1F8000000000") + returns
                       for arch, returns in (("x86", bytes.fromhex("C20400")), ("x64", b"\xC3"))}


_JUMP_FORMS = ["target in the instruction", "target in a pointer"]


def _write_jump_to(target, destination: int, form: str) -> int:
    """Write a jump to *destination* on a page of its own and return the jump's address.

    The pointer of a jump through one follows the instruction: x86 code names
    it by its address, x64 code by its distance from the instruction.
    """
    base = int(target.helper.allocate(0x1000), 16)
    if form == "target in the instruction":
        if target.arch == "x64":
            pytest.skip("a page of its own may be out of a 32-bit jump's reach")
        code = b"\xE9" + struct.pack("<i", destination - (base + 5))
    elif target.arch == "x86":
        code = b"\xFF\x25" + struct.pack("<I", base + 6) + struct.pack("<I", destination)
    else:
        code = bytes.fromhex("FF2500000000") + struct.pack("<Q", destination)
    target.run({"cmd": "mem_write", "addr": hex_addr(base), "hex": code.hex()})
    return base


def _write_out_of_reach(target, code: bytes) -> int:
    """Write *code* where a hook's jump must be the long form; skips where that cannot be arranged."""
    if target.arch == "x86":
        pytest.skip("every address is within reach of a 32-bit jump")
    address = target.write_code_out_of_reach(code)
    if address is None:
        pytest.skip("the address space around a page could not be reserved")
    return address


def _wait_until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not met in time"
        time.sleep(0.01)


def _wait_for_jump(target, address: int, code: bytes) -> None:
    """Block until a hook's jump stands at *address*, where the program has *code*."""
    def first_byte() -> bytes:
        return bytes.fromhex(target.run({"cmd": "mem_read", "addr": hex_addr(address), "size": 1})["hex"])

    _wait_until(lambda: first_byte() != code[:1])


def _probe(target, address: int) -> dict:
    return target.run({"cmd": "trace", "addr": hex_addr(address), "count": 1, "timeout": 0.2,
                       "probe": True})


class _InstallReturnsOnceTheHookIsGone:
    """The agent's exports, with ``install_trace`` returning only once its hook has removed itself."""

    def __init__(self, api):
        self._api = api

    def __getattr__(self, name):
        return getattr(self._api, name)

    def install_trace(self, addr, config):
        result = self._api.install_trace(addr, config)
        deadline = time.monotonic() + 5
        while not self._api.flush_traces(result["traceId"])["done"]:
            assert time.monotonic() < deadline, "the trace did not fill up"
            time.sleep(0.01)
        return result


def _arguments(record: dict, arch: str) -> tuple:
    reads = record["enter"]["reads"]
    if arch == "x86":
        return tuple(reads[0]["value"])
    return tuple(int(read["value"], 16) for read in reads)


class TestFunctionHook:
    def test_at_an_entry_records_arguments_caller_and_return_value(self, target):
        with target.stays_correct():
            reply = target.run({"cmd": "trace", "addr": target.addr("callee"), "count": 3,
                                "timeout": 5, "read": _READ_ARGS_AT_ENTRY[target.arch]})

        assert reply["ok"] and reply["count"] == 3, reply
        for record in reply["samples"]:
            assert _arguments(record, target.arch) == ARGS
            assert int(record["caller"], 16) == int(target.addr("after_call"), 16)
            assert int(record["leave"]["retval"], 16) == RESULT

    def test_reports_the_bytes_its_jump_replaced(self, target):
        reply = target.run({"cmd": "trace", "addr": target.addr("callee"), "count": 1, "timeout": 5})

        diag = reply["hookDiag"]
        assert diag["bytesTaken"] == _JUMP_COVERS["callee"][target.arch]
        assert diag["followedTo"] is None and "hookVerified" not in diag

    def test_reports_the_bytes_its_jump_replaced_once_the_hook_has_removed_itself(
            self, target, monkeypatch):
        monkeypatch.setattr(target.daemon, "api", _InstallReturnsOnceTheHookIsGone(target.daemon.api))

        reply = target.run({"cmd": "trace", "addr": target.addr("callee"), "count": 1, "timeout": 5})

        assert reply["ok"] and reply["count"] == 1, reply
        assert reply["hookDiag"]["bytesTaken"] == _JUMP_COVERS["callee"][target.arch]

    def test_owns_the_bytes_its_jump_replaced_and_no_more_once_the_jump_is_written(self, target):
        callee = int(target.addr("callee"), 16)
        taken = _JUMP_COVERS["callee"][target.arch]
        installed = target.daemon.api.install_trace(target.addr("callee"), {"count": 0})
        try:
            _wait_for_jump(target, callee, target.loop.built_bytes("callee", 1))
            inside = target.run({"cmd": "bp_add", "addr": hex_addr(callee + taken - 1)})
            past = target.run({"cmd": "bp_add", "addr": hex_addr(callee + taken)})
            target.run({"cmd": "bp_del", "addr": hex_addr(callee + taken)})
            with target.stays_correct():
                pass
        finally:
            target.daemon.api.remove_trace(installed["traceId"])

        assert not inside["ok"] and f"has replaced {taken} bytes" in inside["error"], inside
        assert past["ok"], past

    def test_on_a_page_that_can_no_longer_be_read_comes_out_with_its_bytes_uncounted(self, target):
        code = target.write_code(_ZEROES_WHERE_THE_LONG_JUMP_ENDS)
        installed = target.daemon.api.install_trace(hex_addr(code), {"count": 0})
        target.helper.make_inaccessible(hex_addr(code), 1)

        removed = target.daemon.api.remove_trace(installed["traceId"])

        assert removed["ok"] and removed["bytesTaken"] is None, removed

    @pytest.mark.parametrize("form", _JUMP_FORMS)
    def test_asked_for_at_a_jump_sits_where_the_jump_leads(self, target, form):
        callee = int(target.addr("callee"), 16)
        jump = _write_jump_to(target, callee, form)

        with target.stays_correct():
            reply = target.run({"cmd": "trace", "addr": hex_addr(jump), "count": 2, "timeout": 5})

        assert reply["ok"] and reply["count"] == 2, reply
        diag = reply["hookDiag"]
        assert int(diag["followedTo"], 16) == callee
        assert diag["bytesTaken"] == _JUMP_COVERS["callee"][target.arch]

    @pytest.mark.parametrize("form", _JUMP_FORMS)
    def test_asked_for_at_a_jump_owns_the_bytes_where_the_jump_leads(self, target, form):
        jump = _write_jump_to(target, int(target.addr("callee"), 16), form)
        installed = target.daemon.api.install_trace(hex_addr(jump), {"count": 0})
        try:
            reply = target.run({"cmd": "bp_add", "addr": target.addr("callee")})
        finally:
            target.daemon.api.remove_trace(installed["traceId"])

        assert not reply["ok"] and "hook" in reply["error"], reply

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

        assert reply["ok"], reply
        (record,) = reply["samples"]
        assert "caller" not in record
        assert "leave" not in record

    def test_reports_the_bytes_its_jump_replaced(self, target):
        reply = target.run({"cmd": "trace", "addr": target.addr("call_site"), "count": 1,
                            "timeout": 5, "probe": True})

        diag = reply["hookDiag"]
        assert diag["bytesTaken"] == _JUMP_COVERS["call_site"][target.arch]

    def test_whose_jump_would_cover_a_branch_target_is_refused(self, target):
        code = target.write_code(_LOOP_HEAD_INSIDE_THE_JUMP)

        reply = _probe(target, code)

        assert not reply["ok"]
        assert hex_addr(code + 2)[2:] in reply["error"] and "bp add" in reply["error"], reply

    def test_whose_long_jump_would_cover_a_branch_target_is_refused(self, target):
        code = _write_out_of_reach(target, _LOOP_HEAD_INSIDE_THE_LONG_JUMP)

        reply = _probe(target, code)

        assert not reply["ok"]
        assert hex_addr(code + 7)[2:] in reply["error"] and "bp add" in reply["error"], reply

    def test_out_of_reach_of_a_short_jump_owns_the_bytes_of_its_long_one(self, target):
        code = _write_out_of_reach(target, _STRAIGHT_PAST_THE_LONG_JUMP)
        installed = target.daemon.api.install_trace(hex_addr(code), {"count": 0, "probe": True})
        try:
            _wait_for_jump(target, code, _STRAIGHT_PAST_THE_LONG_JUMP)
            reply = target.run({"cmd": "bp_add", "addr": hex_addr(code + _LONG_JUMP_BYTES - 2)})
        finally:
            removed = target.daemon.api.remove_trace(installed["traceId"])

        assert removed["bytesTaken"] == _LONG_JUMP_BYTES
        assert not reply["ok"] and f"has replaced {_LONG_JUMP_BYTES} bytes" in reply["error"], reply

    def test_long_jump_owns_the_bytes_it_wrote_that_equal_the_ones_before(self, target):
        code = _write_out_of_reach(target, _ZEROES_WHERE_THE_LONG_JUMP_ENDS)
        installed = target.daemon.api.install_trace(hex_addr(code), {"count": 0, "probe": True})
        try:
            _wait_for_jump(target, code, _ZEROES_WHERE_THE_LONG_JUMP_ENDS)
            reply = target.run({"cmd": "bp_add", "addr": hex_addr(code + _LONG_JUMP_BYTES - 2)})
        finally:
            removed = target.daemon.api.remove_trace(installed["traceId"])

        assert removed["bytesTaken"] == _LONG_JUMP_BYTES
        assert not reply["ok"] and "hook" in reply["error"], reply

    @pytest.mark.parametrize("jump", ["short", "long"])
    def test_over_a_branch_among_the_instructions_its_jump_replaces_runs_them_as_before(
            self, target, jump):
        if jump == "short":
            code = target.write_code(_BRANCH_OVER_A_HALT[target.arch])
        else:
            code = _write_out_of_reach(target, _BRANCH_OVER_A_HALT[target.arch])
        installed = target.daemon.api.install_trace(hex_addr(code), {"count": 1, "probe": True})
        try:
            _wait_for_jump(target, code, _BRANCH_OVER_A_HALT[target.arch])
            target.helper.start_thread(hex_addr(code))
            _wait_until(lambda: target.daemon.api.flush_traces(installed["traceId"])["done"])
            with target.stays_correct():
                pass
        finally:
            target.daemon.api.remove_trace(installed["traceId"])

    def test_with_no_room_for_its_jump_before_a_return_is_refused(self, target):
        code = target.write_code(_RETURNS_AFTER_TWO_BYTES)

        reply = _probe(target, code)

        assert not reply["ok"]
        assert "3 bytes" in reply["error"] and "bp add" in reply["error"], reply

    def test_on_a_jump_is_refused_and_its_target_left_alone(self, target):
        code = target.write_code(_JUMP_THEN_ITS_TARGET)

        reply = _probe(target, code)

        assert not reply["ok"] and "bp add" in reply["error"], reply
        after = target.run({"cmd": "mem_read", "addr": hex_addr(code), "size": 16})
        assert bytes.fromhex(after["hex"]) == _JUMP_THEN_ITS_TARGET

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

    def test_fence_on_a_jump_is_refused(self, target, tmp_path):
        code = target.write_code(_JUMP_THEN_ITS_TARGET)

        reply = target.run({"cmd": "collect", "addrs": [target.addr("callee")], "duration": 0.5,
                            "fence": hex_addr(code), "output": str(tmp_path / "out.jsonl")})

        assert not reply["ok"] and "bp add" in reply["error"], reply

    def test_fence_at_a_call_instruction_counts_intervals(self, target, tmp_path):
        with target.stays_correct():
            reply = target.run({"cmd": "collect", "addrs": [target.addr("callee")],
                                "duration": 5, "maxRecords": 3,
                                "fence": target.addr("call_site"),
                                "output": str(tmp_path / "fenced.jsonl")})

        assert reply["ok"] and reply["fenceCount"] >= 3


class TestStepTrace:
    def test_records_the_function_through_its_return(self, target):
        with target.stays_correct():
            reply = target.run({"cmd": "steptrace", "addr": target.addr("callee"), "timeout": 5,
                                "detail": "full"})

        assert reply["ok"], reply
        trace = reply["trace"]
        assert trace["insnCount"] > 0
        assert "ret" in [call["type"] for call in trace["calls"]]

    def test_at_a_call_instruction_is_refused(self, target):
        with target.stays_correct():
            reply = target.run({"cmd": "steptrace", "addr": target.addr("call_site"),
                                "timeout": 2})

        assert not reply["ok"]
        assert "call instruction" in reply["error"]

