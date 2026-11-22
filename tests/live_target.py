"""A throwaway process running known machine code, for tests that need real Frida.

``LiveTarget`` starts an idle system program, attaches the livetools daemon to
it and runs a small hand-assembled loop on a new thread, so a test knows every
instruction address and every argument value:

    loop:        load the arguments 1, 2, 3 (pushed on x86, in registers on x64)
    call_site:   call callee
    after_call:  count the iteration as good if callee returned 6, else as bad
    spare:       instructions that do nothing, enough of them for the jump of a
                 hook: Frida moves the instructions its jump replaces into
                 memory it frees with the hook, and a thread that is inside a
                 call moved there returns into that memory
                 Sleep(10) and repeat
    callee:      return a + b + c, through a ``bnd ret`` (a prefixed return)

A hook that disturbs an argument, a return address or the stack shows up in
the ``bad`` counter, or stops the ``good`` counter from advancing.

The same code page holds two more routines a test may use:

    repeater:    fill ``rep_count`` bytes at ``rep_buffer`` with ``rep stosb``
                 (``REP_COUNT`` bytes of the data page unless a test sets a
                 longer run), count it in ``reps``, Sleep(10) and repeat; it
                 runs once a test starts it
    dormant:     nops and a return that nothing calls, a site for code
                 patches that must never execute

The code page is read-execute like a real module's, and it belongs to the
process, not to a Frida script, so it outlives a detach.
"""

from __future__ import annotations

import contextlib
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from livetools import server

ARGS = (1, 2, 3)
RESULT = sum(ARGS)

_CREATE_NO_WINDOW = 0x08000000
_PAGE = 0x1000

_HOST_DIR = {"x86": "SysWOW64", "x64": "System32"}

# Runs beside the livetools agent. It does what the agent has no command for,
# and plays the part of the program's own exception handling.
_HELPER_JS = r"""
var kernel32 = Process.getModuleByName('kernel32.dll');
var virtualAlloc = new NativeFunction(kernel32.getExportByName('VirtualAlloc'),
    'pointer', ['pointer', 'size_t', 'uint32', 'uint32']);
var virtualFree = new NativeFunction(kernel32.getExportByName('VirtualFree'),
    'int', ['pointer', 'size_t', 'uint32']);
var createThread = new NativeFunction(kernel32.getExportByName('CreateThread'),
    'pointer', ['pointer', 'size_t', 'pointer', 'pointer', 'uint32', 'pointer']);

var MEM_RESERVE = 0x2000;
var MEM_RELEASE = 0x8000;
var PAGE_NOACCESS = 1;
var ALLOCATION_GRANULARITY = 0x10000;
// More than a 32-bit jump spans.
var OUT_OF_REACH = 0x80000000 + ALLOCATION_GRANULARITY;

var EFLAGS_OFFSET = Process.pointerSize === 8 ? 0x44 : 0xC0;
var TRAP_FLAG = 0x100;
var ownTraps = {};
var awaitingOwnStep = {};
var ownExceptions = { breakpoint: 0, singleStep: 0 };

Process.setExceptionHandler(function (details) {
    var threadId = Process.getCurrentThreadId();
    if (details.type === 'breakpoint' && ownTraps[details.context.pc.toString()]) {
        ownExceptions.breakpoint++;
        details.context.pc = details.context.pc.add(1);
        var flags = details.nativeContext.add(EFLAGS_OFFSET);
        flags.writeU32(flags.readU32() | TRAP_FLAG);
        awaitingOwnStep[threadId] = true;
        return true;
    }
    if (details.type === 'single-step' && awaitingOwnStep[threadId]) {
        delete awaitingOwnStep[threadId];
        ownExceptions.singleStep++;
        return true;
    }
    return false;
});

rpc.exports = {
    exportAddress: function (moduleName, exportName) {
        return Process.getModuleByName(moduleName).getExportByName(exportName).toString();
    },
    allocate: function (size) {
        return virtualAlloc(NULL, size, 0x3000, 0x40).toString();
    },
    allocateOutOfReach: function () {
        var span = virtualAlloc(NULL, 2 * OUT_OF_REACH + ALLOCATION_GRANULARITY, MEM_RESERVE, PAGE_NOACCESS);
        if (span.isNull()) return null;
        virtualFree(span, 0, MEM_RELEASE);
        var page = span.add(OUT_OF_REACH);
        var below = virtualAlloc(span, OUT_OF_REACH, MEM_RESERVE, PAGE_NOACCESS);
        var above = virtualAlloc(page.add(ALLOCATION_GRANULARITY), OUT_OF_REACH, MEM_RESERVE, PAGE_NOACCESS);
        if (below.isNull() || above.isNull()) return null;
        var allocated = virtualAlloc(page, Process.pageSize, 0x3000, 0x40);
        return allocated.isNull() ? null : allocated.toString();
    },
    release: function (address) {
        return virtualFree(ptr(address), 0, 0x8000) !== 0;
    },
    makeReadExecute: function (address, size) {
        return Memory.protect(ptr(address), size, 'r-x');
    },
    // Writes where the agent's `mem write` cannot: it finds no range in memory Frida cloaks.
    write: function (address, hex) {
        var bytes = [];
        for (var i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
        ptr(address).writeByteArray(bytes);
    },
    makeInaccessible: function (address, size) {
        return Memory.protect(ptr(address), size, '---');
    },
    protection: function (address) {
        return Process.getRangeByAddress(ptr(address)).protection;
    },
    startThread: function (entry, parameter) {
        var argument = parameter ? ptr(parameter) : NULL;
        return createThread(NULL, 0, ptr(entry), argument, 0, NULL).toString();
    },
    // Runs the code at `address` on the thread that serves this call, and
    // returns whether that thread is one Frida cloaks.
    callOnFridasThread: function (address) {
        new NativeFunction(ptr(address), 'void', [], { exceptions: 'propagate' })();
        return Cloak.hasCurrentThread();
    },
    plantOwnTrap: function (address) {
        ownTraps[ptr(address).toString()] = true;
        Memory.patchCode(ptr(address), 1, function (code) { code.writeU8(0xCC); });
    },
    ownExceptions: function () {
        return ownExceptions;
    }
};
"""

REP_COUNT = 64

_DATA_LABELS = {"good": 0x1000, "bad": 0x1004, "stop": 0x1008, "reps": 0x100C,
                "sleep_ptr": 0x1010, "rep_buffer": 0x1018, "rep_count": 0x1020,
                "buffer": 0x1100}
_REPEATER = 0x80
_DORMANT = 0xC0
_DORMANT_CODE = b"\x90" * 16 + b"\xC3"


def _x86_code(base: int) -> tuple[bytes, dict[str, int]]:
    labels = {"loop": 0x00, "second": 0x02, "call_site": 0x06, "after_call": 0x0B,
              "spare": 0x1E, "callee": 0x40, "callee_second": 0x44,
              "repeater": _REPEATER, "rep": 0x8E, "after_rep": 0x90, "dormant": _DORMANT,
              **_DATA_LABELS}
    at = {name: base + offset for name, offset in labels.items()}
    code = bytes.fromhex("6A03 6A02 6A01")                              # 00 push 3; push 2; push 1
    code += b"\xE8" + struct.pack("<i", labels["callee"] - 0x0B)        # 06 call callee
    code += bytes.fromhex("83F806")                                     # 0B cmp eax, 6
    code += bytes.fromhex("7408")                                       # 0E je 0x18
    code += b"\xFF\x05" + struct.pack("<I", at["bad"])                  # 10 inc dword [bad]
    code += bytes.fromhex("EB06")                                       # 16 jmp 0x1E
    code += b"\xFF\x05" + struct.pack("<I", at["good"])                 # 18 inc dword [good]
    code += bytes.fromhex("909090")                                     # 1E nop; nop; nop
    code += bytes.fromhex("6A0A")                                       # 21 push 10
    code += b"\xFF\x15" + struct.pack("<I", at["sleep_ptr"])            # 23 call [sleep_ptr]
    code += b"\x83\x3D" + struct.pack("<I", at["stop"]) + b"\x00"       # 29 cmp dword [stop], 0
    code += bytes.fromhex("74CE")                                       # 30 je loop
    code += bytes.fromhex("31C0 C20400")                                # 32 xor eax, eax; ret 4
    code = code.ljust(labels["callee"], b"\xCC")
    code += bytes.fromhex("8B442404 03442408 0344240C F2C20C00")        # 40 a + b + c; bnd ret 12
    code = code.ljust(_REPEATER, b"\xCC")
    code += b"\x8B\x3D" + struct.pack("<I", at["rep_buffer"])           # 80 mov edi, [rep_buffer]
    code += b"\x8B\x0D" + struct.pack("<I", at["rep_count"])            # 86 mov ecx, [rep_count]
    code += bytes.fromhex("31C0 F3AA")                                  # 8C xor eax, eax; 8E rep stosb
    code += b"\xFF\x05" + struct.pack("<I", at["reps"])                 # 90 inc dword [reps]
    code += bytes.fromhex("6A0A")                                       # 96 push 10
    code += b"\xFF\x15" + struct.pack("<I", at["sleep_ptr"])            # 98 call [sleep_ptr]
    code += bytes.fromhex("EBE0")                                       # 9E jmp repeater
    code = code.ljust(_DORMANT, b"\xCC") + _DORMANT_CODE                # C0 dormant
    return code, at


def _x64_code(base: int) -> tuple[bytes, dict[str, int]]:
    labels = {"loop": 0x04, "second": 0x09, "call_site": 0x14, "after_call": 0x19,
              "spare": 0x2C, "callee": 0x60, "callee_second": 0x63,
              "repeater": _REPEATER, "rep": 0x93, "after_rep": 0x95, "dormant": _DORMANT,
              **_DATA_LABELS}

    def rip_relative(label: str, next_insn: int) -> bytes:
        return struct.pack("<i", labels[label] - next_insn)

    code = bytes.fromhex("4883EC28")                                    # 00 sub rsp, 0x28
    code += bytes.fromhex("B901000000 BA02000000 41B803000000")         # 04 mov ecx, 1; mov edx, 2; mov r8d, 3
    code += b"\xE8" + rip_relative("callee", 0x19)                      # 14 call callee
    code += bytes.fromhex("83F806")                                     # 19 cmp eax, 6
    code += bytes.fromhex("7408")                                       # 1C je 0x26
    code += b"\xFF\x05" + rip_relative("bad", 0x24)                     # 1E inc dword [bad]
    code += bytes.fromhex("EB06")                                       # 24 jmp 0x2C
    code += b"\xFF\x05" + rip_relative("good", 0x2C)                    # 26 inc dword [good]
    code += bytes.fromhex("90")                                         # 2C nop
    code += bytes.fromhex("B90A000000")                                 # 2D mov ecx, 10
    code += b"\xFF\x15" + rip_relative("sleep_ptr", 0x38)               # 32 call [sleep_ptr]
    code += b"\x83\x3D" + rip_relative("stop", 0x3F) + b"\x00"          # 38 cmp dword [stop], 0
    code += bytes.fromhex("74C3")                                       # 3F je loop
    code += bytes.fromhex("31C0 4883C428 C3")                           # 41 xor eax, eax; add rsp, 0x28; ret
    code = code.ljust(labels["callee"], b"\xCC")
    code += bytes.fromhex("8D0411 4401C0")                              # 60 lea eax, [rcx+rdx]; add eax, r8d
    code += bytes.fromhex("0F1F440000 0F1F440000 F2C3")                 # 66 two 5-byte nops; bnd ret
    code = code.ljust(_REPEATER, b"\xCC")
    code += bytes.fromhex("4883EC28")                                   # 80 sub rsp, 0x28
    code += b"\x48\x8B\x3D" + rip_relative("rep_buffer", 0x8B)          # 84 mov rdi, [rep_buffer]
    code += b"\x8B\x0D" + rip_relative("rep_count", 0x91)               # 8B mov ecx, [rep_count]
    code += bytes.fromhex("31C0 F3AA")                                  # 91 xor eax, eax; 93 rep stosb
    code += b"\xFF\x05" + rip_relative("reps", 0x9B)                    # 95 inc dword [reps]
    code += bytes.fromhex("B90A000000")                                 # 9B mov ecx, 10
    code += b"\xFF\x15" + rip_relative("sleep_ptr", 0xA6)               # A0 call [sleep_ptr]
    code += bytes.fromhex("EBDC")                                       # A6 jmp 0x84
    code = code.ljust(_DORMANT, b"\xCC") + _DORMANT_CODE                # C0 dormant
    return code, {name: base + offset for name, offset in labels.items()}


_CODE = {"x86": _x86_code, "x64": _x64_code}


def hex_addr(address: int) -> str:
    """*address* in the form the daemon's commands take."""
    return f"0x{address:08X}"


class Loop:
    """One copy of the loop, running on its own thread of a ``LiveTarget``."""

    def __init__(self, target: "LiveTarget", base: int, labels: dict[str, int], code: bytes):
        self._target = target
        self._base = base
        self._labels = labels
        self._code = code
        self._repeater_started = False

    def start_thread(self) -> None:
        """Run the loop on one more thread, sharing this copy's code and counters."""
        self._target.helper.start_thread(self.addr("loop"))

    def set_repeat(self, buffer: int, count: int) -> None:
        """Make the repeater fill *count* bytes at *buffer* from its next pass on."""
        data = struct.pack("<QI", buffer, count)
        self._target.run({"cmd": "mem_write", "addr": self.addr("rep_buffer"), "hex": data.hex()})

    def start_repeater(self) -> None:
        """Run the repeater on its own thread, once per copy of the code."""
        if not self._repeater_started:
            self._target.helper.start_thread(self.addr("repeater"))
            self._repeater_started = True

    @property
    def reps(self) -> int:
        """How many times the repeater has completed its ``rep stosb``."""
        reply = self._target.run({"cmd": "mem_read", "addr": self.addr("reps"), "size": 4})
        return struct.unpack("<I", bytes.fromhex(reply["hex"]))[0]

    def addr(self, label: str) -> str:
        """Address of *label* in the form the daemon's commands take."""
        return hex_addr(self._labels[label])

    def built_bytes(self, label: str, size: int) -> bytes:
        """The *size* bytes the loop was built with at *label*."""
        offset = self._labels[label] - self._base
        return self._code[offset:offset + size]

    def live_bytes(self, label: str, size: int) -> bytes:
        """The *size* bytes now in the process at *label*."""
        reply = self._target.run({"cmd": "mem_read", "addr": self.addr(label), "size": size})
        return bytes.fromhex(reply["hex"])

    def _counters(self) -> tuple[int, int]:
        """(good, bad): iterations in which callee returned the right sum, and the rest."""
        reply = self._target.run({"cmd": "mem_read", "addr": self.addr("good"), "size": 8})
        return struct.unpack("<II", bytes.fromhex(reply["hex"]))

    @property
    def bad(self) -> int:
        """Iterations in which callee returned anything but the sum of its arguments."""
        return self._counters()[1]

    def wait_for_iterations(self, count: int, timeout: float = 5.0) -> None:
        """Block until the loop has completed *count* more iterations.

        Raises:
            AssertionError: The loop did not get that far within *timeout*.
        """
        goal = sum(self._counters()) + count
        deadline = time.monotonic() + timeout
        while sum(self._counters()) < goal:
            assert self._target.alive, "the target process died"
            assert time.monotonic() < deadline, "the target's loop stopped running"
            time.sleep(0.02)

    @contextlib.contextmanager
    def stays_correct(self):
        """Assert the loop keeps running and computes the right sum throughout."""
        bad_before = self.bad
        yield
        self.wait_for_iterations(3)
        assert self.bad == bad_before, "callee received or returned a wrong value"


class LiveTarget:
    """An idle process with a daemon attached and one ``Loop`` running in it.

    Attributes:
        arch: "x86" or "x64".
        daemon: The attached ``livetools.server.Daemon``.
        loop: The loop started with the process.
        helper: RPC exports of the helper script loaded beside the agent.
    """

    def __init__(self, arch: str):
        self.arch = arch
        host = Path(os.environ["SystemRoot"]) / _HOST_DIR[arch] / "cmd.exe"
        self._process = subprocess.Popen(
            [str(host)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=_CREATE_NO_WINDOW)
        self.daemon = None
        try:
            self.attach_daemon()
            self.loop = self.start_loop()
        except BaseException:
            self.close()
            raise

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def alive(self) -> bool:
        return self._process.poll() is None

    def attach_daemon(self) -> None:
        """Attach a new daemon, and with it a new agent and helper script."""
        self.daemon = server.Daemon(str(self.pid))
        self.daemon.attach()
        helper = self.daemon.session.create_script(_HELPER_JS)
        helper.load()
        self.helper = helper.exports_sync

    def detach_daemon(self) -> None:
        """Unload the agent and drop the session, as the daemon does when it stops."""
        self.daemon._cleanup()

    def start_loop(self) -> Loop:
        """Write another copy of the loop into the process and run it on a new thread."""
        base = int(self.helper.allocate(2 * _PAGE), 16)
        sleep = int(self.helper.export_address("kernel32.dll", "Sleep"), 16)
        code, labels = _CODE[self.arch](base)
        data = struct.pack("<IIIIQQI", 0, 0, 0, 0, sleep, labels["buffer"], REP_COUNT)
        self.run({"cmd": "mem_write", "addr": hex_addr(base), "hex": code.hex()})
        self.run({"cmd": "mem_write", "addr": hex_addr(labels["good"]), "hex": data.hex()})
        self.helper.make_read_execute(hex_addr(base), _PAGE)
        self.helper.start_thread(hex_addr(base))
        loop = Loop(self, base, labels, code)
        loop.wait_for_iterations(3)
        return loop

    def write_code(self, code: bytes) -> int:
        """Write *code* to a page of its own, which nothing executes, and return its address."""
        base = int(self.helper.allocate(_PAGE), 16)
        self.run({"cmd": "mem_write", "addr": hex_addr(base), "hex": code.hex()})
        return base

    def write_code_out_of_reach(self, code: bytes) -> int | None:
        """Write *code* to a page with no free memory within reach of a 32-bit jump.

        A hook there cannot have its trampoline nearby, so its jump is the long
        form. The address space around the page stays reserved.

        Returns:
            The address of the code, or None if the address space could not be reserved.
        """
        page = self.helper.allocate_out_of_reach()
        if page is None:
            return None
        self.run({"cmd": "mem_write", "addr": page, "hex": code.hex()})
        return int(page, 16)

    def release(self, base: int) -> None:
        """Unmap the pages allocated at *base*."""
        assert self.helper.release(hex_addr(base))

    def run(self, command: dict) -> dict:
        """Send *command* to the daemon the way the CLI does and return its reply."""
        return self.daemon.handle(command)

    def reset(self) -> None:
        """Remove the vishook and every breakpoint, and release a frozen thread."""
        self.run({"cmd": "vishook_off"})
        for breakpoint in self.run({"cmd": "bp_list"})["breakpoints"]:
            self.run({"cmd": "bp_del", "addr": breakpoint["addr"]})
        if self.run({"cmd": "status"})["state"] == "FROZEN":
            self.run({"cmd": "resume"})

    def addr(self, label: str) -> str:
        return self.loop.addr(label)

    @property
    def bad(self) -> int:
        return self.loop.bad

    def wait_for_iterations(self, count: int, timeout: float = 5.0) -> None:
        self.loop.wait_for_iterations(count, timeout)

    def stays_correct(self):
        return self.loop.stays_correct()

    def close(self) -> None:
        """Kill the process, then drop the session."""
        self._process.kill()
        self._process.wait()
        self._process.stdin.close()
        if self.daemon is not None:
            self.daemon._cleanup()
