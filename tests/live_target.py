"""A throwaway process running known machine code, for tests that need real Frida.

``LiveTarget`` starts an idle system program, attaches the livetools daemon to
it and runs a small hand-assembled loop on a new thread, so a test knows every
instruction address and every argument value:

    loop:        load the arguments 1, 2, 3 (pushed on x86, in registers on x64)
    call_site:   call callee
    after_call:  count the iteration as good if callee returned 6, else as bad
                 Sleep(10) and repeat
    callee:      return a + b + c

A hook that disturbs an argument, a return address or the stack shows up in
the ``bad`` counter, or stops the ``good`` counter from advancing.
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

# Runs beside the livetools agent to do what the agent has no command for.
_HELPER_JS = r"""
rpc.exports = {
    exportAddress: function (moduleName, exportName) {
        return Process.getModuleByName(moduleName).getExportByName(exportName).toString();
    },
    startThread: function (entry) {
        var createThread = new NativeFunction(
            Process.getModuleByName('kernel32.dll').getExportByName('CreateThread'),
            'pointer', ['pointer', 'size_t', 'pointer', 'pointer', 'uint32', 'pointer']);
        return createThread(NULL, 0, ptr(entry), NULL, 0, NULL).toString();
    }
};
"""


def _x86_image(base: int, sleep: int) -> tuple[bytes, dict[str, int]]:
    labels = {"loop": 0x00, "call_site": 0x06, "after_call": 0x0B, "callee": 0x40,
              "good": 0x60, "bad": 0x64, "stop": 0x68, "sleep_ptr": 0x6C}
    at = {name: base + offset for name, offset in labels.items()}
    code = bytes.fromhex("6A03 6A02 6A01")                              # 00 push 3; push 2; push 1
    code += b"\xE8" + struct.pack("<i", labels["callee"] - 0x0B)        # 06 call callee
    code += bytes.fromhex("83F806")                                     # 0B cmp eax, 6
    code += bytes.fromhex("7408")                                       # 0E je 0x18
    code += b"\xFF\x05" + struct.pack("<I", at["bad"])                  # 10 inc dword [bad]
    code += bytes.fromhex("EB06")                                       # 16 jmp 0x1E
    code += b"\xFF\x05" + struct.pack("<I", at["good"])                 # 18 inc dword [good]
    code += bytes.fromhex("6A0A")                                       # 1E push 10
    code += b"\xFF\x15" + struct.pack("<I", at["sleep_ptr"])            # 20 call [sleep_ptr]
    code += b"\x83\x3D" + struct.pack("<I", at["stop"]) + b"\x00"       # 26 cmp dword [stop], 0
    code += bytes.fromhex("74D1")                                       # 2D je loop
    code += bytes.fromhex("31C0 C20400")                                # 2F xor eax, eax; ret 4
    code = code.ljust(labels["callee"], b"\xCC")
    code += bytes.fromhex("8B442404 03442408 0344240C C20C00")          # 40 a + b + c; ret 12
    code = code.ljust(labels["good"], b"\xCC")
    code += struct.pack("<IIII", 0, 0, 0, sleep)
    return code, at


def _x64_image(base: int, sleep: int) -> tuple[bytes, dict[str, int]]:
    labels = {"loop": 0x04, "call_site": 0x14, "after_call": 0x19, "callee": 0x60,
              "good": 0x80, "bad": 0x84, "stop": 0x88, "sleep_ptr": 0x90}

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
    code += bytes.fromhex("B90A000000")                                 # 2C mov ecx, 10
    code += b"\xFF\x15" + rip_relative("sleep_ptr", 0x37)               # 31 call [sleep_ptr]
    code += b"\x83\x3D" + rip_relative("stop", 0x3E) + b"\x00"          # 37 cmp dword [stop], 0
    code += bytes.fromhex("74C4")                                       # 3E je loop
    code += bytes.fromhex("31C0 4883C428 C3")                           # 40 xor eax, eax; add rsp, 0x28; ret
    code = code.ljust(labels["callee"], b"\xCC")
    code += bytes.fromhex("8D0411 4401C0")                              # 60 lea eax, [rcx+rdx]; add eax, r8d
    code += bytes.fromhex("0F1F440000 0F1F440000 C3")                   # 66 two 5-byte nops; ret
    code = code.ljust(labels["good"], b"\xCC")
    code += struct.pack("<IIIIQ", 0, 0, 0, 0, sleep)
    return code, {name: base + offset for name, offset in labels.items()}


_IMAGE = {"x86": _x86_image, "x64": _x64_image}


class LiveTarget:
    """An idle process with the loop above running in it and a daemon attached.

    Attributes:
        arch: "x86" or "x64".
        daemon: The attached ``livetools.server.Daemon``.
    """

    def __init__(self, arch: str):
        self.arch = arch
        host = Path(os.environ["SystemRoot"]) / _HOST_DIR[arch] / "cmd.exe"
        self._process = subprocess.Popen(
            [str(host)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=_CREATE_NO_WINDOW)
        try:
            self.daemon = server.Daemon(str(self._process.pid))
            self.daemon.attach()
            helper = self.daemon.session.create_script(_HELPER_JS)
            helper.load()
            base = int(self.run({"cmd": "mem_alloc", "size": _PAGE})["addr"], 16)
            sleep = int(helper.exports_sync.export_address("kernel32.dll", "Sleep"), 16)
            image, self._labels = _IMAGE[arch](base, sleep)
            self.run({"cmd": "mem_write", "addr": self._hex(base), "hex": image.hex()})
            helper.exports_sync.start_thread(self._hex(base))
            self.wait_for_iterations(3)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _hex(address: int) -> str:
        return f"0x{address:08X}"

    def addr(self, label: str) -> str:
        """Address of *label* in the form the daemon's commands take."""
        return self._hex(self._labels[label])

    def run(self, command: dict) -> dict:
        """Send *command* to the daemon the way the CLI does and return its reply."""
        return self.daemon.handle(command)

    def _counters(self) -> tuple[int, int]:
        """(good, bad): iterations in which callee returned the right sum, and the rest."""
        reply = self.run({"cmd": "mem_read", "addr": self.addr("good"), "size": 8})
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
            assert self._process.poll() is None, "the target process died"
            assert time.monotonic() < deadline, "the target's loop stopped running"
            time.sleep(0.02)

    @contextlib.contextmanager
    def stays_correct(self):
        """Assert the loop keeps running and computes the right sum throughout."""
        bad_before = self.bad
        yield
        self.wait_for_iterations(3)
        assert self.bad == bad_before, "callee received or returned a wrong value"

    def close(self) -> None:
        """Kill the process, then drop the session.

        The process goes first: the loop runs in memory the agent allocated,
        which unloading the agent would free under the running thread.
        """
        self._process.kill()
        self._process.wait()
        self._process.stdin.close()
        daemon = getattr(self, "daemon", None)
        if daemon is not None:
            daemon._cleanup()
