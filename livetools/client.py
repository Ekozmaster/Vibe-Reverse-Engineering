"""TCP client helper and output formatters for the livetools CLI."""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path

HOST = "127.0.0.1"
PORT = 27042
STATE_FILE = Path(__file__).parent / ".state.json"
DAEMON_LOG = Path(__file__).parent / ".daemon.log"
RECV_BUF = 1 << 20


# ── state file helpers ─────────────────────────────────────────────────────

def read_state() -> dict | None:
    if not STATE_FILE.exists():
        return None
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return None


def is_target_running(pid: int) -> bool:
    """Check if a process with the given PID is still alive."""
    if pid is None:
        return False
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        SYNCHRONIZE = 0x00100000
        h = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if h:
            kernel32.CloseHandle(h)
            return True
        return False
    except Exception:
        import os
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def is_daemon_alive() -> bool:
    state = read_state()
    if state is None:
        return False
    target_pid = state.get("targetPid")
    if target_pid and not is_target_running(target_pid):
        _kill_stale_daemon(state)
        return False
    try:
        s = socket.create_connection((HOST, state.get("port", PORT)), timeout=2)
        s.close()
        return True
    except OSError:
        STATE_FILE.unlink(missing_ok=True)
        return False


def _kill_stale_daemon(state: dict) -> None:
    """Terminate a daemon whose target process has exited."""
    daemon_pid = state.get("pid")
    if daemon_pid:
        try:
            import os, signal
            os.kill(daemon_pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
    STATE_FILE.unlink(missing_ok=True)


# ── TCP protocol: length-prefixed JSON ─────────────────────────────────────

def _send_raw(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recv_raw(sock: socket.socket) -> bytes:
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("daemon closed connection")
        hdr += chunk
    length = struct.unpack("!I", hdr)[0]
    parts, remaining = [], length
    while remaining > 0:
        chunk = sock.recv(min(remaining, RECV_BUF))
        if not chunk:
            raise ConnectionError("daemon closed connection")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def send_command(cmd: dict, timeout: float | None = None) -> dict:
    """Connect to daemon, send *cmd* dict, return parsed response dict."""
    state = read_state()
    port = state.get("port", PORT) if state else PORT
    sock = socket.create_connection((HOST, port), timeout=5)
    if timeout is not None:
        sock.settimeout(timeout + 10)
    try:
        _send_raw(sock, json.dumps(cmd).encode())
        return json.loads(_recv_raw(sock))
    finally:
        sock.close()


# ── output formatting ──────────────────────────────────────────────────────

def format_status_line(resp: dict) -> str:
    target = resp.get("target", "?")
    pid = resp.get("pid", "?")
    state = resp.get("state", "UNKNOWN")
    bps = resp.get("bpCount", 0)
    if state == "FROZEN":
        frozen_addr = resp.get("frozenAddr", "?")
        return f"[attached: {target} (pid {pid}) | FROZEN @ {frozen_addr} | bps: {bps}]"
    if state == "RUNNING":
        return f"[attached: {target} (pid {pid}) | RUNNING | bps: {bps}]"
    return "[not attached]"


def format_snapshot(snap: dict, header: str = "BREAKPOINT HIT") -> str:
    lines: list[str] = []
    addr = snap.get("addr", "????????")
    if not addr.startswith("0x"):
        addr = "0x" + addr
    bp_id = snap.get("bpId", "?")
    hit = snap.get("hitCount", "?")
    lines.append(f"=== {header} === {addr} (bp#{bp_id}, hit #{hit})")
    lines.append("")

    regs = snap.get("regs", {})
    arch = regs.get("_arch", "x86")
    lines.append("Registers:")

    if arch == "x64":
        w = 16
        lines.append(
            f"  RAX={regs.get('rax','?'):>{w}s}  RBX={regs.get('rbx','?'):>{w}s}"
            f"  RCX={regs.get('rcx','?'):>{w}s}  RDX={regs.get('rdx','?'):>{w}s}")
        lines.append(
            f"  RSI={regs.get('rsi','?'):>{w}s}  RDI={regs.get('rdi','?'):>{w}s}"
            f"  RBP={regs.get('rbp','?'):>{w}s}  RSP={regs.get('rsp','?'):>{w}s}")
        lines.append(
            f"  R8 ={regs.get('r8','?'):>{w}s}  R9 ={regs.get('r9','?'):>{w}s}"
            f"  R10={regs.get('r10','?'):>{w}s}  R11={regs.get('r11','?'):>{w}s}")
        lines.append(
            f"  R12={regs.get('r12','?'):>{w}s}  R13={regs.get('r13','?'):>{w}s}"
            f"  R14={regs.get('r14','?'):>{w}s}  R15={regs.get('r15','?'):>{w}s}")
        lines.append(f"  RIP={regs.get('rip','?'):>{w}s}")
        sp_key, ip_key, slot_size = "rsp", "rip", 8
    else:
        w = 8
        lines.append(
            f"  EAX={regs.get('eax','?'):>{w}s}  EBX={regs.get('ebx','?'):>{w}s}"
            f"  ECX={regs.get('ecx','?'):>{w}s}  EDX={regs.get('edx','?'):>{w}s}")
        lines.append(
            f"  ESI={regs.get('esi','?'):>{w}s}  EDI={regs.get('edi','?'):>{w}s}"
            f"  EBP={regs.get('ebp','?'):>{w}s}  ESP={regs.get('esp','?'):>{w}s}")
        lines.append(f"  EIP={regs.get('eip','?'):>{w}s}")
        sp_key, ip_key, slot_size = "esp", "eip", 4
    lines.append("")

    stack = snap.get("stack", [])
    if stack:
        sp_str = regs.get(sp_key, "?" * w)
        lines.append(f"Stack [{sp_key.upper()}={sp_str}]:")
        row = []
        for i, val in enumerate(stack):
            row.append(f"+{i*slot_size:02X}: {val}")
            if len(row) == 4:
                lines.append("  " + "  ".join(row))
                row = []
        if row:
            lines.append("  " + "  ".join(row))
        lines.append("")

    disasm = snap.get("disasm", [])
    if disasm:
        lines.append("Disasm @ EIP:")
        for i, insn in enumerate(disasm):
            marker = ">" if i == 0 else " "
            lines.append(f"{marker} {insn.get('addr', '????????')}  {insn.get('str', '??')}")
    return "\n".join(lines)


# ── NEW: trace formatter ──────────────────────────────────────────────────

def format_trace(resp: dict) -> str:
    lines: list[str] = []
    samples = resp.get("samples", [])
    count = resp.get("count", len(samples))
    if samples:
        addr = samples[0].get("addr", "?")
        lines.append(f"=== TRACE {addr} === {count} samples")
    else:
        lines.append("=== TRACE === 0 samples")
    lines.append("")

    for i, s in enumerate(samples):
        caller = s.get("caller", "?")
        interval = s.get("interval", 0)
        label = s.get("label", "")
        hdr = f"#{i+1}  caller={caller}"
        if interval:
            hdr += f"  interval={interval}"
        if label:
            hdr += f"  [{label}]"
        lines.append(hdr)

        enter = s.get("enter", {})
        if enter:
            parts = []
            regs = enter.get("regs", {})
            for rn in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
                if rn in regs:
                    parts.append(f"{rn}={regs[rn]}")
            reads = enter.get("reads", [])
            for r in reads:
                val = r.get("value")
                if val is None:
                    parts.append(f"{r['spec']}=<err>")
                else:
                    parts.append(f"{r['spec']}={_fmt_val(val)}")
            lines.append(f"  ENTER  {' '.join(parts)}")

        leave = s.get("leave", {})
        if leave:
            parts = []
            for k in ("eax", "retval"):
                v = leave.get(k)
                if v:
                    parts.append(f"{k}={v}")
            reads = leave.get("reads", [])
            for r in reads:
                val = r.get("value")
                parts.append(f"{r['spec']}={_fmt_val(val)}")
            lines.append(f"  LEAVE  {' '.join(parts)}")

    output = resp.get("output")
    if output:
        lines.append("")
        lines.append(f"Output written to: {output}")

    if count == 0:
        diag = resp.get("hookDiag", {})
        if diag:
            p = diag.get("prologue", {})
            insns = p.get("insns", [])
            desc = ", ".join(f"{i['mnemonic']} {i['opStr']} [{i['size']}B]" for i in insns[:4])
            lines.append("")
            lines.append(f"  [WARN] 0 samples — function may be dead/inlined, or game window not focused")
            lines.append(f"    prologue={p.get('totalBytes', '?')}B (need {p.get('needed', '?')}B), "
                         f"insns=[{desc}]")

    return "\n".join(lines)


def _fmt_val(val) -> str:
    if val is None:
        return "<null>"
    if isinstance(val, list):
        if len(val) <= 8:
            return "[" + ", ".join(str(v) for v in val) + "]"
        return "[" + ", ".join(str(v) for v in val[:8]) + f", ... ({len(val)} total)]"
    return str(val)


# ── NEW: steptrace formatter ──────────────────────────────────────────────

def format_steptrace(resp: dict) -> str:
    lines: list[str] = []
    trace = resp.get("trace", {})
    addr = trace.get("addr", "?")
    insn_count = trace.get("insnCount", 0)
    detail = trace.get("detail", "?")
    calls = trace.get("calls", [])
    branches = trace.get("branches", [])
    insn_addrs = trace.get("trace", [])

    n_calls = sum(1 for c in calls if c.get("type") == "call")
    n_branches = len(branches)

    lines.append(f"=== STEPTRACE {addr} === {insn_count} insns, "
                 f"{n_calls} calls, {n_branches} branches, detail={detail}")
    lines.append("")

    entry_regs = trace.get("entryRegs", {})
    if entry_regs:
        arch = entry_regs.get("_arch", "x86")
        reg_list = (["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
                    if arch == "x86" else
                    ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"])
        parts = [f"{r}={entry_regs.get(r, '?')}" for r in reg_list]
        lines.append(f"Entry: {' '.join(parts)}")
        lines.append("")

    branch_map = {b["addr"]: b for b in branches}
    call_by_addr = {}
    for c in calls:
        call_by_addr.setdefault(c.get("addr", ""), []).append(c)

    for ia in insn_addrs[:200]:
        ann = ""
        if ia in branch_map:
            br = branch_map[ia]
            regs = br.get("regs", {})
            ann = "  ; " + " ".join(f"{k}={v}" for k, v in regs.items()
                                     if k != "_arch" and k in
                                     ("eax", "ecx", "edx", "ebx", "esi", "edi",
                                      "rax", "rcx", "rdx", "rbx", "rsi", "rdi"))
        if ia in call_by_addr:
            for c in call_by_addr[ia]:
                depth = c.get("depth", 0)
                if c.get("type") == "call":
                    tgt = c.get("target", "?")
                    sk = " [SKIPPED]" if c.get("skipped") else ""
                    ann += f"  ; call {tgt} depth={depth}{sk}"
                elif c.get("type") == "ret":
                    ann += f"  ; ret depth={depth}"

        lines.append(f" {ia}{ann}")

    if len(insn_addrs) > 200:
        lines.append(f" ... ({len(insn_addrs) - 200} more instructions)")

    output = resp.get("output")
    if output:
        lines.append("")
        lines.append(f"Output written to: {output}")

    return "\n".join(lines)


# ── NEW: collect formatter ─────────────────────────────────────────────────

def format_collect(resp: dict) -> str:
    lines: list[str] = []
    total = resp.get("totalRecords", 0)
    output = resp.get("output", "?")
    fence = resp.get("fenceCount", 0)
    lines.append(f"=== COLLECT COMPLETE ===")
    lines.append(f"  Records: {total}")
    lines.append(f"  Intervals (fences): {fence}")
    lines.append(f"  Output: {output}")

    diags = resp.get("hookDiags", [])
    failed = [d for d in diags if not d.get("ok")]
    if failed:
        lines.append("")
        for d in failed:
            lines.append(f"  [HOOK FAILED] {d['addr']}: {d.get('error', '?')}")
    if total == 0 and not failed:
        lines.append("")
        lines.append("  [WARN] 0 records collected. Possible causes:")
        lines.append("    - Game window not focused (alt-tab to game during collect)")
        lines.append("    - Function never called at runtime (dead code or inlined)")
        for d in diags:
            if d.get("ok"):
                p = d.get("prologue", {})
                insns = p.get("insns", [])
                desc = ", ".join(f"{i['mnemonic']} {i['opStr']} [{i['size']}B]" for i in insns[:4])
                lines.append(f"    {d['addr']}: prologue={p.get('totalBytes', '?')}B "
                             f"(need {p.get('needed', '?')}B), "
                             f"insns=[{desc}]")
    return "\n".join(lines)


# ── NEW: modules formatter ─────────────────────────────────────────────────

def format_modules(resp: dict) -> str:
    lines: list[str] = []
    modules = resp.get("modules", [])
    lines.append(f"=== MODULES === {len(modules)} loaded")
    lines.append("")
    lines.append(f"  {'Name':<30s}  {'Base':>10s}  {'Size':>10s}  Path")
    lines.append(f"  {'-'*30}  {'-'*10}  {'-'*10}  {'-'*40}")
    for m in modules:
        name = m.get("name", "?")
        base = m.get("base", "?")
        size = m.get("size", 0)
        path = m.get("path", "?")
        lines.append(f"  {name:<30s}  {base:>10s}  {size:>10d}  {path}")
    return "\n".join(lines)


# ── mem read formatter (existing) ──────────────────────────────────────────

def format_mem_read(addr: int, raw: bytes, as_type: str | None = None) -> str:
    lines: list[str] = []
    for off in range(0, len(raw), 16):
        chunk = raw[off : off + 16]
        hex_left = " ".join(f"{b:02X}" for b in chunk[:8])
        hex_right = " ".join(f"{b:02X}" for b in chunk[8:])
        ascii_repr = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{addr + off:08X}: {hex_left:<23s} | {hex_right:<23s}  {ascii_repr}")

    if as_type:
        lines.append("")
        lines.append(_interpret_as(addr, raw, as_type))
    else:
        lines.append("")
        for t in ("float32", "uint32", "int32", "uint16", "ascii"):
            interp = _interpret_as(addr, raw, t)
            if interp:
                lines.append(interp)
    return "\n".join(lines)


def _interpret_as(addr: int, raw: bytes, dtype: str) -> str:
    import struct as st

    if dtype == "float32":
        return f"As float32: [{', '.join(f'{v:12.6f}' for v in _unpack_all(raw, '<f', 4))}]"
    elif dtype == "float64":
        return f"As float64: [{', '.join(f'{v:16.10f}' for v in _unpack_all(raw, '<d', 8))}]"
    elif dtype == "half":
        return f"As half:    [{', '.join(f'{v:10.4f}' for v in _unpack_all(raw, '<e', 2))}]"
    elif dtype == "uint32":
        return f"As uint32:  [{', '.join(f'0x{v:08X}' for v in _unpack_all(raw, '<I', 4))}]"
    elif dtype == "int32":
        return f"As int32:   [{', '.join(f'{v:11d}' for v in _unpack_all(raw, '<i', 4))}]"
    elif dtype == "uint16":
        return f"As uint16:  [{', '.join(f'0x{v:04X}' for v in _unpack_all(raw, '<H', 2))}]"
    elif dtype == "int16":
        return f"As int16:   [{', '.join(f'{v:6d}' for v in _unpack_all(raw, '<h', 2))}]"
    elif dtype == "uint8":
        return f"As uint8:   [{', '.join(f'0x{b:02X}' for b in raw)}]"
    elif dtype == "int8":
        return f"As int8:    [{', '.join(f'{v:4d}' for v in _unpack_all(raw, '<b', 1))}]"
    elif dtype == "ptr":
        return f"As ptr:     [{', '.join(f'-> 0x{v:08X}' for v in _unpack_all(raw, '<I', 4))}]"
    elif dtype == "ascii":
        return f'As ascii:   "{raw.decode("ascii", errors="replace").rstrip(chr(0))}"'
    elif dtype == "utf16":
        return f'As utf16:   "{raw.decode("utf-16-le", errors="replace").rstrip(chr(0))}"'
    return ""


def _unpack_all(raw: bytes, fmt: str, size: int) -> list:
    import struct as st
    return [st.unpack(fmt, raw[off : off + size])[0]
            for off in range(0, len(raw) - size + 1, size)]
