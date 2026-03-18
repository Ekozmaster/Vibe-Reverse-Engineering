"""CLI entry point for livetools -- Frida-based live process analysis toolkit.

Usage:  python -m livetools <command> [args]

Session management:
    python -m livetools attach <process_name_or_pid>
    python -m livetools detach
    python -m livetools status

Breakpoints:
    python -m livetools bp add <addr>
    python -m livetools bp del <addr>
    python -m livetools bp list

Execution control:
    python -m livetools watch [--timeout 60]
    python -m livetools step [over|into|out]
    python -m livetools resume

Inspection:
    python -m livetools regs
    python -m livetools stack [count]
    python -m livetools disasm [addr] [-n 16]
    python -m livetools bt
    python -m livetools mem read <addr> <size> [--as float32]
    python -m livetools mem write <addr> <hex_bytes>

Non-blocking tracing:
    python -m livetools trace <addr> [--count N] [--read SPEC] [--filter EXPR]
    python -m livetools steptrace <addr> [--max-insn N] [--call-depth D]
    python -m livetools collect <addr> [addr2 ...] [--duration N] [--fence ADDR]
    python -m livetools modules [--filter PATTERN]

Offline analysis:
    python -m livetools analyze <file.jsonl> [--summary] [--group-by FIELD]

Scanning:
    python -m livetools scan <hex_pattern> [--range START:SIZE]

Memory watchpoint:
    python -m livetools memwatch start <addr> [--size N] [--max-hits N]
    python -m livetools memwatch read
    python -m livetools memwatch stop

Workflow:  attach -> (bp/trace/collect/steptrace/modules) -> analyze -> detach

NOTE: Some games only run rendering/logic when their window is focused.
If trace/steptrace/collect time out with 0 results, alt-tab to the game first.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from . import client


def _parse_addr(addr_str: str) -> str:
    val = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str, 16)
    return f"0x{val:08X}"


def _require_attached() -> bool:
    if not client.is_daemon_alive():
        print("[not attached]")
        return False
    return True


# ── session commands ───────────────────────────────────────────────────────

def cmd_attach(args: argparse.Namespace) -> None:
    if client.is_daemon_alive():
        try:
            resp = client.send_command({"cmd": "status"})
            if resp.get("state") in ("RUNNING", "FROZEN"):
                print(client.format_status_line(resp))
                print("Already attached. Use 'detach' first to release.")
                return
        except Exception:
            pass
        print("Stale daemon detected, cleaning up...")
        _force_cleanup()

    _spawn_daemon(args.target)


def _force_cleanup() -> None:
    state = client.read_state()
    if state:
        client._kill_stale_daemon(state)
    else:
        client.STATE_FILE.unlink(missing_ok=True)
    time.sleep(0.5)


def _spawn_daemon(target: str) -> None:
    daemon_cmd = [sys.executable, "-m", "livetools.server", target]
    kwargs: dict = {}
    if sys.platform == "win32":
        CREATE_NO_WINDOW = 0x08000000
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    kwargs["stdout"] = subprocess.DEVNULL
    kwargs["stderr"] = subprocess.DEVNULL
    subprocess.Popen(daemon_cmd, **kwargs)

    deadline = time.time() + 15
    while time.time() < deadline:
        if client.is_daemon_alive():
            resp = client.send_command({"cmd": "status"})
            print(client.format_status_line(resp))
            print(f"Attached to {target}.")
            return
        time.sleep(0.3)
    print("[error] Daemon did not start within 15 seconds.", file=sys.stderr)
    sys.exit(1)


def cmd_detach(_args: argparse.Namespace) -> None:
    if not client.is_daemon_alive():
        client.STATE_FILE.unlink(missing_ok=True)
        print("Detached (daemon was already gone).")
        return
    try:
        resp = client.send_command({"cmd": "detach"})
        print(client.format_status_line(resp))
    except Exception:
        pass
    print("Detached.")
    time.sleep(0.5)
    client.STATE_FILE.unlink(missing_ok=True)


def cmd_status(_args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    resp = client.send_command({"cmd": "status"})
    print(client.format_status_line(resp))


# ── breakpoint commands ────────────────────────────────────────────────────

def cmd_bp(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    action = args.action
    if action == "add":
        addr = _parse_addr(args.addr)
        resp = client.send_command({"cmd": "bp_add", "addr": addr})
        print(client.format_status_line(resp))
        if resp.get("ok"):
            msg = resp.get("msg", "")
            extra = f" ({msg})" if msg else ""
            print(f"Breakpoint #{resp.get('bpId')} set at {addr}{extra}")
        else:
            print(f"[error] {resp.get('error', 'unknown')}")
    elif action == "del":
        addr = _parse_addr(args.addr)
        resp = client.send_command({"cmd": "bp_del", "addr": addr})
        print(client.format_status_line(resp))
        if resp.get("ok"):
            print(f"Breakpoint at {addr} removed.")
        else:
            print(f"[error] {resp.get('error', resp.get('msg', 'unknown'))}")
    elif action == "list":
        resp = client.send_command({"cmd": "bp_list"})
        print(client.format_status_line(resp))
        bps = resp.get("breakpoints", [])
        if not bps:
            print("No breakpoints set.")
        else:
            for bp in bps:
                print(f"  bp#{bp['id']}  {bp['addr']}  hits: {bp['hitCount']}")


# ── execution control commands ─────────────────────────────────────────────

def cmd_watch(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    timeout = args.timeout
    resp = client.send_command({"cmd": "watch", "timeout": timeout}, timeout=timeout)
    print(client.format_status_line(resp))
    if resp.get("timeout"):
        print(f"[TIMEOUT] No breakpoint hit within {timeout}s")
        return
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    snap = resp.get("snapshot")
    if snap:
        print(client.format_snapshot(snap))


def cmd_regs(_args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    resp = client.send_command({"cmd": "regs"})
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    regs = resp["regs"]
    arch = regs.get("_arch", "x86")
    print("Registers:")
    if arch == "x64":
        w = 16
        print(f"  RAX={regs.get('rax','?'):>{w}s}  RBX={regs.get('rbx','?'):>{w}s}"
              f"  RCX={regs.get('rcx','?'):>{w}s}  RDX={regs.get('rdx','?'):>{w}s}")
        print(f"  RSI={regs.get('rsi','?'):>{w}s}  RDI={regs.get('rdi','?'):>{w}s}"
              f"  RBP={regs.get('rbp','?'):>{w}s}  RSP={regs.get('rsp','?'):>{w}s}")
        print(f"  R8 ={regs.get('r8','?'):>{w}s}  R9 ={regs.get('r9','?'):>{w}s}"
              f"  R10={regs.get('r10','?'):>{w}s}  R11={regs.get('r11','?'):>{w}s}")
        print(f"  R12={regs.get('r12','?'):>{w}s}  R13={regs.get('r13','?'):>{w}s}"
              f"  R14={regs.get('r14','?'):>{w}s}  R15={regs.get('r15','?'):>{w}s}")
        print(f"  RIP={regs.get('rip','?'):>{w}s}")
    else:
        print(f"  EAX={regs.get('eax','?'):>8s}  EBX={regs.get('ebx','?'):>8s}"
              f"  ECX={regs.get('ecx','?'):>8s}  EDX={regs.get('edx','?'):>8s}")
        print(f"  ESI={regs.get('esi','?'):>8s}  EDI={regs.get('edi','?'):>8s}"
              f"  EBP={regs.get('ebp','?'):>8s}  ESP={regs.get('esp','?'):>8s}")
        print(f"  EIP={regs.get('eip','?'):>8s}")


def cmd_stack(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    resp = client.send_command({"cmd": "stack", "count": args.count})
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    entries = resp["stack"]
    print("Stack [ESP]:")
    row = []
    for i, val in enumerate(entries):
        row.append(f"+{i*4:02X}: {val}")
        if len(row) == 4:
            print("  " + "  ".join(row))
            row = []
    if row:
        print("  " + "  ".join(row))


def cmd_mem_read(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    addr = _parse_addr(args.addr)
    resp = client.send_command({"cmd": "mem_read", "addr": addr, "size": args.size})
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    raw = bytes.fromhex(resp["hex"])
    print(client.format_mem_read(int(addr, 16), raw, as_type=args.type))


def cmd_mem_write(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    addr = _parse_addr(args.addr)
    hex_bytes = args.hex_bytes.replace(" ", "")
    resp = client.send_command({"cmd": "mem_write", "addr": addr, "hex": hex_bytes})
    print(client.format_status_line(resp))
    if resp.get("ok"):
        print(f"Wrote {len(hex_bytes)//2} bytes to {addr}.")
    else:
        print(f"[error] {resp.get('error', resp.get('msg', 'unknown'))}")


def cmd_mem_alloc(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    resp = client.send_command({"cmd": "mem_alloc", "size": args.size})
    print(client.format_status_line(resp))
    if resp.get("ok"):
        print(f"Allocated {args.size} bytes at {resp['addr']} (rwx)")
    else:
        print(f"[error] {resp.get('error', resp.get('msg', 'unknown'))}")


def cmd_disasm(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    cmd: dict = {"cmd": "disasm", "count": args.count}
    if args.addr:
        cmd["addr"] = _parse_addr(args.addr)
    resp = client.send_command(cmd)
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    for i, insn in enumerate(resp["disasm"]):
        marker = ">" if i == 0 and not args.addr else " "
        print(f"{marker} {insn['addr']}  {insn.get('str', '??')}")


def cmd_bt(_args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    resp = client.send_command({"cmd": "bt"})
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    for i, frame in enumerate(resp["frames"]):
        print(f"  #{i}  {frame}")


def cmd_step(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    resp = client.send_command({"cmd": "step", "mode": args.mode}, timeout=15)
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    snap = resp.get("snapshot")
    if snap:
        print(client.format_snapshot(snap, header="STEP COMPLETE"))


def cmd_resume(_args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    resp = client.send_command({"cmd": "resume"})
    print(client.format_status_line(resp))
    if resp.get("ok"):
        print("Resumed.")
    else:
        print(f"[error] {resp.get('error', 'unknown')}")


def cmd_scan(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    cmd: dict = {"cmd": "scan", "pattern": args.pattern}
    if args.range:
        parts = args.range.split(":")
        if len(parts) == 2:
            cmd["start"] = _parse_addr(parts[0])
            cmd["size"] = int(parts[1], 0)
    resp = client.send_command(cmd)
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    results = resp.get("results", [])
    if not results:
        print("No matches.")
    else:
        for m in results:
            print(f"  {m['addr']}  ({m['size']} bytes)")


# ── NEW: trace command ─────────────────────────────────────────────────────

def cmd_trace(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    addr = _parse_addr(args.addr)
    cmd: dict = {
        "cmd": "trace", "addr": addr,
        "count": args.count,
        "read": args.read or "",
        "readLeave": args.read_leave or "",
        "filter": args.filter or "",
        "timeout": args.timeout,
    }
    if args.output:
        cmd["output"] = args.output
    resp = client.send_command(cmd, timeout=args.timeout)
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    print(client.format_trace(resp))


# ── NEW: steptrace command ─────────────────────────────────────────────────

def cmd_steptrace(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    addr = _parse_addr(args.addr)
    cmd: dict = {
        "cmd": "steptrace", "addr": addr,
        "maxInsn": args.max_insn,
        "callDepth": args.call_depth,
        "detail": args.detail,
        "timeout": args.timeout,
    }
    if args.output:
        cmd["output"] = args.output
    resp = client.send_command(cmd, timeout=args.timeout)
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    print(client.format_steptrace(resp))


# ── NEW: collect command ───────────────────────────────────────────────────

def cmd_collect(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    addrs = [_parse_addr(a) for a in args.addrs]

    read_specs = {}
    if args.read_at:
        for spec in args.read_at:
            parts = spec.split("=", 1)
            if len(parts) == 2:
                read_specs[_parse_addr(parts[0])] = parts[1]

    labels = {}
    if args.label:
        for lbl in args.label:
            parts = lbl.split("=", 1)
            if len(parts) == 2:
                labels[_parse_addr(parts[0])] = parts[1]

    cmd: dict = {
        "cmd": "collect",
        "addrs": addrs,
        "duration": args.duration,
        "maxRecords": args.max_records,
        "read": args.read or "",
        "readSpecs": read_specs,
        "labels": labels,
    }
    if args.output:
        cmd["output"] = args.output
    if args.fence:
        cmd["fence"] = _parse_addr(args.fence)
    if args.fence_every:
        cmd["fenceEvery"] = args.fence_every

    resp = client.send_command(cmd, timeout=args.duration + 30)
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    print(client.format_collect(resp))


# ── NEW: modules command ───────────────────────────────────────────────────

def cmd_modules(args: argparse.Namespace) -> None:
    if not _require_attached():
        return
    cmd: dict = {"cmd": "modules"}
    if args.filter:
        cmd["filter"] = args.filter
    resp = client.send_command(cmd)
    print(client.format_status_line(resp))
    if not resp.get("ok"):
        print(f"[error] {resp.get('error', 'unknown')}")
        return
    print(client.format_modules(resp))


# ── NEW: dipcnt command ───────────────────────────────────────────────────

def cmd_dipcnt(args: argparse.Namespace) -> None:
    action = getattr(args, "action", None)
    if action == "on":
        dev_ptr = getattr(args, "dev_ptr")
        resp = client.send_command({"cmd": "dipcnt_on", "devPtrAddr": dev_ptr})
        print(client.format_status_line(resp))
        print("DIP counter ON." if resp.get("ok") else f"[error] {resp.get('msg', '?')}")
    elif action == "off":
        resp = client.send_command({"cmd": "dipcnt_off"})
        print(client.format_status_line(resp))
        print("DIP counter OFF." if resp.get("ok") else f"[error] {resp.get('msg', '?')}")
    elif action == "read":
        resp = client.send_command({"cmd": "dipcnt_read"})
        print(client.format_status_line(resp))
        if resp.get("installed"):
            print(f"  Total DIP calls: {resp.get('total', 0)}")
            print(f"  Delta (since last read): {resp.get('delta', 0)}")
        else:
            print("  Not installed.")
    elif action == "callers":
        count = getattr(args, "count", 200)
        resp = client.send_command({"cmd": "dipcnt_callers", "count": count})
        print(client.format_status_line(resp))
        if resp.get("ok"):
            callers = resp.get("callers", [])
            print(f"  Sampled {resp.get('sampled', '?')} DIP calls, {len(callers)} unique callers:")
            for c in callers:
                print(f"    {c['addr']}  x{c['count']}")
        else:
            print(f"  [error] {resp.get('msg', '?')}")
    else:
        print("Usage: python -m livetools dipcnt [on|off|read|callers]")


# ── NEW: analyze command ───────────────────────────────────────────────────

def cmd_analyze(args: argparse.Namespace) -> None:
    from .analyze import run_analyze
    run_analyze(args)


# ── NEW: vishook command ──────────────────────────────────────────────────

def cmd_vishook(args: argparse.Namespace) -> None:
    action = getattr(args, "action", None)
    if action == "on":
        threshold = getattr(args, "threshold")
        jmp_site = getattr(args, "jmp_site")
        orig_target = getattr(args, "orig_target")
        resp = client.send_command({
            "cmd": "vishook_on", "threshold": threshold,
            "jmpSite": jmp_site, "origTarget": orig_target,
        })
        print(client.format_status_line(resp))
        if resp.get("ok"):
            cave = resp.get("cave", "?")
            thr = resp.get("threshold", "?")
            print(f"Visibility override ON.  code-cave @ 0x{cave}")
            print(f"  Callers >= 0x{thr:X}: force visible")
            print(f"  Callers <  0x{thr:X}: call original")
        else:
            print(f"[error] {resp.get('msg', resp.get('error', 'unknown'))}")
    elif action == "off":
        resp = client.send_command({"cmd": "vishook_off"})
        print(client.format_status_line(resp))
        if resp.get("ok"):
            print("Visibility override OFF.  Original jmp restored.")
        else:
            print(f"[error] {resp.get('msg', resp.get('error', 'unknown'))}")
    elif action == "stats":
        resp = client.send_command({"cmd": "vishook_stats"})
        print(client.format_status_line(resp))
        if resp.get("installed"):
            print(f"  Override calls:    {resp.get('overrideCount', 0)}")
            print(f"  Passthrough calls: {resp.get('passthroughCount', 0)}")
        else:
            print("  Not installed.")
    else:
        print("Usage: python -m livetools vishook [on|off|stats]")


# ── NEW: memwatch command ─────────────────────────────────────────────────

def cmd_memwatch(args: argparse.Namespace) -> None:
    action = getattr(args, "action", None)
    if action == "start":
        addr = getattr(args, "addr")
        size = getattr(args, "size", 4)
        max_hits = getattr(args, "max_hits", 20)
        resp = client.send_command({
            "cmd": "memwatch_start", "addr": addr, "size": size, "maxHits": max_hits,
        })
        print(client.format_status_line(resp))
        if resp.get("ok"):
            print(f"Memory write watchpoint active: {resp.get('watching')} ({resp.get('size')} bytes)")
            print(f"  Will capture up to {resp.get('maxHits')} hits, then auto-stop.")
            print("  Use 'python -m livetools memwatch read' to check hits.")
        else:
            print(f"[error] {resp.get('error', '?')}")
    elif action == "stop":
        resp = client.send_command({"cmd": "memwatch_stop"})
        print(client.format_status_line(resp))
        if resp.get("ok"):
            print(f"Watchpoint stopped. {resp.get('hits', 0)} hits captured.")
        else:
            print(f"[error] {resp.get('error', '?')}")
    elif action == "read":
        resp = client.send_command({"cmd": "memwatch_read"})
        print(client.format_status_line(resp))
        if resp.get("ok"):
            hits = resp.get("hits", [])
            print(f"  {len(hits)} write hit(s):")
            for i, h in enumerate(hits):
                print(f"\n  [{i}] Write to {h.get('addr', '?')} from {h.get('from', '?')}")
                bt = h.get("backtrace", [])
                if bt:
                    for j, frame in enumerate(bt):
                        print(f"       bt[{j}]: {frame}")
        else:
            print(f"[error] {resp.get('error', '?')}")
    else:
        print("Usage: python -m livetools memwatch [start|stop|read]")


# ── gamectl command ───────────────────────────────────────────────────────

def cmd_gamectl(args: argparse.Namespace) -> None:
    from . import gamectl as gc
    action = args.gc_action

    hwnd, err = gc.resolve_hwnd(getattr(args, "exe", None),
                                getattr(args, "window", None))
    if action == "info":
        # info doesn't need a valid hwnd to report the error clearly
        if not hwnd:
            print(f"[error] {err}"); return
        info = gc.get_window_info(hwnd)
        print(f"hwnd:  {info['hwnd']}")
        print(f"title: {info['title']}")
        print(f"pid:   {info['pid']}")
        print(f"tid:   {info['tid']}")
        return

    if not hwnd:
        print(f"[error] {err}"); return

    if action == "key":
        focused = gc.focus_hwnd(hwnd)
        r = gc.send_key(args.key_name, hold_ms=args.hold_ms)
        print(f"focused={focused} {r}")

    elif action == "keys":
        r = gc.send_keys(hwnd, args.sequence, delay_ms=args.delay_ms)
        print(f"focused={r['focused']} sent={r['count']} ok={r['ok']}")
        for a in r["actions"]:
            if not a.get("ok", True):
                print(f"  [error] {a}")

    elif action == "click":
        r = gc.click_at(hwnd, args.x, args.y)
        print(r)

    elif action == "macro":
        macros = gc.load_macros(args.macro_file)
        r = gc.run_macro(hwnd, args.macro_name, macros, delay_ms=args.delay_ms)
        if r["ok"]:
            print(f"Macro '{args.macro_name}' done. "
                  f"{r['steps_result']['count']} actions sent.")
        else:
            print(f"[error] {r.get('error', r)}")

    elif action == "macros":
        macros = gc.load_macros(args.macro_file)
        print(f"Macros in {args.macro_file}:")
        for name, defn in sorted(macros.items()):
            print(f"  {name:<24s}  {defn.get('description', '')}")
            print(f"    steps: {defn.get('steps', '')}")

    else:
        print("Usage: python -m livetools gamectl [info|key|keys|click|macro|macros]")


# ── argument parser ────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m livetools",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command")

    # -- session --
    sp = sub.add_parser("attach",
        help="Attach to a running process (starts background daemon)",
        description="Attach to a running process by name or PID. "
                    "Starts a background Frida daemon that stays connected.\n\n"
                    "Example:\n"
                    "  python -m livetools attach game.exe\n"
                    "  python -m livetools attach 12345")
    sp.add_argument("target",
        help="Process name (e.g. game.exe) or PID (e.g. 12345)")

    sub.add_parser("detach",
        help="Detach from the process and stop the daemon")
    sub.add_parser("status",
        help="Show current state: attached process, frozen status, bp count")

    # -- breakpoints --
    sp = sub.add_parser("bp",
        help="Manage breakpoints (add / del / list)")
    bp_sub = sp.add_subparsers(dest="action")
    bp_add = bp_sub.add_parser("add", help="Set a breakpoint at address")
    bp_add.add_argument("addr", help="Code address in hex (e.g. 0x401000)")
    bp_del = bp_sub.add_parser("del", help="Remove a breakpoint")
    bp_del.add_argument("addr", help="Address of breakpoint to remove (hex)")
    bp_sub.add_parser("list", help="List all active breakpoints with hit counts")

    # -- watch --
    sp = sub.add_parser("watch",
        help="Block until a breakpoint is hit, then print snapshot",
        description=(
            "Wait for a breakpoint to be hit, then print a full snapshot.\n\n"
            "NOTE: Some games only execute rendering/logic when their window\n"
            "is focused. If watch times out, make sure the game window is in\n"
            "the foreground."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("--timeout", type=int, default=60,
        help="Seconds to wait before giving up (default: 60)")

    # -- inspection --
    sub.add_parser("regs", help="Print all registers (x86/x64)")
    sp = sub.add_parser("stack", help="Dump stack slots from ESP/RSP")
    sp.add_argument("count", nargs="?", type=int, default=16,
        help="Number of pointer-sized slots (default: 16)")

    sp = sub.add_parser("mem", help="Read or write live process memory")
    mem_sub = sp.add_subparsers(dest="mem_action")
    mr = mem_sub.add_parser("read",
        help="Read N bytes at address (hex dump + type interpretation)")
    mr.add_argument("addr", help="Start address in hex (e.g. 0x401000)")
    mr.add_argument("size", type=int, help="Number of bytes to read")
    mr.add_argument("--as", dest="type", default=None,
        choices=["float32", "float64", "half", "uint8", "int8", "uint16",
                 "int16", "uint32", "int32", "ptr", "ascii", "utf16"],
        help="Interpret bytes as a specific type")
    mw = mem_sub.add_parser("write", help="Write hex bytes to address")
    mw.add_argument("addr", help="Target address in hex")
    mw.add_argument("hex_bytes", help="Hex bytes (e.g. '90 90 90' or 'B001C3')")
    ma = mem_sub.add_parser("alloc", help="Allocate rwx memory in target process")
    ma.add_argument("size", type=int, help="Number of bytes to allocate")

    sp = sub.add_parser("disasm",
        help="Disassemble instructions at address (default: current EIP/RIP)")
    sp.add_argument("addr", nargs="?", default=None, help="Start address in hex")
    sp.add_argument("-n", "--count", type=int, default=16,
        help="Number of instructions (default: 16)")

    sub.add_parser("bt", help="Print stack backtrace")

    # -- control --
    sp = sub.add_parser("step",
        help="Single-step one instruction (must be frozen at a bp)")
    sp.add_argument("mode", nargs="?", default="over",
        choices=["over", "into", "out"],
        help="'over' skips calls, 'into' enters, 'out' runs to return (default: over)")

    sub.add_parser("resume", help="Resume execution (unfreeze from breakpoint)")

    # -- scan --
    sp = sub.add_parser("scan", help="Scan process memory for a byte pattern")
    sp.add_argument("pattern", help="Hex byte pattern (e.g. '00 00 80 3F')")
    sp.add_argument("--range", default=None,
        help="Restrict scan to START:SIZE (e.g. 0x400000:0x100000)")

    # -- trace --
    sp = sub.add_parser("trace",
        help="Non-blocking function enter/leave tracing with data capture",
        description=(
            "Hook a function's entry and exit without freezing the target.\n"
            "Reads specified data at each call, returns structured results.\n\n"
            "Read spec format (semicolon-separated):\n"
            "  register:       ecx, eax, ebp, ...\n"
            "  memory:         [reg+OFFSET]:SIZE:TYPE\n"
            "  double-deref:   *[reg+OFFSET]:SIZE:TYPE\n"
            "  Types: hex, float32, float64, uint32, int32, uint16, int16,\n"
            "         uint8, int8, ascii, utf16, ptr\n\n"
            "Filter format:\n"
            "  [esp+8]==0x2  |  eax!=0  |  [ecx+0x54]:4:float32>0.5\n\n"
            "Examples:\n"
            "  python -m livetools trace 0x401000 --count 10 "
            '--read "ecx; [esp+4]:12:float32"\n'
            "  python -m livetools trace 0x402000 --count 5 "
            '--filter "[esp+8]==0x2" --read "[esp+c]:64:float32"\n'
            "  python -m livetools trace 0x403000 --count 20 "
            '--read "ecx; [esp+4]:12:float32" --read-leave "eax"\n\n'
            "NOTE: Some games only execute rendering/logic when their window\n"
            "is focused. If trace times out with 0 samples, alt-tab to the\n"
            "game before running."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("addr", help="Function address to hook (hex)")
    sp.add_argument("--count", type=int, default=10,
        help="Number of calls to capture (default: 10)")
    sp.add_argument("--read", default=None,
        help='Read spec for function entry (e.g. "ecx; [esp+4]:12:float32")')
    sp.add_argument("--read-leave", default=None,
        help='Read spec for function exit (e.g. "eax; st0")')
    sp.add_argument("--filter", default=None,
        help='Filter expression (e.g. "[esp+8]==0x2")')
    sp.add_argument("--timeout", type=int, default=30,
        help="Max seconds to wait for all samples (default: 30)")
    sp.add_argument("--output", default=None,
        help="Write samples to JSONL file (default: stdout only)")

    # -- steptrace --
    sp = sub.add_parser("steptrace",
        help="Instruction-level execution recording via Stalker",
        description=(
            "Record every instruction executed from function entry through\n"
            "return (or a configurable limit). Uses Frida Stalker for real-time\n"
            "instruction-level tracing.\n\n"
            "Detail levels:\n"
            "  full      Every instruction + register snapshots at calls/rets\n"
            "  branches  All instructions logged, regs at branches (default)\n"
            "  blocks    Only instruction addresses, cheapest\n\n"
            "Examples:\n"
            "  python -m livetools steptrace 0x403000 "
            "--max-insn 500 --call-depth 1 --detail full\n"
            "  python -m livetools steptrace 0x401000 "
            "--max-insn 1000 --detail branches\n"
            "  python -m livetools steptrace 0x402000 "
            "--max-insn 5000 --detail blocks\n\n"
            "NOTE: Some games only execute rendering/logic when their window\n"
            "is focused. If steptrace times out with 0 instructions, alt-tab\n"
            "to the game before running."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("addr", help="Function address to trace (hex)")
    sp.add_argument("--max-insn", type=int, default=1000,
        help="Max instructions to record before stopping (default: 1000)")
    sp.add_argument("--call-depth", type=int, default=0,
        help="How many call levels to follow into (default: 0 = entry only)")
    sp.add_argument("--detail", default="branches",
        choices=["full", "branches", "blocks"],
        help="Detail level: full|branches|blocks (default: branches)")
    sp.add_argument("--timeout", type=int, default=30,
        help="Max seconds to wait (default: 30)")
    sp.add_argument("--output", default=None,
        help="Write trace to JSONL file")

    # -- collect --
    sp = sub.add_parser("collect",
        help="Long-running multi-function data collection with intervals",
        description=(
            "Collect data from one or more functions over a duration.\n"
            "Optionally partition records into intervals via fence hooks.\n\n"
            "The fence concept:\n"
            "  --fence ADDR   Hook a boundary function (e.g. DX Present) that\n"
            "                 increments an interval counter. Every trace record\n"
            "                 includes the current interval ID, enabling per-frame\n"
            "                 or per-N-calls analysis.\n\n"
            "Output: JSONL file in patches/<exe>/traces/ by default.\n\n"
            "Examples:\n"
            "  python -m livetools collect 0x401000 0x402000 "
            "--duration 30 --output trace.jsonl "
            '--read "ecx; [esp+4]:12:float32" '
            "--fence 0x403000 "
            "--label 0x401000=FuncA --label 0x402000=FuncB\n\n"
            "  python -m livetools collect 0x401000 "
            "--duration 20 --fence-every 100 --output output.jsonl\n\n"
            "  python -m livetools collect 0x401000 0x402000 "
            '--read@0x401000="ecx; [esp+4]:12:float32" '
            '--read@0x402000="ecx; [esp+4]:28:hex" '
            "--duration 15 --output multi.jsonl\n\n"
            "NOTE: Some games only execute rendering/logic when their window\n"
            "is focused. If collect finishes with 0 records, alt-tab to the\n"
            "game before running."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("addrs", nargs="+",
        help="One or more function addresses to hook (hex)")
    sp.add_argument("--duration", type=int, default=10,
        help="Collection duration in seconds (default: 10)")
    sp.add_argument("--max-records", type=int, default=0,
        help="Stop after N total records (default: unlimited)")
    sp.add_argument("--output", default=None,
        help="Output JSONL file path (default: auto-generated)")
    sp.add_argument("--read", default=None,
        help='Read spec applied to all hooks (e.g. "ecx; [esp+4]:12:float32")')
    sp.add_argument("--read@", dest="read_at", action="append", default=None,
        help='Per-address read spec: ADDR=SPEC (e.g. 0x401000="ecx; [esp+4]:12:float32")')
    sp.add_argument("--fence", default=None,
        help="Address of fence function for interval marking (e.g. DX Present)")
    sp.add_argument("--fence-every", type=int, default=0,
        help="Mark interval every N calls to first traced addr")
    sp.add_argument("--label", action="append", default=None,
        help="Human label: ADDR=NAME (e.g. 0x401000=FuncA)")

    # -- modules --
    sp = sub.add_parser("modules",
        help="List loaded DLLs with base addresses and sizes",
        description=(
            "Enumerate all loaded modules (DLLs) in the target process.\n"
            "Useful for finding DLL bases for vtable hooks.\n\n"
            "Examples:\n"
            "  python -m livetools modules\n"
            "  python -m livetools modules --filter d3d\n"
            "  python -m livetools modules --filter kernel"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("--filter", default=None,
        help="Case-insensitive substring filter on module name/path")

    # -- vishook --
    sp = sub.add_parser("vishook",
        help="Selective visibility override via code cave on a jmp trampoline",
        description=(
            "Patches a jmp trampoline to route through a code cave that\n"
            "selectively forces 'visible' for callers above a threshold\n"
            "address while letting callers below run the original function.\n\n"
            "Designed for __thiscall functions that return float on st(0)\n"
            "with ret 0x10 (4 stack args) and an optional byte output in\n"
            "[esp+0x10].\n\n"
            "Uses a code cave that checks the return address:\n"
            "  >= threshold  → force visible (float=102400.0, byte=1)\n"
            "  <  threshold  → call original function\n\n"
            "Examples:\n"
            "  python -m livetools vishook on 0x401000 0x402000\n"
            "  python -m livetools vishook on 0x401000 0x402000 --threshold 560000\n"
            "  python -m livetools vishook stats\n"
            "  python -m livetools vishook off"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    vhsub = sp.add_subparsers(dest="action")
    vhon = vhsub.add_parser("on", help="Enable selective visibility override")
    vhon.add_argument("jmp_site",
        help="Address of the jmp trampoline to patch (hex)")
    vhon.add_argument("orig_target",
        help="Address of the original target function (hex)")
    vhon.add_argument("--threshold", default="500000",
        help="Hex address threshold (default: 500000). "
             "Callers >= this get forced visible.")
    vhsub.add_parser("off", help="Disable override, restore original jmp")
    vhsub.add_parser("stats", help="Show override/passthrough call counts")

    # -- dipcnt --
    sp = sub.add_parser("dipcnt",
        help="Count DrawIndexedPrimitive calls (D3D9 vtable hook)")
    dc_sub = sp.add_subparsers(dest="action")
    dc_on = dc_sub.add_parser("on", help="Start counting DIP calls")
    dc_on.add_argument("dev_ptr",
        help="Address of the global IDirect3DDevice9* pointer (hex)")
    dc_sub.add_parser("off", help="Stop counting")
    dc_sub.add_parser("read", help="Read current count + delta since last read")
    cal_p = dc_sub.add_parser("callers", help="Sample N DIP calls and show caller histogram")
    cal_p.add_argument("count", nargs="?", type=int, default=200, help="Number of calls to sample (default 200)")

    # -- memwatch --
    sp = sub.add_parser("memwatch",
        help="Hardware memory write watchpoint (catch who writes to an address)",
        description=(
            "Set a memory write watchpoint on a specific address range.\n"
            "Uses Frida's MemoryAccessMonitor to detect writes, capturing\n"
            "the instruction pointer and backtrace for each hit.\n\n"
            "Examples:\n"
            "  python -m livetools memwatch start 0x7A0000 --size 48\n"
            "  python -m livetools memwatch read\n"
            "  python -m livetools memwatch stop"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    mw_sub = sp.add_subparsers(dest="action")
    mw_start = mw_sub.add_parser("start", help="Start watching an address for writes")
    mw_start.add_argument("addr", help="Address to watch (hex, e.g. 0x7A0000)")
    mw_start.add_argument("--size", type=int, default=4,
        help="Number of bytes to watch (default: 4)")
    mw_start.add_argument("--max-hits", type=int, default=20,
        help="Auto-stop after N hits (default: 20)")
    mw_sub.add_parser("stop", help="Stop the active watchpoint")
    mw_sub.add_parser("read", help="Read captured hits")

    # -- analyze --
    sp = sub.add_parser("analyze",
        help="Offline JSONL aggregation and query (no Frida needed)",
        description=(
            "Pure Python offline analysis of JSONL files produced by\n"
            "'collect' or 'trace --output'. Provides deterministic,\n"
            "non-hallucinated aggregation and filtering.\n\n"
            "Field path syntax: dot-separated with array indices.\n"
            "  enter.reads.0.value.0  = first read spec's first value\n"
            "  leave.eax              = EAX at function exit\n"
            "  addr                   = hooked address\n"
            "  interval               = fence counter value\n\n"
            "Examples:\n"
            "  python -m livetools analyze trace.jsonl --summary\n"
            "  python -m livetools analyze trace.jsonl --group-by addr\n"
            "  python -m livetools analyze trace.jsonl "
            '--filter "addr==00401000" --group-by "leave.eax"\n'
            "  python -m livetools analyze trace.jsonl "
            '--filter "addr==00401000" --cross-tab caller leave.eax\n'
            "  python -m livetools analyze trace.jsonl "
            "--group-by interval --top 5\n"
            "  python -m livetools analyze trace.jsonl --interval 47\n"
            "  python -m livetools analyze trace.jsonl "
            "--compare-intervals 10 50\n"
            "  python -m livetools analyze trace.jsonl "
            '--filter "addr==00401000" --histogram "enter.reads.0.value.0"\n'
            "  python -m livetools analyze trace.jsonl "
            '--filter "addr==00401000" --export-csv output.csv'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("file", help="Path to JSONL file")
    sp.add_argument("--summary", action="store_true",
        help="Show record count, unique addrs, interval count, time span")
    sp.add_argument("--group-by", default=None,
        help="Group records by a field path and show distribution")
    sp.add_argument("--filter", default=None,
        help='Keep only records matching expression (e.g. "addr==005E72E0")')
    sp.add_argument("--cross-tab", nargs=2, default=None, metavar=("F1", "F2"),
        help="Cross-tabulate two fields")
    sp.add_argument("--top", type=int, default=20,
        help="Show top N groups (default: 20)")
    sp.add_argument("--interval", type=int, default=None,
        help="Show detail for a specific interval number")
    sp.add_argument("--intervals", default=None,
        help="Show records for interval range N:M")
    sp.add_argument("--compare-intervals", nargs=2, type=int, default=None,
        metavar=("A", "B"),
        help="Diff two intervals side by side")
    sp.add_argument("--histogram", default=None,
        help="Show value distribution histogram for a field path")
    sp.add_argument("--export-csv", default=None,
        help="Export filtered/grouped data as CSV to file")

    # -- gamectl --
    sp = sub.add_parser("gamectl",
        help="Send keystrokes/mouse clicks directly to a game window (no Frida, no focus needed)",
        description=(
            "Posts WM_KEYDOWN/WM_KEYUP directly to the target window handle.\n"
            "No focus stealing — works even when the game is in the background.\n\n"
            "Window lookup (pick one):\n"
            "  --exe game.exe      find window by process exe name (recommended)\n"
            "  --window <hint>     find window by title substring\n\n"
            "Key names: RETURN, ESCAPE, SPACE, UP, DOWN, LEFT, RIGHT,\n"
            "           TAB, F1-F12, A-Z, 0-9, NUMPAD0-9, SHIFT, CTRL, ALT\n\n"
            "Sequence token syntax:\n"
            "  KEY_NAME          — keydown + keyup\n"
            "  WAIT:N            — pause N milliseconds\n"
            "  HOLD:KEY_NAME:N   — hold key N ms before keyup\n\n"
            "Examples:\n"
            "  python -m livetools gamectl --exe revolt_xbox.exe info\n"
            "  python -m livetools gamectl --exe revolt_xbox.exe key RETURN\n"
            "  python -m livetools gamectl --exe revolt_xbox.exe keys \"DOWN DOWN RETURN\"\n"
            "  python -m livetools gamectl --exe revolt_xbox.exe keys "
            "\"RETURN WAIT:1000 RETURN WAIT:1000 RETURN\" --delay-ms 0\n"
            "  python -m livetools gamectl --exe revolt_xbox.exe click 400 300\n"
            "  python -m livetools gamectl --exe revolt_xbox.exe macro "
            "--macro-file patches/revolt/macros.json navigate_menu"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("--exe", "-e", default=None,
        help="Target process exe name (e.g. revolt_xbox.exe) — preferred over --window")
    sp.add_argument("--window", "-w", default=None,
        help="Window title substring fallback (case-insensitive)")
    gc_sub = sp.add_subparsers(dest="gc_action")

    gc_sub.add_parser("info", help="Show hwnd, title, pid for the matched window")

    gc_key = gc_sub.add_parser("key", help="Send a single key press")
    gc_key.add_argument("key_name", help="Key name (e.g. RETURN, UP, F5, A)")
    gc_key.add_argument("--hold-ms", type=int, default=50,
        help="Hold duration in ms (default: 50)")

    gc_keys = gc_sub.add_parser("keys", help="Send a space-separated key sequence")
    gc_keys.add_argument("sequence",
        help='e.g. "DOWN DOWN RETURN" or "RETURN WAIT:1000 RETURN"')
    gc_keys.add_argument("--delay-ms", type=int, default=200,
        help="Delay between keys in ms (default: 200)")

    gc_click = gc_sub.add_parser("click", help="Post left-click at client-area coordinates")
    gc_click.add_argument("x", type=int, help="Client X coordinate")
    gc_click.add_argument("y", type=int, help="Client Y coordinate")

    gc_macro = gc_sub.add_parser("macro", help="Run a named macro from a JSON file")
    gc_macro.add_argument("macro_name", help="Macro name to execute")
    gc_macro.add_argument("--macro-file", default="macros.json",
        help="Path to macro JSON file (default: macros.json)")
    gc_macro.add_argument("--delay-ms", type=int, default=200,
        help="Delay between keys in ms (default: 200)")

    gc_macros = gc_sub.add_parser("macros", help="List all macros in a JSON file")
    gc_macros.add_argument("--macro-file", default="macros.json",
        help="Path to macro JSON file (default: macros.json)")

    return p


# ── main ───────────────────────────────────────────────────────────────────

def main() -> None:
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    dispatch = {
        "attach": cmd_attach,
        "detach": cmd_detach,
        "status": cmd_status,
        "bp": cmd_bp,
        "watch": cmd_watch,
        "regs": cmd_regs,
        "stack": cmd_stack,
        "mem": lambda a: cmd_mem_read(a) if getattr(a, "mem_action", None) == "read"
                         else cmd_mem_write(a) if getattr(a, "mem_action", None) == "write"
                         else cmd_mem_alloc(a) if getattr(a, "mem_action", None) == "alloc"
                         else print("Usage: python -m livetools mem [read|write|alloc]"),
        "disasm": cmd_disasm,
        "bt": cmd_bt,
        "step": cmd_step,
        "resume": cmd_resume,
        "scan": cmd_scan,
        "trace": cmd_trace,
        "steptrace": cmd_steptrace,
        "collect": cmd_collect,
        "modules": cmd_modules,
        "vishook": cmd_vishook,
        "dipcnt": cmd_dipcnt,
        "memwatch": cmd_memwatch,
        "analyze": cmd_analyze,
        "gamectl": cmd_gamectl,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
