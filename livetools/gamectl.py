"""Game window input automation via SendInput with proper focus management.

Re-Volt and most older DX9/DirectInput games read raw device state — they
ignore WM_KEYDOWN/PostMessage entirely. SendInput is required, but the game
window must be in the foreground first.

Focus strategy: attach our thread to the game's input queue via
AttachThreadInput, then SetForegroundWindow. This bypasses the Windows
foreground-lock that normally blocks background processes from stealing focus.

Window lookup supports two modes:
  --exe    <exe_name>     find window by process exe name (recommended)
  --window <title_hint>   find window by title substring fallback

Usage (CLI):
    python -m livetools gamectl --exe revolt_xbox.exe info
    python -m livetools gamectl --exe revolt_xbox.exe key RETURN
    python -m livetools gamectl --exe revolt_xbox.exe keys "DOWN DOWN RETURN"
    python -m livetools gamectl --exe revolt_xbox.exe keys "RETURN WAIT:1000 RETURN" --delay-ms 0
    python -m livetools gamectl --exe revolt_xbox.exe click 400 300
    python -m livetools gamectl --exe revolt_xbox.exe macro --macro-file patches/revolt/macros.json navigate_menu
    python -m livetools gamectl --exe revolt_xbox.exe macros --macro-file patches/revolt/macros.json

Usage (library):
    from livetools.gamectl import find_hwnd_by_exe, focus_hwnd, send_key, send_keys
    hwnd = find_hwnd_by_exe("revolt_xbox.exe")
    focus_hwnd(hwnd)
    send_key("RETURN")
    send_keys("DOWN DOWN RETURN", delay_ms=200)

Macro file format (JSON) — store at patches/<GameName>/macros.json:
    {
      "navigate_menu": {
        "description": "Navigate from title screen into a race",
        "steps": "RETURN WAIT:1000 DOWN DOWN RETURN WAIT:500 RETURN"
      }
    }
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import time
from pathlib import Path

# ── Win32 constants ────────────────────────────────────────────────────────

INPUT_KEYBOARD       = 1
INPUT_MOUSE          = 0
KEYEVENTF_KEYUP      = 0x0002
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP   = 0x0004
SW_RESTORE           = 9
SW_SHOW              = 5
GW_OWNER             = 4
TH32CS_SNAPPROCESS   = 0x00000002

user32   = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# ── Virtual key map ────────────────────────────────────────────────────────

VK_MAP: dict[str, int] = {
    "RETURN": 0x0D, "ENTER": 0x0D,
    "ESCAPE": 0x1B, "ESC": 0x1B,
    "SPACE": 0x20,
    "UP": 0x26, "DOWN": 0x28, "LEFT": 0x25, "RIGHT": 0x27,
    "TAB": 0x09, "BACKSPACE": 0x08, "DELETE": 0x2E,
    "HOME": 0x24, "END": 0x23, "PAGEUP": 0x21, "PAGEDOWN": 0x22,
    "F1": 0x70, "F2": 0x71, "F3": 0x72,  "F4": 0x73,
    "F5": 0x74, "F6": 0x75, "F7": 0x76,  "F8": 0x77,
    "F9": 0x78, "F10": 0x79, "F11": 0x7A, "F12": 0x7B,
    "SHIFT": 0x10, "CTRL": 0x11, "ALT": 0x12,
    **{c: 0x41 + i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")},
    **{str(d): 0x30 + d for d in range(10)},
    "NUMPAD0": 0x60, "NUMPAD1": 0x61, "NUMPAD2": 0x62, "NUMPAD3": 0x63,
    "NUMPAD4": 0x64, "NUMPAD5": 0x65, "NUMPAD6": 0x66, "NUMPAD7": 0x67,
    "NUMPAD8": 0x68, "NUMPAD9": 0x69,
}

# ── SendInput structures ───────────────────────────────────────────────────

class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk",         wt.WORD),
        ("wScan",       wt.WORD),
        ("dwFlags",     wt.DWORD),
        ("time",        wt.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]

class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx",          wt.LONG),
        ("dy",          wt.LONG),
        ("mouseData",   wt.DWORD),
        ("dwFlags",     wt.DWORD),
        ("time",        wt.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]

class _INPUT_UNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT)]

class INPUT(ctypes.Structure):
    _fields_ = [("type", wt.DWORD), ("union", _INPUT_UNION)]

WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wt.DWORD),
        ("cntUsage",            wt.DWORD),
        ("th32ProcessID",       wt.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        wt.DWORD),
        ("cntThreads",          wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wt.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]


def _find_pid(exe_name: str) -> int | None:
    """Return the PID of the first process whose exe matches exe_name."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value:
        return None
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    try:
        if not kernel32.Process32First(snap, ctypes.byref(entry)):
            return None
        while True:
            name = entry.szExeFile.decode("utf-8", errors="replace")
            if name.lower() == exe_name.lower():
                return entry.th32ProcessID
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return None

# ── Window lookup ──────────────────────────────────────────────────────────

WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def find_hwnd_by_exe(exe_name: str) -> int | None:
    """Find the main visible window of a process by its exe filename.

    Args:
        exe_name: Process exe name, e.g. "revolt_xbox.exe"

    Returns:
        Window handle (int) or None if not found.
    """
    pid = _find_pid(exe_name)
    if pid is None:
        return None
    result: list[int] = []

    @WNDENUMPROC
    def _cb(hwnd: int, _: int) -> bool:
        if not user32.IsWindowVisible(hwnd):
            return True
        if user32.GetWindow(hwnd, GW_OWNER) != 0:
            return True
        proc_id = wt.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc_id))
        if proc_id.value == pid:
            result.append(hwnd)
        return True

    user32.EnumWindows(_cb, 0)
    return result[0] if result else None


def find_hwnd_by_title(title_hint: str) -> int | None:
    """Find the first visible top-level window whose title contains title_hint."""
    result: list[int] = []

    @WNDENUMPROC
    def _cb(hwnd: int, _: int) -> bool:
        if not user32.IsWindowVisible(hwnd):
            return True
        if user32.GetWindow(hwnd, GW_OWNER) != 0:
            return True
        buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, buf, 256)
        if buf.value and title_hint.lower() in buf.value.lower():
            result.append(hwnd)
        return True

    user32.EnumWindows(_cb, 0)
    return result[0] if result else None


def resolve_hwnd(exe: str | None, window: str | None) -> tuple[int | None, str]:
    """Resolve hwnd from --exe or --window, return (hwnd, error_msg)."""
    if exe:
        hwnd = find_hwnd_by_exe(exe)
        if not hwnd:
            return None, f"No window found for process '{exe}'"
        return hwnd, ""
    if window:
        hwnd = find_hwnd_by_title(window)
        if not hwnd:
            return None, f"No window found matching title '{window}'"
        return hwnd, ""
    return None, "Provide --exe <game.exe> or --window <title>"


def get_window_info(hwnd: int) -> dict:
    """Return title and process info for a hwnd."""
    buf = ctypes.create_unicode_buffer(256)
    user32.GetWindowTextW(hwnd, buf, 256)
    pid = wt.DWORD(0)
    tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return {"hwnd": hwnd, "title": buf.value, "pid": pid.value, "tid": tid}

# ── Focus management ───────────────────────────────────────────────────────

def focus_hwnd(hwnd: int) -> bool:
    """Force hwnd to the foreground using AttachThreadInput.

    DirectInput games only process keys when their window is the foreground
    window. This attaches our thread to the game's input queue so
    SetForegroundWindow is not blocked by the Windows foreground lock.

    Returns True if the window is in the foreground after the call.
    """
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, SW_RESTORE)
        time.sleep(0.3)

    my_tid  = kernel32.GetCurrentThreadId()
    fg_hwnd = user32.GetForegroundWindow()
    fg_tid  = user32.GetWindowThreadProcessId(fg_hwnd, None)

    if fg_tid and fg_tid != my_tid:
        user32.AttachThreadInput(my_tid, fg_tid, True)
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
        user32.AttachThreadInput(my_tid, fg_tid, False)
    else:
        user32.SetForegroundWindow(hwnd)

    time.sleep(0.15)
    return user32.GetForegroundWindow() == hwnd

# ── SendInput keyboard ─────────────────────────────────────────────────────

def _make_key_input(vk: int, up: bool = False) -> INPUT:
    inp = INPUT()
    inp.type = INPUT_KEYBOARD
    inp.union.ki.wVk   = vk
    inp.union.ki.wScan = user32.MapVirtualKeyW(vk, 0)
    inp.union.ki.dwFlags = KEYEVENTF_KEYUP if up else 0
    inp.union.ki.time = 0
    inp.union.ki.dwExtraInfo = None
    return inp


def send_key(key_name: str, hold_ms: int = 50) -> dict:
    """Send a single key press via SendInput (game must be foreground).

    Args:
        key_name: Key name from VK_MAP (e.g. "RETURN", "UP", "A", "F5").
        hold_ms:  Delay between keydown and keyup in milliseconds.

    Returns:
        dict with ok, key, vk
    """
    vk = VK_MAP.get(key_name.upper())
    if vk is None:
        return {"ok": False, "error": f"Unknown key: '{key_name}'. "
                f"Valid: {', '.join(sorted(VK_MAP))}"}
    dn = (INPUT * 1)(_make_key_input(vk, up=False))
    user32.SendInput(1, dn, ctypes.sizeof(INPUT))
    time.sleep(hold_ms / 1000.0)
    up = (INPUT * 1)(_make_key_input(vk, up=True))
    user32.SendInput(1, up, ctypes.sizeof(INPUT))
    return {"ok": True, "key": key_name, "vk": hex(vk)}


def send_keys(hwnd: int, sequence: str, delay_ms: int = 200) -> dict:
    """Focus hwnd then send a space-separated key sequence via SendInput.

    Token syntax:
        KEY_NAME          — keydown + keyup
        WAIT:N            — pause N milliseconds
        HOLD:KEY_NAME:N   — hold key N ms before keyup

    Args:
        hwnd:      Target window handle (will be focused before sending).
        sequence:  Space-separated token string.
        delay_ms:  Default inter-key delay in milliseconds.

    Returns:
        dict with ok, count, actions
    """
    focused = focus_hwnd(hwnd)
    if not focused:
        # Still try — some games accept input even if focus check is unreliable
        pass

    actions: list[dict] = []
    for token in sequence.strip().split():
        upper = token.upper()
        if upper.startswith("WAIT:"):
            ms = int(token.split(":")[1])
            time.sleep(ms / 1000.0)
            actions.append({"action": "wait", "ms": ms})
        elif upper.startswith("HOLD:"):
            parts = token.split(":")
            key = parts[1]
            ms  = int(parts[2]) if len(parts) > 2 else 500
            r   = send_key(key, hold_ms=ms)
            actions.append({**r, "action": "hold", "hold_ms": ms})
            time.sleep(delay_ms / 1000.0)
        else:
            r = send_key(token)
            actions.append(r)
            time.sleep(delay_ms / 1000.0)
    return {"ok": True, "focused": focused, "count": len(actions), "actions": actions}

# ── Mouse input ────────────────────────────────────────────────────────────

def click_at(hwnd: int, x: int, y: int) -> dict:
    """Focus hwnd then left-click at client-area coordinates via SendInput.

    Args:
        hwnd: Target window handle.
        x, y: Client-area coordinates.

    Returns:
        dict with ok, screen_x, screen_y
    """
    focus_hwnd(hwnd)
    pt = wt.POINT(x, y)
    user32.ClientToScreen(hwnd, ctypes.byref(pt))
    user32.SetCursorPos(pt.x, pt.y)
    time.sleep(0.05)

    dn = INPUT(); dn.type = INPUT_MOUSE; dn.union.mi.dwFlags = MOUSEEVENTF_LEFTDOWN
    up = INPUT(); up.type = INPUT_MOUSE; up.union.mi.dwFlags = MOUSEEVENTF_LEFTUP
    arr = (INPUT * 2)(dn, up)
    user32.SendInput(2, arr, ctypes.sizeof(INPUT))
    return {"ok": True, "screen_x": pt.x, "screen_y": pt.y, "client_x": x, "client_y": y}

# ── Macro support ──────────────────────────────────────────────────────────

def load_macros(path: str | Path) -> dict[str, dict]:
    """Load a macro JSON file.

    Args:
        path: Path to JSON file mapping name -> {description, steps}.

    Returns:
        dict of macro definitions.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Macro file not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Macro file must be a JSON object")
    return data


def run_macro(hwnd: int, name: str, macros: dict[str, dict],
              delay_ms: int = 200) -> dict:
    """Focus hwnd and execute a named macro.

    Args:
        hwnd:      Target window handle.
        name:      Macro name key.
        macros:    Loaded macro definitions.
        delay_ms:  Inter-key delay in milliseconds.

    Returns:
        dict with ok, macro, steps_result
    """
    if name not in macros:
        return {"ok": False,
                "error": f"Macro '{name}' not found. "
                         f"Available: {', '.join(sorted(macros))}"}
    steps = macros[name].get("steps", "")
    if not steps:
        return {"ok": False, "error": f"Macro '{name}' has no steps"}
    result = send_keys(hwnd, steps, delay_ms=delay_ms)
    return {"ok": result["ok"], "macro": name, "steps_result": result}
