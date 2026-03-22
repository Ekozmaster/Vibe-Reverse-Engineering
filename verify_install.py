"""Smoke-test that all RE toolkit dependencies are installed and usable."""

import importlib
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
R2_DIR = next(ROOT.glob("tools/radare2-*/bin"), None)
PASS, FAIL, WARN = "PASS", "FAIL", "WARN"
results: list[tuple[str, str, str]] = []


def record(name: str, status: str, detail: str = ""):
    results.append((name, status, detail))
    tag = {"PASS": "+", "FAIL": "!", "WARN": "~"}[status]
    msg = f"  [{tag}] {name}"
    if detail:
        msg += f" -- {detail}"
    print(msg)


def check_lfs():
    if R2_DIR is None:
        record("git-lfs", FAIL, "tools/radare2-*/bin/ not found")
        return
    exe = R2_DIR / "radare2.exe"
    if not exe.exists():
        record("git-lfs", FAIL, f"{exe.relative_to(ROOT)} missing")
        return
    header = exe.read_bytes()[:4]
    if header[:2] == b"MZ":
        record("git-lfs", PASS, f"{exe.relative_to(ROOT)} is a real PE")
    elif header.startswith(b"vers"):
        record("git-lfs", FAIL,
               "radare2.exe is an LFS pointer stub -- run: git lfs pull")
    else:
        record("git-lfs", WARN,
               f"unexpected header {header!r}, may still work")


def check_python_deps():
    libs = {
        "pefile":   "pefile",
        "capstone": "capstone",
        "r2pipe":   "r2pipe",
        "frida":    "frida",
        "minidump": "minidump",
    }
    for name, mod in libs.items():
        try:
            m = importlib.import_module(mod)
            ver = getattr(m, "__version__", getattr(m, "VERSION", "?"))
            record(f"pip:{name}", PASS, f"v{ver}")
        except ImportError as e:
            record(f"pip:{name}", FAIL, str(e))


def check_r2_runs():
    if R2_DIR is None:
        record("r2-exec", FAIL, "radare2 dir not found")
        return
    exe = R2_DIR / "radare2.exe"
    try:
        out = subprocess.check_output(
            [str(exe), "-v"], stderr=subprocess.STDOUT, timeout=10
        )
        first_line = out.decode(errors="replace").split("\n")[0].strip()
        record("r2-exec", PASS, first_line)
    except Exception as e:
        record("r2-exec", FAIL, str(e))


def check_r2ghidra():
    if R2_DIR is None:
        record("r2ghidra", FAIL, "radare2 dir not found")
        return
    sleigh = R2_DIR.parent / "share" / "r2ghidra_sleigh"
    if sleigh.is_dir() and any(sleigh.glob("*.slaspec")):
        record("r2ghidra", PASS,
               f"{len(list(sleigh.glob('*.slaspec')))} arch specs")
    else:
        record("r2ghidra", FAIL,
               "r2ghidra_sleigh/ missing or empty -- run: git lfs pull")


def check_sigdb():
    db_path = ROOT / "retools" / "data" / "signatures.db"
    if db_path.is_file() and db_path.stat().st_size > 1024:
        record("sigdb", PASS,
               f"signatures.db ({db_path.stat().st_size:,} bytes)")
    else:
        record("sigdb", WARN,
               "signatures.db missing or empty -- run: python retools/sigdb.py pull")


def check_retools_import():
    modules = [
        "retools.common", "retools.decompiler", "retools.disasm",
        "retools.funcinfo", "retools.cfg", "retools.callgraph",
        "retools.xrefs", "retools.datarefs", "retools.structrefs",
        "retools.vtable", "retools.rtti", "retools.search",
        "retools.readmem", "retools.dumpinfo", "retools.throwmap",
        "retools.asi_patcher",
    ]
    ok, bad = 0, []
    for mod in modules:
        try:
            importlib.import_module(mod)
            ok += 1
        except Exception as e:
            bad.append(f"{mod}: {e}")
    if not bad:
        record("retools", PASS, f"all {ok} modules import clean")
    else:
        for msg in bad:
            record("retools", FAIL, msg)


def main():
    print("RE Toolkit Install Verification\n")
    check_lfs()
    check_r2ghidra()
    check_python_deps()
    check_r2_runs()
    check_retools_import()
    check_sigdb()

    failures = sum(1 for _, s, _ in results if s == FAIL)
    print()
    if failures:
        print(f"FAILED: {failures} check(s) did not pass.")
        print("Fix the above issues before using the toolkit.")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED.")


if __name__ == "__main__":
    main()
