"""Smoke-test that all RE toolkit dependencies are installed and usable.

Usage:
    python verify_install.py              # check only
    python verify_install.py --setup      # check + auto-install missing optional deps (Ghidra, JDK, pyghidra)
"""

import importlib
import io
import os
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
TOOLS_DIR = ROOT / "tools"
R2_DIR = next(ROOT.glob("tools/radare2-*/bin"), None)
PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
results: list[tuple[str, str, str]] = []

GHIDRA_VERSION = "11.4.3"
GHIDRA_DATE = "20251203"
GHIDRA_ZIP = f"ghidra_{GHIDRA_VERSION}_PUBLIC_{GHIDRA_DATE}.zip"
GHIDRA_URL = f"https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_{GHIDRA_VERSION}_build/{GHIDRA_ZIP}"
GHIDRA_DIR_NAME = f"ghidra_{GHIDRA_VERSION}_PUBLIC"
JDK_VERSION = "21"
JDK_ADOPTIUM_URL = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse"


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


def check_java() -> bool:
    """Check for JDK 21+. Returns True if found."""
    try:
        out = subprocess.check_output(
            ["java", "-version"], stderr=subprocess.STDOUT, timeout=10
        ).decode(errors="replace")
        first = out.strip().split("\n")[0]
        record("java", PASS, first)
        return True
    except FileNotFoundError:
        record("java", WARN, "java not found -- required for pyghidra/Ghidra backend")
        return False
    except Exception as e:
        record("java", WARN, f"java check failed: {e}")
        return False


def _find_ghidra_dir() -> Path | None:
    """Find Ghidra installation: env var first, then tools/ directory."""
    env = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if env and Path(env).is_dir():
        return Path(env)
    candidate = TOOLS_DIR / GHIDRA_DIR_NAME
    if candidate.is_dir():
        return candidate
    for d in sorted(TOOLS_DIR.glob("ghidra_*"), reverse=True):
        if d.is_dir() and (d / "ghidraRun.bat").exists():
            return d
    return None


def check_ghidra() -> bool:
    """Check for Ghidra installation. Returns True if found."""
    ghidra = _find_ghidra_dir()
    if ghidra:
        record("ghidra-install", PASS, str(ghidra))
        return True
    record("ghidra-install", WARN,
           "Ghidra not found in tools/ or GHIDRA_INSTALL_DIR -- "
           "run: python verify_install.py --setup")
    return False


def check_pyghidra():
    try:
        import pyghidra
        ver = getattr(pyghidra, "__version__", "?")
        record("pip:pyghidra", PASS, f"v{ver}")
    except ImportError:
        record("pip:pyghidra", WARN,
               "pyghidra not installed -- run: python verify_install.py --setup")


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


def _download(url: str, desc: str) -> bytes:
    """Download a URL with progress reporting."""
    from urllib.request import Request
    print(f"  Downloading {desc}...")
    req = Request(url, headers={"User-Agent": "vibe-re-toolkit/1.0"})
    resp = urlopen(req)
    total = int(resp.headers.get("Content-Length", 0))
    data = bytearray()
    while True:
        chunk = resp.read(1 << 20)  # 1MB chunks
        if not chunk:
            break
        data.extend(chunk)
        if total:
            pct = len(data) * 100 // total
            mb = len(data) / (1 << 20)
            print(f"\r  {mb:.0f} MB / {total / (1 << 20):.0f} MB ({pct}%)", end="", flush=True)
    print()
    return bytes(data)


def setup_jdk():
    """Download and install Adoptium JDK 21 to tools/jdk-21."""
    if shutil.which("java"):
        try:
            out = subprocess.check_output(
                ["java", "-version"], stderr=subprocess.STDOUT, timeout=10
            ).decode(errors="replace")
            if f'"{JDK_VERSION}.' in out or f" {JDK_VERSION}." in out:
                print(f"  JDK {JDK_VERSION} already installed (system)")
                return True
        except Exception:
            pass

    # Check if we already downloaded it
    for d in TOOLS_DIR.glob(f"jdk-{JDK_VERSION}*"):
        if (d / "bin" / "java.exe").exists():
            print(f"  JDK already at {d}")
            os.environ["JAVA_HOME"] = str(d)
            os.environ["PATH"] = str(d / "bin") + os.pathsep + os.environ.get("PATH", "")
            return True

    print(f"\n  JDK {JDK_VERSION} not found. Downloading Adoptium Temurin JDK {JDK_VERSION}...")
    try:
        data = _download(JDK_ADOPTIUM_URL, f"JDK {JDK_VERSION}")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        zip_path = TOOLS_DIR / f"jdk-{JDK_VERSION}.zip"
        zip_path.write_bytes(data)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(TOOLS_DIR)
        zip_path.unlink()
        jdk_dir = next(TOOLS_DIR.glob(f"jdk-{JDK_VERSION}*"), None)
        if jdk_dir and (jdk_dir / "bin" / "java.exe").exists():
            os.environ["JAVA_HOME"] = str(jdk_dir)
            os.environ["PATH"] = str(jdk_dir / "bin") + os.pathsep + os.environ.get("PATH", "")
            record("setup:jdk", PASS, f"Installed to {jdk_dir}")
            return True
        record("setup:jdk", FAIL, "Extraction succeeded but java.exe not found")
        return False
    except Exception as e:
        record("setup:jdk", FAIL, f"Download failed: {e}")
        return False


def setup_ghidra():
    """Download and extract Ghidra to tools/."""
    existing = _find_ghidra_dir()
    if existing:
        print(f"  Ghidra already at {existing}")
        os.environ["GHIDRA_INSTALL_DIR"] = str(existing)
        return True

    print(f"\n  Downloading Ghidra {GHIDRA_VERSION} (~435 MB)...")
    try:
        data = _download(GHIDRA_URL, f"Ghidra {GHIDRA_VERSION}")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        zip_path = TOOLS_DIR / GHIDRA_ZIP
        zip_path.write_bytes(data)
        print("  Extracting...")
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(TOOLS_DIR)
        zip_path.unlink()
        ghidra_dir = TOOLS_DIR / GHIDRA_DIR_NAME
        if ghidra_dir.is_dir():
            os.environ["GHIDRA_INSTALL_DIR"] = str(ghidra_dir)
            record("setup:ghidra", PASS, f"Installed to {ghidra_dir}")
            return True
        record("setup:ghidra", FAIL, "Extraction succeeded but directory not found")
        return False
    except Exception as e:
        record("setup:ghidra", FAIL, f"Download failed: {e}")
        return False


def setup_pyghidra():
    """Install pyghidra via pip."""
    try:
        import pyghidra
        print(f"  pyghidra already installed (v{getattr(pyghidra, '__version__', '?')})")
        return True
    except ImportError:
        pass

    print("  Installing pyghidra...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pyghidra>=2.0.0,<4.0.0", "-q"],
            timeout=120,
        )
        record("setup:pyghidra", PASS, "Installed via pip")
        return True
    except Exception as e:
        record("setup:pyghidra", FAIL, f"pip install failed: {e}")
        return False


def run_setup():
    """Auto-install optional pyghidra dependencies: JDK, Ghidra, pyghidra."""
    print("=" * 60)
    print("Pyghidra Setup (optional Ghidra decompiler backend)")
    print("=" * 60)

    if not setup_jdk():
        print("\n  Cannot proceed without JDK. Install JDK 21+ manually.")
        return

    if not setup_ghidra():
        print("\n  Cannot proceed without Ghidra. Download manually from ghidra-sre.org")
        return

    setup_pyghidra()

    ghidra_dir = _find_ghidra_dir()
    if ghidra_dir:
        print(f"\n  Set GHIDRA_INSTALL_DIR={ghidra_dir}")
        print("  Add to your shell profile for persistent use:")
        print(f'    export GHIDRA_INSTALL_DIR="{ghidra_dir}"')

    print()


def main():
    setup_mode = "--setup" in sys.argv

    print("RE Toolkit Install Verification\n")
    check_lfs()
    check_r2ghidra()
    check_python_deps()
    check_java()
    check_ghidra()
    check_pyghidra()
    check_r2_runs()
    check_retools_import()
    check_sigdb()

    failures = sum(1 for _, s, _ in results if s == FAIL)
    warns = sum(1 for _, s, _ in results if s == WARN)
    print()

    if failures:
        print(f"FAILED: {failures} check(s) did not pass.")
        print("Fix the above issues before using the toolkit.")
        sys.exit(1)

    if warns and setup_mode:
        ghidra_warns = any(
            n in ("java", "ghidra-install", "pip:pyghidra")
            for n, s, _ in results if s == WARN
        )
        if ghidra_warns:
            run_setup()
            # Re-check after setup
            results.clear()
            print("Re-checking after setup...\n")
            check_java()
            check_ghidra()
            check_pyghidra()
    elif warns:
        print(f"ALL REQUIRED CHECKS PASSED ({warns} optional warning(s)).")
        print("Run 'python verify_install.py --setup' to auto-install optional Ghidra backend.")
    else:
        print("ALL CHECKS PASSED.")


if __name__ == "__main__":
    main()
