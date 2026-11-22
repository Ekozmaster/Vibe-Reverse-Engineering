"""Smoke-test that all RE toolkit dependencies are installed and usable.

Usage:
    python verify_install.py              # check only
    python verify_install.py --setup      # check + auto-install missing optional deps (Ghidra, JDK, pyghidra)
"""

import importlib
import os
import pkgutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlopen

from retools.jdk import MIN_MAJOR as MIN_JDK_MAJOR, PYGHIDRA_OVERRIDE, find_jdk, probe_home, pyghidra_override

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
JDK_ADOPTIUM_URL = f"https://api.adoptium.net/v3/binary/latest/{MIN_JDK_MAJOR}/ga/windows/x64/jdk/hotspot/normal/eclipse"


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
               "signatures.db missing or empty -- run: python -m retools.sigdb pull")


def check_java() -> bool:
    """Check that the JDK pyghidra will start is new enough for Ghidra. Returns True if it is."""
    override = pyghidra_override()
    if override is not None:
        found = probe_home(override)
        if found is None or found.major < MIN_JDK_MAJOR:
            record("java", WARN,
                   f"{PYGHIDRA_OVERRIDE} names {override}, which is no JDK {MIN_JDK_MAJOR}+ -- "
                   "pyghidra starts it in place of any other; unset it or point it at one")
            return False
        record("java", PASS, f"JDK {found.major} ({found.home}, named by {PYGHIDRA_OVERRIDE})")
        return True

    found = find_jdk()
    if found is None:
        record("java", WARN,
               f"no JDK {MIN_JDK_MAJOR}+ in JAVA_HOME, on PATH or under tools/jdk-* -- "
               "required for pyghidra/Ghidra backend")
        return False
    record("java", PASS, f"JDK {found.major} ({found.home})")
    return True


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


def retools_modules() -> list[str]:
    """Dotted names of every module in the retools package."""
    return sorted(
        f"retools.{info.name}"
        for info in pkgutil.iter_modules([str(ROOT / "retools")])
    )


def check_retools_import():
    ok, bad = 0, []
    for mod in retools_modules():
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
    """Download and install Adoptium JDK 21 under tools/ unless a JDK 21+ is already found."""
    found = find_jdk()
    if found is not None:
        print(f"  JDK {found.major} already available ({found.home})")
        return True

    print(f"\n  No JDK {MIN_JDK_MAJOR}+ found. Downloading Adoptium Temurin JDK {MIN_JDK_MAJOR}...")
    try:
        data = _download(JDK_ADOPTIUM_URL, f"JDK {MIN_JDK_MAJOR}")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        zip_path = TOOLS_DIR / f"jdk-{MIN_JDK_MAJOR}.zip"
        zip_path.write_bytes(data)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(TOOLS_DIR)
        zip_path.unlink()
    except Exception as e:
        record("setup:jdk", FAIL, f"Download failed: {e}")
        return False
    found = find_jdk()
    if found is None:
        record("setup:jdk", FAIL, f"Extracted to {TOOLS_DIR}, but no JDK {MIN_JDK_MAJOR}+ runs from it")
        return False
    record("setup:jdk", PASS, f"Installed to {found.home}")
    return True


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
        print(f"\n  Ghidra is at {ghidra_dir}")
        print("  retools finds a Ghidra under tools/ on its own; set GHIDRA_INSTALL_DIR")
        print("  only to use an installation somewhere else.")

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

    print()
    _exit_if_failed()

    ghidra_checks = ("java", "ghidra-install", "pip:pyghidra")
    ghidra_missing = any(n in ghidra_checks for n, s, _ in results if s == WARN)

    if setup_mode and ghidra_missing:
        run_setup()
        results[:] = [r for r in results if r[0] not in ghidra_checks]
        print("Re-checking after setup...\n")
        check_java()
        check_ghidra()
        check_pyghidra()
        print()
        _exit_if_failed()
        ghidra_missing = any(n in ghidra_checks for n, s, _ in results if s == WARN)

    warns = sum(1 for _, s, _ in results if s == WARN)
    if warns:
        print(f"ALL REQUIRED CHECKS PASSED ({warns} optional warning(s)).")
        if ghidra_missing and not setup_mode:
            print("Run 'python verify_install.py --setup' to auto-install optional Ghidra backend.")
    else:
        print("ALL CHECKS PASSED.")


def _exit_if_failed():
    failures = sum(1 for _, s, _ in results if s == FAIL)
    if failures:
        print(f"FAILED: {failures} check(s) did not pass.")
        print("Fix the above issues before using the toolkit.")
        sys.exit(1)


if __name__ == "__main__":
    main()
