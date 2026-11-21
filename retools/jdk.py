"""Find a JDK new enough to run Ghidra.

The install checker and the Ghidra backend both resolve their JDK here, so the
one ``verify_install`` reports is the one pyghidra is handed. Standard library
only: ``verify_install`` imports this before it knows what else is installed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

MIN_MAJOR = 21

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
_LAUNCHER = "java.exe" if os.name == "nt" else "java"


@dataclass(frozen=True)
class Jdk:
    """A Java installation that ran and reported its version."""
    home: Path
    major: int


def java_major_version(version: str) -> int | None:
    """Major version of a ``java.version`` value: ``21.0.9`` is 21, legacy ``1.8.0_391`` is 8."""
    match = re.match(r"(\d+)(?:\.(\d+))?", version)
    if not match:
        return None
    major = int(match.group(1))
    if major == 1 and match.group(2):
        return int(match.group(2))
    return major


def _read_properties(launcher: Path) -> str:
    """What ``java -XshowSettings:properties -version`` prints."""
    return subprocess.run(
        [str(launcher), "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, errors="replace", timeout=30,
    ).stderr


def probe(launcher: Path) -> Jdk | None:
    """Run *launcher* and read where its Java lives and which version it is.

    The home comes from the JVM itself, since a ``java`` on PATH can be a
    shim that lives outside the JDK it starts.

    Returns:
        None when the launcher does not run or does not report both.
    """
    try:
        properties = _read_properties(launcher)
    except (OSError, subprocess.SubprocessError):
        return None
    home = re.search(r"^\s*java\.home = (.+?)\s*$", properties, re.MULTILINE)
    version = re.search(r"^\s*java\.version = (\S+)", properties, re.MULTILINE)
    major = java_major_version(version.group(1)) if version else None
    if home is None or major is None:
        return None
    return Jdk(home=Path(home.group(1)), major=major)


def _version_key(jdk_dir: Path) -> tuple[int, ...]:
    """``jdk-21.0.9+10`` sorts as (21, 0, 9, 10), so jdk-21 ranks above jdk-9."""
    return tuple(int(n) for n in re.findall(r"\d+", jdk_dir.name))


def candidates() -> list[Path]:
    """Java launchers in the order they are tried.

    The JDK that JAVA_HOME names, then ``java`` on PATH, then the portable
    JDKs under tools/, highest version first.
    """
    found = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home and (Path(java_home) / "bin" / _LAUNCHER).is_file():
        found.append(Path(java_home) / "bin" / _LAUNCHER)
    on_path = shutil.which("java")
    if on_path:
        found.append(Path(on_path))
    portable = sorted(TOOLS_DIR.glob("jdk-*"), key=_version_key, reverse=True)
    found.extend(d / "bin" / _LAUNCHER for d in portable if (d / "bin" / _LAUNCHER).is_file())
    return found


def find_jdk() -> Jdk | None:
    """The first candidate that runs and is at least version ``MIN_MAJOR``, or None."""
    for launcher in candidates():
        jdk = probe(launcher)
        if jdk is not None and jdk.major >= MIN_MAJOR:
            return jdk
    return None
