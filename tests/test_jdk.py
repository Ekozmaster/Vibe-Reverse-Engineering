"""Tests for retools/jdk.py -- the one JDK resolver behind verify_install and pyghidra_backend."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import jdk

_LAUNCHER = "java.exe" if os.name == "nt" else "java"


def _properties(version: str, home: Path) -> str:
    return f"Property settings:\n    java.home = {home}\n    java.version = {version}\n"


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """No JAVA_HOME, nothing on PATH and an empty tools dir; returns a function that installs a fake JDK.

    A fake JDK's launcher is an empty file; running it is replaced by the
    properties output of the version it was installed as.
    """
    tools = tmp_path / "tools"
    tools.mkdir()
    monkeypatch.setattr(jdk, "TOOLS_DIR", tools)
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(jdk.shutil, "which", lambda name: None)
    versions: dict[Path, str] = {}

    def read_properties(launcher):
        if launcher not in versions:
            raise OSError("not a JDK")
        return _properties(versions[launcher], launcher.parent.parent)
    monkeypatch.setattr(jdk, "_read_properties", read_properties)

    def install(home: Path, version: str) -> Path:
        launcher = home / "bin" / _LAUNCHER
        launcher.parent.mkdir(parents=True)
        launcher.write_bytes(b"")
        versions[launcher] = version
        return launcher
    install.tools = tools
    return install


class TestFindJdk:
    def test_none_when_nothing_is_installed(self, installed):
        assert jdk.find_jdk() is None

    def test_java_home_comes_first(self, installed, tmp_path, monkeypatch):
        installed(tmp_path / "from-env", "21.0.9")
        installed(installed.tools / "jdk-22", "22")
        monkeypatch.setenv("JAVA_HOME", str(tmp_path / "from-env"))
        assert jdk.find_jdk().home == tmp_path / "from-env"

    def test_java_home_without_a_launcher_is_skipped(self, installed, tmp_path, monkeypatch):
        monkeypatch.setenv("JAVA_HOME", str(tmp_path / "missing"))
        assert jdk.find_jdk() is None

    def test_old_java_on_path_gives_way_to_a_portable_jdk(self, installed, tmp_path, monkeypatch):
        old = installed(tmp_path / "jre8", "1.8.0_391")
        monkeypatch.setattr(jdk.shutil, "which", lambda name: str(old))
        installed(installed.tools / "jdk-21.0.9+10", "21.0.9")
        found = jdk.find_jdk()
        assert (found.home, found.major) == (installed.tools / "jdk-21.0.9+10", 21)

    def test_portable_jdks_rank_by_version_number_not_by_name(self, installed):
        installed(installed.tools / "jdk-9", "9.0.4")
        installed(installed.tools / "jdk-21.0.9+10", "21.0.9")
        assert jdk.find_jdk().home == installed.tools / "jdk-21.0.9+10"

    def test_a_portable_jdk_older_than_the_minimum_is_not_used(self, installed):
        installed(installed.tools / "jdk-17.0.2", "17.0.2")
        assert jdk.find_jdk() is None

    def test_home_is_where_the_jvm_says_it_is(self, installed, tmp_path, monkeypatch):
        """A java on PATH can be a shim outside the JDK it starts."""
        shim = tmp_path / "javapath" / _LAUNCHER
        shim.parent.mkdir()
        shim.write_bytes(b"")
        monkeypatch.setattr(jdk.shutil, "which", lambda name: str(shim))
        monkeypatch.setattr(jdk, "_read_properties", lambda launcher: _properties("21.0.9", tmp_path / "real"))
        assert jdk.find_jdk().home == tmp_path / "real"


class TestJavaMajorVersion:
    @pytest.mark.parametrize("version, major", [
        ("21.0.9", 21),
        ("17.0.2", 17),
        ("1.8.0_391", 8),
        ("22", 22),
    ])
    def test_parses_java_version(self, version, major):
        assert jdk.java_major_version(version) == major

    def test_unrecognised_version_gives_none(self):
        assert jdk.java_major_version("unknown") is None
