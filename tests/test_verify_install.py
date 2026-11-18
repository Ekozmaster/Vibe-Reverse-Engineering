"""Tests for the install checker's discovery helpers."""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import verify_install

JAVA_EXE = "java.exe" if sys.platform == "win32" else "java"


def _fake_jdk(root: Path) -> Path:
    launcher = root / "bin" / JAVA_EXE
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"")
    return launcher


@pytest.fixture
def no_java(tmp_path, monkeypatch):
    """An environment with no JAVA_HOME, no java on PATH and an empty tools dir."""
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(verify_install.shutil, "which", lambda name: None)
    tools = tmp_path / "tools"
    tools.mkdir()
    monkeypatch.setattr(verify_install, "TOOLS_DIR", tools)
    return tools


class TestFindJava:
    def test_none_when_nothing_is_installed(self, no_java):
        assert verify_install.find_java() is None

    def test_java_home_is_used_when_java_is_not_on_path(self, no_java, tmp_path, monkeypatch):
        launcher = _fake_jdk(tmp_path / "jdk-from-env")
        monkeypatch.setenv("JAVA_HOME", str(tmp_path / "jdk-from-env"))
        assert verify_install.find_java() == launcher

    def test_java_home_without_a_launcher_is_ignored(self, no_java, tmp_path, monkeypatch):
        monkeypatch.setenv("JAVA_HOME", str(tmp_path / "missing"))
        assert verify_install.find_java() is None

    def test_path_is_used_when_java_home_is_unset(self, no_java, tmp_path, monkeypatch):
        launcher = _fake_jdk(tmp_path / "jdk-on-path")
        monkeypatch.setattr(verify_install.shutil, "which", lambda name: str(launcher))
        assert verify_install.find_java() == launcher

    def test_portable_jdk_under_tools_is_the_last_resort(self, no_java):
        launcher = _fake_jdk(no_java / "jdk-21.0.9+10")
        assert verify_install.find_java() == launcher


class TestJavaMajorVersion:
    @pytest.mark.parametrize("banner, major", [
        ('openjdk version "21.0.9" 2025-10-21 LTS', 21),
        ('java version "17.0.2" 2022-01-18 LTS', 17),
        ('java version "1.8.0_391"', 8),
        ('openjdk version "22" 2024-03-19', 22),
    ])
    def test_parses_the_version_banner(self, banner, major):
        assert verify_install.java_major_version(banner) == major

    def test_unrecognised_banner_gives_none(self):
        assert verify_install.java_major_version("not a java banner") is None


class TestRetoolsModuleDiscovery:
    def test_lists_every_module_in_the_package(self):
        on_disk = {
            f"retools.{path.stem}"
            for path in (REPO_ROOT / "retools").glob("*.py")
            if path.stem != "__init__"
        }
        assert set(verify_install.retools_modules()) == on_disk
