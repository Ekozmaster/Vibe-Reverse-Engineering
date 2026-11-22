import os
import sys

import pytest


@pytest.fixture(scope="session")
def live_target_factory(tmp_path_factory):
    """``live_target.LiveTarget``, with the daemon's files kept out of the repository.

    Skips where a target cannot run: without Frida, off Windows, or under a
    32-bit Python, which cannot start the x64 host program.
    """
    pytest.importorskip("frida")
    if sys.platform != "win32" or sys.maxsize < 2**32:
        pytest.skip("needs 64-bit Python on Windows to start the x86 and x64 host programs")
    import live_target

    scratch = tmp_path_factory.mktemp("livetools")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(live_target.server, "STATE_FILE", scratch / "state.json")
        patch.setattr(live_target.server, "WORKSPACE", scratch)
        yield live_target.LiveTarget


@pytest.fixture(scope="session", params=["x86", "x64"])
def _shared_target(request, live_target_factory):
    live = live_target_factory(request.param)
    yield live
    live.close()


@pytest.fixture
def target(_shared_target):
    """A live target shared by the whole run, handed over running and free of breakpoints."""
    yield _shared_target
    _shared_target.reset()


@pytest.fixture(params=["x86", "x64"])
def fresh_target(request, live_target_factory):
    """A live target of its own, for a test that detaches from it or leaves it unusable."""
    live = live_target_factory(request.param)
    yield live
    live.close()


@pytest.fixture
def sample_binary():
    candidates = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "kernel32.dll"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ntdll.dll"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    pytest.skip("No PE binary available for testing")
