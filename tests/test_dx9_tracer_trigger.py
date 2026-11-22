"""``dx9tracer trigger``: what it reports about a capture, with and without a tracer answering.

The tracer DLL is played by a thread that does what the DLL does with the files
in the game folder: read the trigger file, write a first progress line carrying
the trigger's id, take the trigger file away, then write more progress, the
last line ending in "done" once the capture file is complete.

What the standalone tracer itself does with those files is tested by building
d3d9.dll from the tracer's src folder and running it in front of the test host
built from tracer_host/d3d9_trace_test_host.c, which needs Windows and the C++
tools of Visual Studio 2022 or later; those tests are skipped without them.
"""

import argparse
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import NamedTuple

import pytest

import proxy_live
from graphics.directx.dx9.tracer import cli

EARLIER_ID = "0123456789abcdef"

holds_open_files_against_removal = pytest.mark.skipif(
    sys.platform != "win32", reason="only Windows refuses to remove or replace a file another handle holds open")


@pytest.fixture(autouse=True)
def short_waits(monkeypatch):
    monkeypatch.setattr(cli, "_WAIT_TIMEOUT_SECONDS", 1.5)
    monkeypatch.setattr(cli, "_POLL_SECONDS", 0.02)


class _Polls:
    """The command's sleeps between two looks at the game folder, counted."""
    # More polls than any report made at once comes near
    POLLS_OF_A_COMMAND_WAITING_FOR_ITS_TIMEOUT = 500

    def __init__(self):
        self.count = 0
        self.timeout_is_out_of_reach = False

    def sleep(self, seconds):
        self.count += 1
        if self.timeout_is_out_of_reach:
            assert self.count < self.POLLS_OF_A_COMMAND_WAITING_FOR_ITS_TIMEOUT, "the command waits for its timeout"
        time.sleep(seconds)

    def wait_for(self, more: int) -> None:
        """Return once the command has polled *more* times from now, or 5 seconds have passed."""
        wanted = self.count + more
        deadline = time.monotonic() + 5
        while self.count < wanted and time.monotonic() < deadline:
            time.sleep(0.005)


@pytest.fixture
def polls(monkeypatch) -> _Polls:
    polls = _Polls()
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=time.monotonic, sleep=polls.sleep))
    return polls


@pytest.fixture
def timeout_out_of_reach(monkeypatch, polls):
    """The command never times out: what it reports, it reports for another reason than time having passed.

    A command that would have waited for the timeout fails the test instead.
    """
    monkeypatch.setattr(cli, "_WAIT_TIMEOUT_SECONDS", math.inf)
    polls.timeout_is_out_of_reach = True


def _trigger(game_dir, wait=True, frames=2) -> int:
    """Run the command; return its exit status."""
    args = argparse.Namespace(game_dir=str(game_dir), frames=frames, delay=0, wait=wait)
    try:
        cli.cmd_trigger(args)
    except SystemExit as exit_:
        return exit_.code
    return 0


def _trigger_id(game_dir) -> str:
    """Wait for a trigger file that carries an id; return the id."""
    trigger = game_dir / "dxtrace_capture.trigger"
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            named = re.search(r"^id=(\S+)$", trigger.read_text(), re.MULTILINE)
        except FileNotFoundError:
            named = None
        if named:
            return named.group(1)
        time.sleep(0.005)
    raise TimeoutError("no trigger file with an id appeared")


def _in_thread(run):
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _tracer(game_dir, progress=(), capture=b'{"seq":0}\n', pause=0.05):
    """Start a thread that takes the trigger file, writing each *progress* line in turn.

    "{id}" in a line stands for the id the trigger carries. The first line is
    written before the trigger file goes, the rest after it. It writes
    *capture* to dxtrace_frame.jsonl with each line, as the standalone tracer
    does; None plays the remix-comp-proxy tracer, which writes its capture to
    its own output folder. It waits *pause* seconds after each line.
    """
    def run():
        capture_id = _trigger_id(game_dir)
        for number, line in enumerate(progress):
            if capture is not None:
                (game_dir / "dxtrace_frame.jsonl").write_bytes(capture)
            (game_dir / "dxtrace_progress.txt").write_text(line.replace("{id}", capture_id))
            if number == 0:
                (game_dir / "dxtrace_capture.trigger").unlink()
            time.sleep(pause)
        if not progress:
            (game_dir / "dxtrace_capture.trigger").unlink()

    return _in_thread(run)


_TRACER = Path(cli.__file__).parent
_TRACER_SOURCES = ["d3d9_trace_main.c", "d3d9_trace_wrapper.c", "d3d9_trace_device.c"]
_HOST_SOURCE = Path(__file__).parent / "tracer_host" / "d3d9_trace_test_host.c"


def _c_string_literals(source: str) -> set[bytes]:
    """The string literals of a C source, as the bytes the compiler stores for them.

    Adjacent literals are one string to the compiler and are left out, as a
    literal behind #include is.
    """
    code = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    code = re.sub(r"'(\\.|[^\\'])'", "", code)
    code = re.sub(r"^\s*#\s*include.*$", "", code, flags=re.MULTILINE)
    literal = r'"((?:[^"\\\n]|\\.)*)"'
    adjacent = {found.start(n) for found in re.finditer(rf"{literal}\s*{literal}", code) for n in (1, 2)}
    escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}
    return {re.sub(r"\\(.)", lambda escape: escapes[escape.group(1)], found.group(1)).encode()
            for found in re.finditer(literal, code) if found.start(1) not in adjacent}


class TestShippedTracer:
    """bin/d3d9.dll is built from a source that speaks the trigger and progress formats of this CLI."""

    @pytest.mark.parametrize("literal", [
        b"frames=",
        b"id=",
        b"%d %d %s\n",
        b"%d %d %s done\n",
        b"0 0 %s failed %s\n",
        b"the trigger's frames= is not a number of frames from 1 up",
    ])
    def test_committed_binary_carries_the_format(self, literal):
        dll = (Path(cli.__file__).parent / "bin" / "d3d9.dll").read_bytes()
        assert literal + b"\0" in dll

    def test_committed_binary_holds_every_string_of_the_source(self):
        """A source edited without a rebuild shows in a message or a format the binary lacks."""
        dll = (_TRACER / "bin" / "d3d9.dll").read_bytes()
        literals = set().union(*(_c_string_literals((_TRACER / "src" / name).read_text()) for name in _TRACER_SOURCES))
        # A short string the compiler may load as a number, which leaves no text in the binary
        texts = {literal for literal in literals if len(literal) >= 12}
        assert len(texts) > 40
        missing = sorted(text for text in texts if text not in dll)
        assert not missing, "bin/d3d9.dll was not rebuilt from src/ (src/build.bat)"


class TestFrameCount:
    @pytest.mark.parametrize("frames", ["0", "-1", "100001", "two"])
    def test_count_no_tracer_would_capture_as_asked_is_refused(self, frames, capsys):
        with pytest.raises(SystemExit) as refused:
            cli.build_parser().parse_args(["trigger", f"--frames={frames}"])
        assert refused.value.code == 2
        assert "--frames" in capsys.readouterr().err

    @pytest.mark.parametrize("frames", [1, 100000])
    def test_count_within_the_tracers_limits_is_taken(self, frames):
        assert cli.build_parser().parse_args(["trigger", "--frames", str(frames)]).frames == frames


class TestTriggerFile:
    def test_names_the_frames_and_an_id_of_its_own(self, tmp_path):
        ids = []
        for _ in range(2):
            assert _trigger(tmp_path, wait=False, frames=7) == 0
            frames, id_ = (tmp_path / "dxtrace_capture.trigger").read_text().splitlines()
            assert frames == "frames=7"
            assert re.fullmatch(r"id=[0-9a-f]{16}", id_)
            ids.append(id_)
        assert ids[0] != ids[1]


class TestNoTracerAnswers:
    @pytest.fixture
    def stale_folder(self, tmp_path):
        """A folder that still holds the files of an earlier capture."""
        (tmp_path / "dxtrace_progress.txt").write_text(f"2 4711 {EARLIER_ID} done\n")
        (tmp_path / "dxtrace_frame.jsonl").write_text('{"seq":0}\n')
        return tmp_path

    def test_files_of_an_earlier_capture_are_not_reported_as_this_one(self, stale_folder, capsys):
        status = _trigger(stale_folder)
        assert status != 0
        assert "Capture complete" not in capsys.readouterr().out

    def test_its_own_trigger_file_is_taken_back(self, stale_folder):
        _trigger(stale_folder)
        assert not (stale_folder / "dxtrace_capture.trigger").exists()

    def test_trigger_taken_between_the_check_and_the_removal_is_not_an_error(self, stale_folder, monkeypatch):
        exists = Path.exists

        def taken_once_seen(path, **kwargs):
            if path.name == "dxtrace_capture.trigger":
                path.unlink(missing_ok=True)
                return True
            return exists(path, **kwargs)

        monkeypatch.setattr(Path, "exists", taken_once_seen)

        assert _trigger(stale_folder) == 1

    def test_without_wait_the_trigger_file_stays_for_the_tracer(self, stale_folder):
        assert _trigger(stale_folder, wait=False) == 0
        assert (stale_folder / "dxtrace_capture.trigger").read_text().startswith("frames=2\n")

    def test_progress_file_stays_for_whoever_follows_the_earlier_capture(self, stale_folder):
        _trigger(stale_folder, wait=False)
        assert (stale_folder / "dxtrace_progress.txt").read_text() == f"2 4711 {EARLIER_ID} done\n"


class TestTracerBusyWithAnEarlierCapture:
    """A tracer leaves the trigger file alone until the capture it is writing has ended."""

    @pytest.mark.parametrize("earlier_line", [
        "2 80 done\n",
        f"2 80 {EARLIER_ID} done\n",
        "2 80 - done\n",
    ], ids=["without an id", "with the id of its trigger", "started without a trigger"])
    def test_earlier_capture_reported_done_is_not_this_one(self, tmp_path, capsys, earlier_line):
        def finish_earlier_capture():
            _trigger_id(tmp_path)
            (tmp_path / "dxtrace_progress.txt").write_text(earlier_line)

        _in_thread(finish_earlier_capture)
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "no tracer took the trigger" in out

    def test_capture_started_once_the_earlier_one_ended_is_followed(self, tmp_path, capsys):
        def finish_earlier_capture_then_take_the_trigger():
            capture_id = _trigger_id(tmp_path)
            progress = tmp_path / "dxtrace_progress.txt"
            progress.write_text(f"1 40 {EARLIER_ID}\n")
            time.sleep(0.2)
            progress.write_text(f"2 80 {EARLIER_ID} done\n")
            time.sleep(0.2)
            progress.write_text(f"0 0 {capture_id}\n")
            (tmp_path / "dxtrace_capture.trigger").unlink()
            time.sleep(0.2)
            progress.write_text(f"2 90 {capture_id} done\n")

        _in_thread(finish_earlier_capture_then_take_the_trigger)
        assert _trigger(tmp_path) == 0
        assert "Capture complete" in capsys.readouterr().out


class TestTracerAnswers:
    def test_capture_the_tracer_reports_done_at_its_last_frame_is_complete(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0 {id}\n", "1 40 {id}\n", "2 80 {id} done\n"])
        assert _trigger(tmp_path) == 0
        assert "Capture complete" in capsys.readouterr().out

    def test_capture_into_a_file_held_open_since_device_creation_is_named(self, tmp_path, capsys):
        # With CaptureInit on, the tracer opens the JSONL at device creation and only flushes it later
        with open(tmp_path / "dxtrace_frame.jsonl", "w") as held_open:
            held_open.write('{"frame":-1,"seq":0}\n')
            held_open.flush()

            def append_capture():
                capture_id = _trigger_id(tmp_path)
                (tmp_path / "dxtrace_progress.txt").write_text(f"0 0 {capture_id}\n")
                (tmp_path / "dxtrace_capture.trigger").unlink()
                time.sleep(0.05)
                held_open.write('{"frame":0,"seq":1}\n')
                held_open.flush()
                (tmp_path / "dxtrace_progress.txt").write_text(f"2 2 {capture_id} done\n")

            _in_thread(append_capture)
            assert _trigger(tmp_path) == 0
        assert f"Capture complete: {tmp_path / 'dxtrace_frame.jsonl'}" in capsys.readouterr().out

    def test_last_frame_is_not_complete_until_the_tracer_reports_done(self, tmp_path, capsys, polls):
        progress = tmp_path / "dxtrace_progress.txt"

        def report_done_once_the_last_frame_has_been_read_without_it():
            capture_id = _trigger_id(tmp_path)
            (tmp_path / "dxtrace_frame.jsonl").write_bytes(b'{"seq":0}\n')
            progress.write_text(f"2 80 {capture_id}\n")
            (tmp_path / "dxtrace_capture.trigger").unlink()
            # The poll under way may have read the folder before the line was there; the next one has not
            polls.wait_for(2)
            progress.write_text(f"2 80 {capture_id} done\n")

        _in_thread(report_done_once_the_last_frame_has_been_read_without_it)
        assert _trigger(tmp_path) == 0
        assert progress.read_text().endswith(" done\n")
        assert "Capture complete" in capsys.readouterr().out

    def test_capture_that_keeps_reporting_new_progress_is_followed_past_the_timeout(self, tmp_path, capsys):
        lines = [f"{frame} {frame * 40} {{id}}\n" for frame in range(6)] + ["6 240 {id} done\n"]
        _tracer(tmp_path, progress=lines, pause=0.4)    # 2.4 s of capture against the 1.5 s timeout
        assert _trigger(tmp_path, frames=6) == 0
        assert "Capture complete" in capsys.readouterr().out

    def test_last_frame_without_done_is_reported_as_not_written_in_full(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0 {id}\n", "1 40 {id}\n", "2 80 {id}\n"])
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "never reported the capture file written in full" in out

    def test_capture_done_short_of_the_frames_asked_for_is_reported_at_once(self, tmp_path, capsys, timeout_out_of_reach):
        _tracer(tmp_path, progress=["0 0 {id}\n", "1 40 {id} done\n"])
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "frame 1 of 2" in out

    def test_capture_that_stops_short_without_done_is_reported_with_the_frame_it_reached(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0 {id}\n", "1 40 {id}\n"])
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "frame 1 of 2" in out


class TestTracerTakesTheTriggerWithoutReporting:
    """The first progress line is written before the trigger goes, so its absence is known at once."""

    @pytest.fixture(autouse=True)
    def at_once(self, timeout_out_of_reach):
        pass

    def assert_named(self, tmp_path, capsys):
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "took the trigger but reported no progress" in out
        return out

    def test_tracer_that_writes_no_progress_file(self, tmp_path, capsys):
        _tracer(tmp_path)
        self.assert_named(tmp_path, capsys)

    def test_tracer_that_leaves_the_progress_of_an_earlier_capture(self, tmp_path, capsys):
        (tmp_path / "dxtrace_progress.txt").write_text(f"2 80 {EARLIER_ID} done\n")
        _tracer(tmp_path)
        self.assert_named(tmp_path, capsys)

    def test_tracer_whose_progress_does_not_name_the_trigger(self, tmp_path, capsys):
        def capture_as_a_tracer_without_ids_does():
            _trigger_id(tmp_path)
            (tmp_path / "dxtrace_capture.trigger").unlink()
            (tmp_path / "dxtrace_progress.txt").write_text("2 80 done\n")

        (tmp_path / "dxtrace_progress.txt").write_text("2 80 done\n")
        _in_thread(capture_as_a_tracer_without_ids_does)
        self.assert_named(tmp_path, capsys)

    def test_tracer_is_not_said_to_be_out_of_date_for_certain(self, tmp_path, capsys):
        _tracer(tmp_path)
        out = self.assert_named(tmp_path, capsys)
        assert "could not write" in out
        assert "dxtrace_proxy.log" in out


class TestTracerCannotStartTheCapture:
    REASON = r"cannot open C:\Games\My Game\dxtrace_frame.jsonl: Permission denied"

    def test_reason_the_tracer_gives_is_reported_at_once(self, tmp_path, capsys, timeout_out_of_reach):
        _tracer(tmp_path, progress=[f"0 0 {{id}} failed {self.REASON}\n"], capture=None)
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status == 1
        assert f"[error] the tracer could not start the capture: {self.REASON}\n" in out
        assert "predates" not in out
        assert "Capture complete" not in out

    def test_capture_given_up_part_way_is_not_said_to_have_failed_to_start(self, tmp_path, capsys, timeout_out_of_reach):
        reason = r"cannot write C:\Games\My Game\dxtrace_frame.jsonl: No space left on device"
        _tracer(tmp_path, progress=["0 0 {id}\n", f"1 512 {{id}} failed {reason}\n"])
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status == 1
        assert f"[error] the tracer gave up the capture at frame 1, after 512 calls: {reason}\n" in out
        assert "could not start" not in out
        assert "Capture complete" not in out

    def test_reason_read_while_the_tracer_is_still_writing_it_is_not_reported_cut_short(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0 {id} failed cannot op", f"0 0 {{id}} failed {self.REASON}\n"],
                capture=None, pause=0.3)
        assert _trigger(tmp_path) == 1
        assert f"could not start the capture: {self.REASON}\n" in capsys.readouterr().out

    def test_reason_with_a_path_outside_utf8_is_still_reported(self, tmp_path, capsys):
        def answer():
            capture_id = _trigger_id(tmp_path)
            (tmp_path / "dxtrace_progress.txt").write_bytes(
                f"0 0 {capture_id} failed cannot open C:/Jeux/".encode() + b"\xe9t\xe9.jsonl: Permission denied\n")
            (tmp_path / "dxtrace_capture.trigger").unlink()

        _in_thread(answer)
        assert _trigger(tmp_path) == 1
        out = capsys.readouterr().out
        assert "could not start the capture: cannot open C:/Jeux/" in out
        assert "Permission denied" in out


class TestProxyTracerAnswers:
    """The remix-comp-proxy tracer reports progress the same way, but writes its capture to its OutputDir."""

    def test_capture_the_proxy_reports_done_is_complete(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0 {id}\n", "1 40 {id}\n", "2 80 {id} done\n"], capture=None)
        assert _trigger(tmp_path) == 0
        out = capsys.readouterr().out
        assert "Capture complete" in out
        assert "OutputDir" in out

    def test_capture_file_of_an_earlier_standalone_capture_is_not_named(self, tmp_path, capsys):
        (tmp_path / "dxtrace_frame.jsonl").write_text('{"seq":0}\n')
        _tracer(tmp_path, progress=["0 0 {id}\n", "2 80 {id} done\n"], capture=None)
        assert _trigger(tmp_path) == 0
        assert "dxtrace_frame.jsonl" not in capsys.readouterr().out


@holds_open_files_against_removal
class TestTracerHoldsTheTriggerFileOpen:
    """The tracer reads the trigger file through fopen, which shares neither removal nor replacement."""

    def test_handle_like_the_tracers_refuses_removal_and_replacement(self, tmp_path):
        trigger = tmp_path / "dxtrace_capture.trigger"
        trigger.write_text("frames=2\n")
        (tmp_path / "staged").write_text("frames=3\n")
        with open(trigger):
            with pytest.raises(PermissionError):
                trigger.unlink()
            with pytest.raises(PermissionError):
                (tmp_path / "staged").replace(trigger)

    def test_trigger_held_when_it_is_taken_back_is_removed_once_released(self, tmp_path, capsys):
        released = threading.Event()

        def read_the_trigger_slowly():
            _trigger_id(tmp_path)
            with open(tmp_path / "dxtrace_capture.trigger"):
                time.sleep(1.8)    # past the 1.5 s the command waits for a tracer
            released.set()

        _in_thread(read_the_trigger_slowly)
        status = _trigger(tmp_path)
        assert released.wait(5)
        assert status == 1
        assert "no tracer took the trigger" in capsys.readouterr().out
        assert not (tmp_path / "dxtrace_capture.trigger").exists()

    def test_earlier_trigger_held_while_the_new_one_is_placed_is_waited_for(self, tmp_path, capsys):
        trigger = tmp_path / "dxtrace_capture.trigger"
        trigger.write_text("frames=2\n")
        earlier_read = open(trigger)
        try:
            threading.Timer(0.3, earlier_read.close).start()
            _tracer(tmp_path, progress=["0 0 {id}\n", "2 80 {id} done\n"])
            assert _trigger(tmp_path) == 0
        finally:
            earlier_read.close()
        assert "Capture complete" in capsys.readouterr().out

    def test_earlier_trigger_held_without_wait_is_an_error_not_a_traceback(self, tmp_path, capsys):
        trigger = tmp_path / "dxtrace_capture.trigger"
        trigger.write_text("frames=2\n")
        with open(trigger):
            status = _trigger(tmp_path, wait=False)
        out = capsys.readouterr().out
        assert status == 1
        assert "[error]" in out
        assert "Trigger file created" not in out
        assert trigger.read_text() == "frames=2\n"
        assert not (tmp_path / "dxtrace_capture.tmp").exists()


ID_A = "a" * 16
ID_B = "b" * 16
STATE_WAITS_FOR_OTHER_CALL = 0x7002
STATE_HELD_IN_DRIVER = 0x7003
STATE_OF_THREAD = 0x8000
CALLS_PER_SHADER = 16
# The host draws each frame with these calls
FRAME = ["BeginScene", "SetRenderState", "DrawPrimitive", "EndScene", "Present"]
# The one device method the host never calls. Windows calls it, through its compatibility
# layer, on a device of a program that is new to it, at a moment of its own choosing.
METHOD_ONLY_WINDOWS_CALLS = "QueryInterface"


def _trigger_file(frames, capture_id=ID_A) -> bytes:
    return f"frames={frames}\nid={capture_id}\n".encode()


class _HostRun(NamedTuple):
    """What a run of the test host left in its folder."""
    stdout: str
    log: str
    progress: str
    records: list[dict]

    def frames(self) -> list[int]:
        return [record["frame"] for record in self.records]

    def of(self, method: str) -> list[dict]:
        return [record for record in self.records if record["method"] == method]

    def host_calls(self) -> list[dict]:
        """The records of the calls the host made, in the order of the file."""
        return [record for record in self.records if record["method"] != METHOD_ONLY_WINDOWS_CALLS]

    def host_methods(self) -> list[str]:
        return [record["method"] for record in self.host_calls()]

    def in_frames(self, *frames: int) -> list[dict]:
        return [record for record in self.records if record["frame"] in frames]


def _build_x86(folder: Path, vcvarsall: Path, *commands: str) -> None:
    """Run the compiler and linker *commands* in *folder*, which receives what they write."""
    script = folder / "build.cmd"
    script.write_text(
        "@echo off\n"
        f'call "{vcvarsall}" x86 >nul 2>&1 || exit /b 1\n'
        + "".join(f"{command} || exit /b 1\n" for command in commands),
        encoding="ascii")
    built = subprocess.run(["cmd", "/c", str(script)], cwd=folder, capture_output=True, text=True)
    assert built.returncode == 0, built.stdout + built.stderr


@pytest.fixture(scope="module")
def vcvarsall() -> Path:
    """Skips without the C++ tools of Visual Studio 2022 or later."""
    found = proxy_live.find_vcvarsall() if os.name == "nt" else None
    if found is None:
        pytest.skip("needs Windows with the C++ tools of Visual Studio 2022 or later")
    return found


@pytest.fixture(scope="module")
def host_program(tmp_path_factory, vcvarsall) -> Path:
    """The test host, built."""
    folder = tmp_path_factory.mktemp("tracer_host")
    _build_x86(folder, vcvarsall, f'cl /nologo /W3 /WX /I "{_TRACER / "src"}" "{_HOST_SOURCE}" /Fe:host.exe')
    return folder / "host.exe"


@pytest.fixture(scope="module")
def tracer_dll(tmp_path_factory, vcvarsall) -> Path:
    """The standalone tracer, built from the source in the working tree the way src/build.bat builds it."""
    folder = tmp_path_factory.mktemp("tracer_dll")
    src = _TRACER / "src"
    sources = " ".join(f'"{src / name}"' for name in _TRACER_SOURCES)
    objects = " ".join(Path(name).with_suffix(".obj").name for name in _TRACER_SOURCES)
    _build_x86(folder, vcvarsall,
               f'cl /nologo /O2 /W3 /c /D "WIN32" /D "NDEBUG" {sources}',
               f'link /nologo /DLL /DEF:"{src / "d3d9.def"}" /OUT:d3d9.dll {objects} kernel32.lib user32.lib')
    return folder / "d3d9.dll"


@pytest.fixture
def host(host_program, tracer_dll, tmp_path):
    """Run the host behind the built tracer in a folder of its own and return what the run left there."""
    def run(*commands, capture_init=0, capture_frames=2, files=None, folder=tmp_path) -> _HostRun:
        shutil.copy(host_program, folder)
        shutil.copy(tracer_dll, folder)
        (folder / "proxy.ini").write_text(
            f"[Trace]\nCaptureFrames={capture_frames}\nCaptureInit={capture_init}\n[Chain]\nDLL=host.exe\n")
        for name, content in (files or {}).items():
            (folder / name).write_bytes(content)
        done = subprocess.run([str(folder / "host.exe"), *map(str, commands)],
                              cwd=folder, capture_output=True, text=True, timeout=120)

        def text(name):
            path = folder / name
            return path.read_text() if path.is_file() else ""

        log = text("dxtrace_proxy.log")
        assert done.returncode == 0, f"the host exited with {done.returncode:#x}: {done.stderr}\n{log}"
        return _HostRun(done.stdout, log, text("dxtrace_progress.txt"),
                        [json.loads(line) for line in text("dxtrace_frame.jsonl").splitlines()])

    return run


class TestBuiltTracerRecordsCalls:
    """The built tracer in front of the test host: the records of a capture."""

    @pytest.fixture(params=[0, 1], ids=["file opened for the capture", "file kept open for init records"])
    def capture(self, request, host):
        """Run the host with a trigger for *frames* in place, under either setting of CaptureInit."""
        def run(*commands, frames) -> _HostRun:
            return host(*commands, capture_init=request.param,
                        files={"dxtrace_capture.trigger": _trigger_file(frames)})

        return run

    def test_capture_holds_every_call_of_its_frames_numbered_as_written(self, capture):
        run = capture("frames", 4, frames=2)
        assert run.host_methods() == FRAME * 2
        assert [record["seq"] for record in run.records] == list(range(len(run.records)))
        assert [record["frame"] for record in run.host_calls()] == [0] * 5 + [1] * 5
        assert run.progress == f"2 {len(run.records)} {ID_A} done\n"

    def test_created_object_is_in_the_record_of_the_call_that_created_it(self, capture):
        run = capture("frames", 1, "shader", "frames", 1, frames=1)
        shader, = run.of("CreateVertexShader")
        assert shader["created_handle"] == "0x0B000010"
        assert shader["data"]["bytecode"] == "FFFE0300" "0000FFFF"

    def test_data_behind_a_pointer_to_no_memory_is_left_out_of_a_whole_record(self, capture):
        run = capture("frames", 1, "unreadable-constants", "frames", 1, frames=1)
        constants, = run.of("SetVertexShaderConstantF")
        assert constants["args"] == {"StartRegister": 0, "pConstantData": "0x00000001", "Vector4fCount": 4}
        assert constants["data"] == {}

    def test_call_returns_while_a_recorded_call_of_another_thread_is_in_the_driver(self, capture):
        run = capture("frames", 1, "blocked-call", "frames", 2, frames=2)
        assert "blocked-call: returned" in run.stdout
        waiting_call, = [record for record in run.of("SetRenderState")
                         if record["args"]["State"] == STATE_WAITS_FOR_OTHER_CALL]
        assert waiting_call["ret"] == "0x00000000"
        assert run.progress.endswith(" done\n")

    def test_capture_ends_after_the_driver_raises_out_of_a_recorded_call(self, capture):
        run = capture("frames", 1, "raise", "frames", 3, frames=2)
        assert run.progress == f"2 {len(run.records)} {ID_A} done\n"
        assert run.host_methods() == FRAME * 2

    def test_call_that_returns_in_a_later_capture_than_it_was_made_in_is_in_neither(self, capture, tmp_path):
        (tmp_path / "next.trigger").write_bytes(_trigger_file(1, ID_B))
        run = capture("frames", 1, "hold-call", "frames", 1, "trigger", "next.trigger", "frames", 1,
                      "release-call", "frames", 1, frames=1)
        assert not [record for record in run.of("SetRenderState") if record["args"]["State"] == STATE_HELD_IN_DRIVER]
        assert [record["method"] for record in run.in_frames(run.frames()[-1])
                if record["method"] != METHOD_ONLY_WINDOWS_CALLS] == FRAME
        assert re.fullmatch(rf"1 \d+ {ID_B} done\n", run.progress)

    def test_records_of_calls_made_on_several_threads_are_whole_and_in_the_order_written(self, capture):
        threads, calls, frames = 4, 400, 20
        run = capture("frames", 1, "threads", threads, calls, frames, "frames", 2 * frames, frames=2 * frames)
        assert run.progress.endswith(f"{ID_A} done\n")
        assert [record["seq"] for record in run.records] == list(range(len(run.records)))
        assert run.frames() == sorted(run.frames())
        for thread in range(threads):
            values = [record["args"]["Value"] for record in run.of("SetRenderState")
                      if record["args"]["State"] == STATE_OF_THREAD + thread]
            assert values == list(range(calls)), f"thread {thread}"
        shaders = run.of("CreateVertexShader")
        assert len(shaders) == threads * calls // CALLS_PER_SHADER
        assert len({shader["created_handle"] for shader in shaders}) == len(shaders)


class TestBuiltTracerDevices:
    def test_device_created_during_a_capture_leaves_the_frames_its_trigger_asked_for(self, host):
        run = host("frames", 2, "device", "frames", 5, capture_frames=2,
                   files={"dxtrace_capture.trigger": _trigger_file(4)})
        # Windows queries a device for an interface of its own when the program is new to it,
        # so the number of calls in the capture is not the host's alone
        assert re.fullmatch(rf"4 \d+ {ID_A} done\n", run.progress)
        assert sorted(set(run.frames())) == [0, 1, 2, 3]

    def test_device_created_later_keeps_the_init_records_of_the_first(self, host):
        run = host("shader", "device", "shader", "trigger", "next.trigger", "frames", 3, capture_init=1,
                   files={"next.trigger": _trigger_file(1)})
        assert run.host_methods() == ["CreateVertexShader"] * 2 + FRAME
        assert run.log.count("Init capture enabled") == 1


class TestBuiltTracerKeepsItsFileForInitRecords:
    """With CaptureInit=1 the file stays open, and a later capture goes on where the file ends."""

    @pytest.fixture
    def run(self, host):
        return host("shader", "trigger", "a.trigger", "frames", 3, "shader", "trigger", "b.trigger", "frames", 3,
                    capture_init=1, files={"a.trigger": _trigger_file(2, ID_A), "b.trigger": _trigger_file(2, ID_B)})

    def test_frames_of_a_second_capture_are_numbered_on_from_the_first(self, run):
        assert [record["frame"] for record in run.host_calls()] == [-1] + [0] * 5 + [1] * 5 + [-1] + [2] * 5 + [3] * 5

    def test_no_two_records_of_the_file_share_a_sequence_number(self, run):
        assert [record["seq"] for record in run.records] == list(range(len(run.records)))

    def test_progress_counts_the_frames_and_calls_of_its_own_capture(self, run):
        assert run.progress == f"2 {len(run.in_frames(2, 3))} {ID_B} done\n"

    def test_creation_that_returns_in_a_later_capture_than_it_was_made_in_is_kept_outside_its_frames(self, host):
        run = host("frames", 1, "hold-shader", "frames", 1, "trigger", "next.trigger", "frames", 1,
                   "release-call", "frames", 1, capture_init=1,
                   files={"dxtrace_capture.trigger": _trigger_file(1, ID_A), "next.trigger": _trigger_file(1, ID_B)})
        shader, = run.of("CreateVertexShader")
        assert shader["frame"] == -1
        assert shader["created_handle"] == "0x0B000010"
        assert [record["frame"] for record in run.host_calls()] == [0] * 5 + [-1] + [1] * 5

    def test_file_that_cannot_be_opened_for_init_records_is_named_in_the_log(self, host, tmp_path):
        (tmp_path / "dxtrace_frame.jsonl").mkdir()
        run = host("shader", capture_init=1)
        assert "Init capture enabled" not in run.log
        assert "ERROR: init records not captured, cannot open " in run.log
        assert "dxtrace_frame.jsonl: " in run.log


class TestBuiltTracerProgressFile:
    def test_log_names_a_progress_file_it_cannot_write_once_for_the_capture(self, host, tmp_path):
        (tmp_path / "dxtrace_progress.txt").mkdir()
        run = host("frames", 5, files={"dxtrace_capture.trigger": _trigger_file(3)})
        assert run.log.count("dxtrace_progress.txt") == 1
        assert "ERROR: cannot write" in run.log
        assert "=== CAPTURE DONE ===" in run.log


class TestBuiltTracerCannotWriteItsFile:
    """A capture file that takes no more writes ends the capture, which is not reported done."""

    @pytest.fixture(params=[0, 1], ids=["file opened for the capture", "file kept open for init records"])
    def run(self, request, host):
        return host("frames", 2, "lock-capture-file", "frames", 4, capture_init=request.param,
                    files={"dxtrace_capture.trigger": _trigger_file(3)})

    def test_progress_names_the_failure_and_not_a_finished_capture(self, run):
        assert re.fullmatch(rf"\d+ \d+ {ID_A} failed cannot write .*dxtrace_frame\.jsonl: .+\n", run.progress)

    def test_log_names_the_failure_once_and_no_finished_capture(self, run):
        assert run.log.count("ERROR: cannot write") == 1
        assert "=== CAPTURE DONE ===" not in run.log


class TestBuiltTracerTrigger:
    def test_frame_count_followed_by_blanks_is_taken(self, host):
        run = host("frames", 4, files={"dxtrace_capture.trigger": f"frames=3 \t\r\nid={ID_A}\r\n".encode()})
        assert run.progress == f"3 {len(run.records)} {ID_A} done\n"

    @pytest.mark.parametrize("frames", ["3 x", " 3", "\n3", "+3"],
                             ids=["text behind it", "blank before it", "on the next line", "signed"])
    def test_frame_count_that_is_not_digits_with_only_blanks_behind_is_refused(self, host, frames):
        run = host("frames", 4, files={"dxtrace_capture.trigger": f"frames={frames}\nid={ID_A}\n".encode()})
        assert run.progress == f"0 0 {ID_A} failed the trigger's frames= is not a number of frames from 1 up\n"

    def test_id_followed_by_blanks_is_taken(self, host):
        run = host("frames", 3, files={"dxtrace_capture.trigger": f"frames=1\r\nid={ID_A} \t\r\n".encode()})
        assert run.progress == f"1 {len(run.records)} {ID_A} done\n"

    def test_id_followed_by_anything_else_counts_as_none(self, host):
        run = host("frames", 3, files={"dxtrace_capture.trigger": f"frames=1\nid={ID_A} x\n".encode()})
        assert run.progress == f"1 {len(run.records)} - done\n"

    @pytest.fixture
    def undeletable_trigger(self, tmp_path):
        trigger = tmp_path / "dxtrace_capture.trigger"
        trigger.write_bytes(_trigger_file(1))
        trigger.chmod(stat.S_IREAD)
        yield trigger
        if trigger.exists():
            trigger.chmod(stat.S_IWRITE)

    def test_trigger_that_cannot_be_deleted_starts_one_capture(self, host, undeletable_trigger):
        run = host("frames", 5)
        assert run.log.count("=== CAPTURE STARTED ===") == 1
        assert run.log.count("trigger file not deleted") == 1
        assert run.host_methods() == FRAME
        assert run.progress == f"1 {len(run.records)} {ID_A} done\n"

    def test_trigger_that_can_be_deleted_later_is_deleted_then(self, host, undeletable_trigger):
        run = host("frames", 3, "make-trigger-writable", "frames", 2)
        assert not undeletable_trigger.exists()
        assert run.log.count("=== CAPTURE STARTED ===") == 1
        assert run.log.count("trigger file not deleted") == 1

    def test_trigger_placed_after_one_that_could_not_be_deleted_starts_a_capture(self, host, undeletable_trigger):
        run = host("frames", 3, "make-trigger-writable", "trigger", "next.trigger", "frames", 3,
                   files={"next.trigger": _trigger_file(1, ID_B)})
        assert run.progress == f"1 {len(run.records)} {ID_B} done\n"


class TestBuiltTracerGameFolder:
    def test_folder_too_long_for_the_names_of_its_files_is_refused_in_the_log(self, host, tmp_path):
        max_path = 260
        padding = max_path - len("dxtrace_capture.trigger") - len(str(tmp_path)) - 2 * len(os.sep)
        if padding < 1:
            pytest.skip("the temporary folder is already too long to hold the host")
        folder = tmp_path / ("d" * padding)
        folder.mkdir()
        run = host("frames", 2, folder=folder)
        assert "ERROR: not tracing" in run.log
        assert "too long" in run.log
