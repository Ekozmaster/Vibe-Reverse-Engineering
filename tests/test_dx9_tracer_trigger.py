"""``dx9tracer trigger``: what it reports about a capture, with and without a tracer answering.

The tracer DLL is played by a thread that does what the DLL does with the files
in the game folder: read the trigger file, write a first progress line carrying
the trigger's id, take the trigger file away, then write more progress, the
last line ending in "done" once the capture file is complete.
"""

import argparse
import re
import sys
import threading
import time
from pathlib import Path

import pytest

from graphics.directx.dx9.tracer import cli

EARLIER_ID = "0123456789abcdef"

holds_open_files_against_removal = pytest.mark.skipif(
    sys.platform != "win32", reason="only Windows refuses to remove or replace a file another handle holds open")


@pytest.fixture(autouse=True)
def short_waits(monkeypatch):
    monkeypatch.setattr(cli, "_WAIT_TIMEOUT_SECONDS", 1.5)
    monkeypatch.setattr(cli, "_POLL_SECONDS", 0.02)


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

    def test_last_frame_is_not_complete_until_the_tracer_reports_done(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0 {id}\n", "2 80 {id}\n", "2 80 {id} done\n"], pause=0.4)
        started = time.time()
        status = _trigger(tmp_path)
        assert status == 0
        assert time.time() - started >= 0.8    # both pauses come before the done line
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

    def test_capture_done_short_of_the_frames_asked_for_is_reported_at_once(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0 {id}\n", "1 40 {id} done\n"])
        started = time.time()
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "frame 1 of 2" in out
        assert time.time() - started < 1.2    # well inside the 1.5 s timeout

    def test_capture_that_stops_short_without_done_is_reported_with_the_frame_it_reached(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0 {id}\n", "1 40 {id}\n"])
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "frame 1 of 2" in out


class TestTracerTakesTheTriggerWithoutReporting:
    """The first progress line is written before the trigger goes, so its absence is known at once."""

    def assert_named_at_once(self, tmp_path, capsys, started):
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "took the trigger but reported no progress" in out
        assert time.time() - started < 1.2    # well inside the 1.5 s timeout
        return out

    def test_tracer_that_writes_no_progress_file(self, tmp_path, capsys):
        _tracer(tmp_path)
        self.assert_named_at_once(tmp_path, capsys, time.time())

    def test_tracer_that_leaves_the_progress_of_an_earlier_capture(self, tmp_path, capsys):
        (tmp_path / "dxtrace_progress.txt").write_text(f"2 80 {EARLIER_ID} done\n")
        _tracer(tmp_path)
        self.assert_named_at_once(tmp_path, capsys, time.time())

    def test_tracer_whose_progress_does_not_name_the_trigger(self, tmp_path, capsys):
        def capture_as_a_tracer_without_ids_does():
            _trigger_id(tmp_path)
            (tmp_path / "dxtrace_capture.trigger").unlink()
            (tmp_path / "dxtrace_progress.txt").write_text("2 80 done\n")

        (tmp_path / "dxtrace_progress.txt").write_text("2 80 done\n")
        _in_thread(capture_as_a_tracer_without_ids_does)
        self.assert_named_at_once(tmp_path, capsys, time.time())

    def test_tracer_is_not_said_to_be_out_of_date_for_certain(self, tmp_path, capsys):
        _tracer(tmp_path)
        out = self.assert_named_at_once(tmp_path, capsys, time.time())
        assert "could not write" in out
        assert "dxtrace_proxy.log" in out


class TestTracerCannotStartTheCapture:
    REASON = r"cannot open C:\Games\My Game\dxtrace_frame.jsonl: Permission denied"

    def test_reason_the_tracer_gives_is_reported_at_once(self, tmp_path, capsys):
        _tracer(tmp_path, progress=[f"0 0 {{id}} failed {self.REASON}\n"], capture=None)
        started = time.time()
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status == 1
        assert f"[error] the tracer could not start the capture: {self.REASON}\n" in out
        assert "predates" not in out
        assert "Capture complete" not in out
        assert time.time() - started < 1.2    # well inside the 1.5 s timeout

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
