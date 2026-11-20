"""``dx9tracer trigger``: what it reports about a capture, with and without a tracer answering.

The tracer DLL is played by a thread that does what the DLL does with the files
in the game folder: take the trigger file away, then write progress, the last
line ending in "done" once the capture file is complete.
"""

import argparse
import threading
import time
from pathlib import Path

import pytest

from graphics.directx.dx9.tracer import cli


@pytest.fixture(autouse=True)
def short_waits(monkeypatch):
    monkeypatch.setattr(cli, "_WAIT_TIMEOUT_SECONDS", 1.5)
    monkeypatch.setattr(cli, "_POLL_SECONDS", 0.02)
    monkeypatch.setattr(cli, "_PROGRESS_GRACE_SECONDS", 0.3)


def _trigger(game_dir, wait=True, frames=2) -> int:
    """Run the command; return its exit status."""
    args = argparse.Namespace(game_dir=str(game_dir), frames=frames, delay=0, wait=wait)
    try:
        cli.cmd_trigger(args)
    except SystemExit as exit_:
        return exit_.code
    return 0


def _tracer(game_dir, progress=(), capture=b'{"seq":0}\n', pause=0.05):
    """Start a thread that takes the trigger file and then writes each *progress* line in turn.

    It writes *capture* to dxtrace_frame.jsonl with each line, as the
    standalone tracer does; None plays the remix-comp-proxy tracer, which
    writes its capture to its own output folder. It waits *pause* seconds
    after each line.
    """
    def run():
        trigger = game_dir / "dxtrace_capture.trigger"
        deadline = time.time() + 5
        while not trigger.exists() and time.time() < deadline:
            time.sleep(0.005)
        trigger.unlink()
        for line in progress:
            if capture is not None:
                (game_dir / "dxtrace_frame.jsonl").write_bytes(capture)
            (game_dir / "dxtrace_progress.txt").write_text(line)
            time.sleep(pause)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


class TestShippedTracer:
    def test_takes_the_frame_count_from_the_trigger_file(self):
        dll = (Path(cli.__file__).parent / "bin" / "d3d9.dll").read_bytes()
        assert b"frames=" in dll


class TestNoTracerAnswers:
    @pytest.fixture
    def stale_folder(self, tmp_path):
        """A folder that still holds the files of an earlier capture."""
        (tmp_path / "dxtrace_progress.txt").write_text("2 4711\n")
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
        assert (stale_folder / "dxtrace_capture.trigger").read_text() == "frames=2\n"
        assert not (stale_folder / "dxtrace_progress.txt").exists()


class TestTracerAnswers:
    def test_capture_the_tracer_reports_done_at_its_last_frame_is_complete(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0\n", "1 40\n", "2 80 done\n"])
        assert _trigger(tmp_path) == 0
        assert "Capture complete" in capsys.readouterr().out

    def test_capture_into_a_file_held_open_since_device_creation_is_named(self, tmp_path, capsys):
        # With CaptureInit on, the tracer opens the JSONL at device creation and only flushes it later
        with open(tmp_path / "dxtrace_frame.jsonl", "w") as held_open:
            held_open.write('{"frame":-1,"seq":0}\n')
            held_open.flush()

            def append_capture():
                trigger = tmp_path / "dxtrace_capture.trigger"
                while not trigger.exists():
                    time.sleep(0.005)
                trigger.unlink()
                time.sleep(0.05)
                held_open.write('{"frame":0,"seq":1}\n')
                held_open.flush()
                (tmp_path / "dxtrace_progress.txt").write_text("2 2 done\n")

            threading.Thread(target=append_capture, daemon=True).start()
            assert _trigger(tmp_path) == 0
        assert f"Capture complete: {tmp_path / 'dxtrace_frame.jsonl'}" in capsys.readouterr().out

    def test_last_frame_is_not_complete_until_the_tracer_reports_done(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0\n", "2 80\n", "2 80 done\n"], pause=0.4)
        started = time.time()
        status = _trigger(tmp_path)
        assert status == 0
        assert time.time() - started >= 0.8    # both pauses come before the done line
        assert "Capture complete" in capsys.readouterr().out

    def test_last_frame_without_done_is_reported_as_not_written_in_full(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0\n", "1 40\n", "2 80\n"])
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "never reported the capture file written in full" in out

    def test_capture_done_short_of_the_frames_asked_for_is_reported_at_once(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0\n", "1 40 done\n"])
        started = time.time()
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "frame 1 of 2" in out
        assert time.time() - started < 1.2    # well inside the 1.5 s timeout

    def test_capture_that_stops_short_without_done_is_reported_with_the_frame_it_reached(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0\n", "1 40\n"])
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "frame 1 of 2" in out

    def test_tracer_that_takes_the_trigger_and_reports_nothing_is_named_as_such(self, tmp_path, capsys):
        _tracer(tmp_path)
        started = time.time()
        status = _trigger(tmp_path)
        out = capsys.readouterr().out
        assert status != 0
        assert "Capture complete" not in out
        assert "took the trigger but reported no progress" in out
        assert time.time() - started < 1.2    # well inside the 1.5 s timeout


class TestProxyTracerAnswers:
    """The remix-comp-proxy tracer reports progress the same way, but writes its capture to its OutputDir."""

    def test_capture_the_proxy_reports_done_is_complete(self, tmp_path, capsys):
        _tracer(tmp_path, progress=["0 0\n", "1 40\n", "2 80 done\n"], capture=None)
        assert _trigger(tmp_path) == 0
        out = capsys.readouterr().out
        assert "Capture complete" in out
        assert "OutputDir" in out

    def test_capture_file_of_an_earlier_standalone_capture_is_not_named(self, tmp_path, capsys):
        (tmp_path / "dxtrace_frame.jsonl").write_text('{"seq":0}\n')
        _tracer(tmp_path, progress=["0 0\n", "2 80 done\n"], capture=None)
        assert _trigger(tmp_path) == 0
        assert "dxtrace_frame.jsonl" not in capsys.readouterr().out
