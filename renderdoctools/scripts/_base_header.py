# ── Base header for renderdoctools analysis scripts ──
# Runs inside RenderDoc's embedded Python 3.6.
# _CONFIG_PATH is injected above this header by core.py.

import json
import sys
import os

# Load config
with open(_CONFIG_PATH, "r") as _f:
    _cfg = json.load(_f)

_CAPTURE = _cfg["capture"]
_OUTPUT = _cfg["output"]


def _write_output(data):
    """Write result JSON and exit cleanly."""
    with open(_OUTPUT, "w") as f:
        json.dump(data, f)


def _write_error(msg):
    """Write error JSON and exit."""
    _write_output({"error": str(msg)})
    sys.exit(1)


# ── Load capture ──
import renderdoc as rd

rd.InitialiseReplay(rd.GlobalEnvironment(), [])

_cap = rd.OpenCaptureFile()
_result = _cap.OpenFile(_CAPTURE, "", None)
if _result != rd.ResultCode.Succeeded:
    _write_error("Failed to open capture: " + str(_result))

_result, _controller = _cap.OpenCapture(rd.ReplayOptions(), None)
if _result != rd.ResultCode.Succeeded:
    _cap.Shutdown()
    rd.ShutdownReplay()
    _write_error("Failed to replay capture: " + str(_result))


def _shutdown():
    """Clean shutdown of replay."""
    _controller.Shutdown()
    _cap.Shutdown()
    rd.ShutdownReplay()
