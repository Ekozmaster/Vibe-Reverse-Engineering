# renderdoctools/scripts/info.py
# Capture metadata.
# Runs inside RenderDoc Python 3.6.

_write_output({
    "api": str(_cap.DriverName()),
    "machineIdent": _cap.RecordedMachineIdent(),
    "timestamp": _cap.TimestampBase(),
})
_shutdown()
sys.exit(0)
