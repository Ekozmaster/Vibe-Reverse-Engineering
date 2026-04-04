# renderdoctools/scripts/pipeline.py
# Pipeline state inspection at a specific event.
# Runs inside RenderDoc Python 3.6.

event_id = _cfg.get("event_id")
stage_filter = _cfg.get("stage", "")

if event_id is None:
    _write_error("--event is required")

_controller.SetFrameEvent(event_id, True)
state = _controller.GetPipelineState()

STAGES = [
    ("vertex", rd.ShaderStage.Vertex),
    ("hull", rd.ShaderStage.Hull),
    ("domain", rd.ShaderStage.Domain),
    ("geometry", rd.ShaderStage.Geometry),
    ("pixel", rd.ShaderStage.Pixel),
    ("compute", rd.ShaderStage.Compute),
]

pipeline = {"event_id": event_id, "stages": {}}

for stage_name, stage_enum in STAGES:
    if stage_filter and stage_filter != stage_name:
        continue

    refl = state.GetShaderReflection(stage_enum)
    if refl is None:
        continue

    stage_info = {
        "bound": True,
        "entryPoint": refl.entryPoint,
        "debugInfo": "",
        "constantBuffers": [],
        "readOnlyResources": [],
        "readWriteResources": [],
    }

    # Safe debugInfo access
    try:
        if refl.debugInfo and len(refl.debugInfo.files) > 0:
            stage_info["debugInfo"] = refl.debugInfo.files[0].filename
    except Exception:
        pass

    for i, cb in enumerate(refl.constantBlocks):
        stage_info["constantBuffers"].append({
            "index": i,
            "name": cb.name,
            "byteSize": cb.byteSize,
        })

    for i, res in enumerate(refl.readOnlyResources):
        stage_info["readOnlyResources"].append({
            "index": i,
            "name": res.name,
            "type": str(res.resType),
        })

    for i, res in enumerate(refl.readWriteResources):
        stage_info["readWriteResources"].append({
            "index": i,
            "name": res.name,
            "type": str(res.resType),
        })

    pipeline["stages"][stage_name] = stage_info

# Render targets
action = _controller.GetRootActions()[0]
cur = action
while cur is not None:
    if cur.eventId == event_id:
        action = cur
        break
    cur = cur.next

outputs = []
for o in action.outputs:
    if o != rd.ResourceId.Null():
        outputs.append(str(int(o)))
pipeline["renderTargets"] = outputs

depth_id = action.depthOut
pipeline["depthTarget"] = str(int(depth_id)) if depth_id != rd.ResourceId.Null() else None

_write_output(pipeline)
_shutdown()
sys.exit(0)
