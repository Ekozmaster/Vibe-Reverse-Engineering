# renderdoctools/scripts/frame_info.py
# Detailed frame metadata and statistics via GetFrameInfo().
# Runs inside RenderDoc Python 3.6.

frame = _controller.GetFrameInfo()
stats = frame.stats

# -- Shader stage names for per-stage stats --
stage_names = ["Vertex", "Hull", "Domain", "Geometry", "Pixel", "Compute"]

# -- Per-stage shader change stats --
shader_changes = []
for i, name in enumerate(stage_names):
    if i < len(stats.shaders):
        s = stats.shaders[i]
        shader_changes.append({
            "stage": name,
            "calls": s.calls,
            "sets": s.sets,
            "nulls": s.nulls,
            "redundants": s.redundants,
        })

# -- Per-stage constant buffer bind stats --
cbuffer_binds = []
for i, name in enumerate(stage_names):
    if i < len(stats.constants):
        c = stats.constants[i]
        cbuffer_binds.append({
            "stage": name,
            "calls": c.calls,
            "sets": c.sets,
            "nulls": c.nulls,
        })

# -- Per-stage sampler bind stats --
sampler_binds = []
for i, name in enumerate(stage_names):
    if i < len(stats.samplers):
        s = stats.samplers[i]
        sampler_binds.append({
            "stage": name,
            "calls": s.calls,
            "sets": s.sets,
            "nulls": s.nulls,
        })

# -- Per-stage resource bind stats --
resource_binds = []
for i, name in enumerate(stage_names):
    if i < len(stats.resources):
        r = stats.resources[i]
        resource_binds.append({
            "stage": name,
            "calls": r.calls,
            "sets": r.sets,
            "nulls": r.nulls,
        })

# -- Debug messages --
debug_msgs = []
for msg in frame.debugMessages:
    debug_msgs.append({
        "category": str(msg.category),
        "severity": str(msg.severity),
        "messageID": msg.messageID,
        "description": msg.description,
    })

result = {
    "frameNumber": frame.frameNumber,
    "captureTime": frame.captureTime,
    "fileOffset": frame.fileOffset,
    "uncompressedFileSize": frame.uncompressedFileSize,
    "compressedFileSize": frame.compressedFileSize,
    "persistentSize": frame.persistentSize,
    "initDataSize": frame.initDataSize,
    "containsAnnotations": frame.containsAnnotations,
    "api": str(_cap.DriverName()),
    "statsRecorded": stats.recorded,
    "draws": {
        "calls": stats.draws.calls,
        "instanced": stats.draws.instanced,
        "indirect": stats.draws.indirect,
    },
    "dispatches": {
        "calls": stats.dispatches.calls,
        "indirect": stats.dispatches.indirect,
    },
    "indexBinds": {
        "calls": stats.indices.calls,
        "sets": stats.indices.sets,
        "nulls": stats.indices.nulls,
    },
    "vertexBinds": {
        "calls": stats.vertices.calls,
        "sets": stats.vertices.sets,
        "nulls": stats.vertices.nulls,
    },
    "layoutBinds": {
        "calls": stats.layouts.calls,
        "sets": stats.layouts.sets,
        "nulls": stats.layouts.nulls,
    },
    "resourceUpdates": {
        "calls": stats.updates.calls,
        "clients": stats.updates.clients,
        "servers": stats.updates.servers,
    },
    "blendState": {
        "calls": stats.blends.calls,
        "sets": stats.blends.sets,
        "nulls": stats.blends.nulls,
        "redundants": stats.blends.redundants,
    },
    "depthStencilState": {
        "calls": stats.depths.calls,
        "sets": stats.depths.sets,
        "nulls": stats.depths.nulls,
        "redundants": stats.depths.redundants,
    },
    "rasterizerState": {
        "calls": stats.rasters.calls,
        "sets": stats.rasters.sets,
        "nulls": stats.rasters.nulls,
        "redundants": stats.rasters.redundants,
    },
    "outputTargets": {
        "calls": stats.outputs.calls,
        "sets": stats.outputs.sets,
        "nulls": stats.outputs.nulls,
    },
    "shaderChanges": shader_changes,
    "constantBufferBinds": cbuffer_binds,
    "samplerBinds": sampler_binds,
    "resourceBinds": resource_binds,
    "debugMessages": debug_msgs,
}

_write_output(result)
_shutdown()
sys.exit(0)
