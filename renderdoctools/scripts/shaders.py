# renderdoctools/scripts/shaders.py
# Shader disassembly and constant buffer inspection.
# Runs inside RenderDoc Python 3.6.

event_id = _cfg.get("event_id")
stage_filter = _cfg.get("stage", "")
show_cbuffers = _cfg.get("cbuffers", False)

if event_id is None:
    _write_error("--event is required")

_controller.SetFrameEvent(event_id, True)
state = _controller.GetPipelineState()

targets = _controller.GetDisassemblyTargets(True)
target = targets[0] if targets else ""

pipe = state.GetGraphicsPipelineObject()

STAGES = [
    ("vertex", rd.ShaderStage.Vertex),
    ("hull", rd.ShaderStage.Hull),
    ("domain", rd.ShaderStage.Domain),
    ("geometry", rd.ShaderStage.Geometry),
    ("pixel", rd.ShaderStage.Pixel),
    ("compute", rd.ShaderStage.Compute),
]

shaders = {}

for stage_name, stage_enum in STAGES:
    if stage_filter and stage_filter != stage_name:
        continue

    refl = state.GetShaderReflection(stage_enum)
    if refl is None:
        continue

    entry = state.GetShaderEntryPoint(stage_enum)
    disasm = _controller.DisassembleShader(pipe, refl, target)

    stage_data = {
        "entryPoint": entry,
        "disassembly": disasm,
    }

    if show_cbuffers:
        cbuffers = []
        for i, cb in enumerate(refl.constantBlocks):
            cb_bind = state.GetConstantBlock(stage_enum, i, 0)
            try:
                variables = _controller.GetCBufferVariableContents(
                    pipe, refl.resourceId, stage_enum, entry, i,
                    cb_bind.descriptor.resource, cb_bind.descriptor.byteOffset,
                    cb_bind.descriptor.byteSize
                )
                vars_data = []
                for v in variables:
                    var_entry = {"name": v.name, "rows": v.rows, "columns": v.columns}
                    if len(v.members) == 0:
                        vals = []
                        for r in range(v.rows):
                            for c in range(v.columns):
                                vals.append(v.value.f32v[r * v.columns + c])
                        var_entry["values"] = vals
                    vars_data.append(var_entry)
                cbuffers.append({"name": cb.name, "index": i, "variables": vars_data})
            except Exception as e:
                cbuffers.append({"name": cb.name, "index": i, "error": str(e)})
        stage_data["constantBuffers"] = cbuffers

    shaders[stage_name] = stage_data

_write_output({"event_id": event_id, "disasmTarget": target, "shaders": shaders})
_shutdown()
sys.exit(0)
