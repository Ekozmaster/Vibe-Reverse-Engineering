# renderdoctools/scripts/debug_shader.py
# Shader debugging via DebugVertex / DebugPixel / DebugThread.
# Runs inside RenderDoc Python 3.6.

event_id = _cfg.get("event_id")
mode = _cfg.get("mode", "")

if event_id is None:
    _write_error("--event is required")
if mode not in ("vertex", "pixel", "compute"):
    _write_error("--mode must be vertex, pixel, or compute")

_controller.SetFrameEvent(event_id, True)
state = _controller.GetPipelineState()

# ── Determine which stage we are debugging ──
if mode == "vertex":
    stage_enum = rd.ShaderStage.Vertex
elif mode == "pixel":
    stage_enum = rd.ShaderStage.Pixel
elif mode == "compute":
    stage_enum = rd.ShaderStage.Compute

refl = state.GetShaderReflection(stage_enum)
if refl is None:
    _write_error("No %s shader bound at EID %d" % (mode, event_id))

if not refl.debugInfo.debuggable:
    _write_error("Shader at EID %d (%s stage) is not debuggable" % (event_id, mode))


# ── Helper: extract values from a ShaderVariable ──
def _extract_var(var):
    """Serialise a ShaderVariable to a JSON-friendly dict."""
    info = {
        "name": var.name,
        "type": str(var.type),
        "rows": var.rows,
        "columns": var.columns,
    }
    if len(var.members) > 0:
        info["members"] = [_extract_var(m) for m in var.members]
    else:
        count = max(var.rows, 1) * max(var.columns, 1)
        t = var.type
        if t == rd.VarType.Float:
            info["float"] = [var.value.f32v[i] for i in range(count)]
        elif t == rd.VarType.Double:
            info["float"] = [var.value.f64v[i] for i in range(count)]
        elif t == rd.VarType.Half:
            # f16v stores raw halfs; expose as float via f32v reinterpret is
            # unreliable, so just pass the raw u16 bits and the float array.
            info["float"] = [float(var.value.f16v[i]) for i in range(count)]
        elif t in (rd.VarType.SInt, rd.VarType.SShort, rd.VarType.SLong, rd.VarType.SByte):
            info["int"] = [var.value.s32v[i] for i in range(count)]
        elif t in (rd.VarType.UInt, rd.VarType.UShort, rd.VarType.ULong, rd.VarType.UByte, rd.VarType.Bool):
            info["uint"] = [var.value.u32v[i] for i in range(count)]
        else:
            # Fallback: expose both float and uint interpretations
            info["float"] = [var.value.f32v[i] for i in range(count)]
            info["uint"] = [var.value.u32v[i] for i in range(count)]
    return info


# ── Helper: extract source variable mapping at an instruction ──
def _extract_source_var(svm):
    return {
        "name": svm.name,
        "type": str(svm.type),
        "rows": svm.rows,
        "columns": svm.columns,
        "signatureIndex": svm.signatureIndex,
    }


# ── Start the debug trace ──
trace = None

if mode == "vertex":
    vertex_index = _cfg.get("vertex_index")
    if vertex_index is None:
        _write_error("--vertex-index is required for vertex mode")
    instance = _cfg.get("instance", 0)
    view = _cfg.get("view", 0)
    raw_index = _cfg.get("raw_index", vertex_index)
    trace = _controller.DebugVertex(vertex_index, instance, raw_index, view)

elif mode == "pixel":
    x = _cfg.get("x")
    y = _cfg.get("y")
    if x is None or y is None:
        _write_error("--x and --y are required for pixel mode")
    inputs = rd.DebugPixelInputs()
    sample = _cfg.get("sample", None)
    primitive = _cfg.get("primitive", None)
    if sample is not None:
        inputs.sample = sample
    if primitive is not None:
        inputs.primitive = primitive
    trace = _controller.DebugPixel(x, y, inputs)

elif mode == "compute":
    group = _cfg.get("group")
    thread = _cfg.get("thread")
    if group is None or thread is None:
        _write_error("--group and --thread are required for compute mode")
    trace = _controller.DebugThread(tuple(group), tuple(thread))

if trace is None or trace.debugger is None:
    if trace is not None:
        _controller.FreeTrace(trace)
    _write_error("Failed to start shader debug at EID %d (mode=%s). "
                  "The shader may not be debuggable or the invocation is invalid." % (event_id, mode))


# ── Collect trace inputs ──
trace_inputs = [_extract_var(v) for v in trace.inputs]

# ── Collect constant blocks snapshot ──
trace_cbuffers = [_extract_var(v) for v in trace.constantBlocks]

# ── Collect source variable mappings from trace level ──
trace_source_vars = [_extract_source_var(sv) for sv in trace.sourceVars]

# ── Step through the shader ──
max_steps = _cfg.get("max_steps", 10000)
steps = []
variables = {}  # accumulated variable state by name

step_count = 0
while True:
    states = _controller.ContinueDebug(trace.debugger)
    if len(states) == 0:
        break

    for s in states:
        step_info = {
            "stepIndex": s.stepIndex,
            "nextInstruction": s.nextInstruction,
            "flags": int(s.flags),
        }

        # Record variable changes
        changes = []
        for change in s.changes:
            ch = {}
            if change.before.name:
                ch["before"] = _extract_var(change.before)
            if change.after.name:
                ch["after"] = _extract_var(change.after)
                variables[change.after.name] = _extract_var(change.after)
            changes.append(ch)
        step_info["changes"] = changes

        # Source location from instInfo (binary search the sparse array)
        inst = s.nextInstruction
        src_info = None
        lo, hi = 0, len(trace.instInfo) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if trace.instInfo[mid].instruction == inst:
                src_info = trace.instInfo[mid]
                break
            elif trace.instInfo[mid].instruction < inst:
                lo = mid + 1
            else:
                hi = mid - 1
        # Lower-bound fallback
        if src_info is None and len(trace.instInfo) > 0:
            idx = lo - 1 if lo > 0 else 0
            src_info = trace.instInfo[idx]

        if src_info is not None:
            li = src_info.lineInfo
            step_info["source"] = {
                "fileIndex": li.fileIndex,
                "lineStart": li.lineStart,
                "lineEnd": li.lineEnd,
                "colStart": li.colStart,
                "colEnd": li.colEnd,
                "disassemblyLine": li.disassemblyLine,
            }
            # Per-instruction source variable mappings
            if len(src_info.sourceVars) > 0:
                step_info["sourceVars"] = [_extract_source_var(sv) for sv in src_info.sourceVars]

        steps.append(step_info)
        step_count += 1

    if step_count >= max_steps:
        break


# ── Collect final variable state ──
final_vars = variables

# ── Source files from debug info ──
source_files = []
try:
    if refl.debugInfo and len(refl.debugInfo.files) > 0:
        for f in refl.debugInfo.files:
            source_files.append({
                "index": len(source_files),
                "filename": f.filename,
            })
except Exception:
    pass

# ── Build output ──
output = {
    "event_id": event_id,
    "mode": mode,
    "stage": str(trace.stage),
    "totalSteps": step_count,
    "inputs": trace_inputs,
    "constantBlocks": trace_cbuffers,
    "sourceVars": trace_source_vars,
    "sourceFiles": source_files,
    "steps": steps,
    "finalState": final_vars,
}

_controller.FreeTrace(trace)
_write_output(output)
_shutdown()
sys.exit(0)
