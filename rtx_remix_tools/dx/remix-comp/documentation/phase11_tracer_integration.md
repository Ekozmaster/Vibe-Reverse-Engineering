# Phase 11: Tracer Integration

Integrate the DX9 frame tracer (`graphics/directx/dx9/tracer/`) as a module within remix-comp, replacing the standalone proxy deployment model.

## Goal

A single DLL that can both trace raw D3D9 calls (for analysis) and convert them to FFP (for Remix). The two modes are mutually exclusive — tracing captures the game's original calls, FFP converts them.

## Architecture

### Current tracer (standalone)

```
Game → tracer d3d9.dll (proxy) → real d3d9.dll
                ↓
         frame.jsonl (JSONL output)
```

- Separate C proxy DLL with code-generated hooks for all 119 device methods
- Captures args, backtraces, pointer-followed data (matrices, constants, shader bytecodes)
- Triggered via file-based signal (`proxy.ini` sentinel)
- Zero overhead when not capturing (single predicted-not-taken branch per call)
- Output analyzed offline with `python -m graphics.directx.dx9.tracer analyze`

### Integrated tracer (target)

```
Game → remix-comp.asi (proxy with FFP + tracer modules)
           ↓                        ↓
    FFP conversion           frame.jsonl (when capturing)
    (normal mode)            (tracer mode)
```

- `comp/modules/tracer.hpp/.cpp` — a `component_module`
- Shares the D3D9Device proxy already in d3d9ex.cpp
- ImGui toggle: F4 → "Tracer" tab → Start/Stop capture, frame count slider
- Same JSONL output format, compatible with existing `analyze.py`
- **FFP automatically disabled during capture** to record the game's unmodified calls

## Implementation Plan

### Step 1: Create tracer module skeleton

**Files:** `src/comp/modules/tracer.hpp`, `src/comp/modules/tracer.cpp`

```cpp
class tracer final : public shared::common::loader::component_module
{
public:
    tracer();
    ~tracer();

    static tracer* get();

    // State
    bool is_capturing() const;
    void start_capture(int num_frames);
    void stop_capture();

    // Called from D3D9Device interceptions (when capturing)
    void on_method_call(const char* method_name, UINT seq, /* arg capture */);

    // Called from Present
    void on_present();

    // ImGui panel
    void draw_imgui_panel();

private:
    HANDLE log_file_ = INVALID_HANDLE_VALUE;
    bool capturing_ = false;
    int frames_to_capture_ = 2;
    int frames_captured_ = 0;
    UINT sequence_ = 0;

    // Backtrace capture
    void capture_backtrace(void** frames, int max_frames);

    // JSONL writing
    void write_record(const char* json_line);
};
```

The module is **always registered** (not conditional on config) but does nothing unless `start_capture()` is called.

### Step 2: Port argument capture from d3d9_methods.py

The Python `d3d9_methods.py` contains argument specs for all 119 device methods — which arguments are pointers to follow, what data to capture (matrices, constants, shader bytecodes, vertex elements). This needs to be ported to C++ as a method dispatch table.

**Approach:** Generate a C++ header from the Python method database, similar to how `d3d9_trace_hooks.inc` is code-generated for the standalone tracer.

```
python -m graphics.directx.dx9.tracer codegen --format cpp -o tracer_dispatch.inc
```

This generates a dispatch table where each method has:
- Method name string
- Argument count and types
- Pointer-follow specs (e.g., "arg 3 is float*, read 16 floats")
- Whether to capture backtrace

The codegen approach keeps the single source of truth in Python while producing C++ that compiles into the module.

### Step 3: Wire D3D9Device interceptions for tracing

The key change: each method in `d3d9ex.cpp` already has FFP tracking calls. For tracing, we add a **second conditional path** that fires when `tracer::get()->is_capturing()`:

```cpp
HRESULT d3d9ex::D3D9Device::SetVertexShaderConstantF(UINT Start, CONST float* pData, UINT Count)
{
    // FFP tracking (always active unless FFP disabled)
    shared::common::ffp_state::get().on_set_vs_const_f(Start, pData, Count);

    // Tracer capture (only when actively capturing)
    if (auto* t = tracer::get(); t && t->is_capturing())
        t->on_set_vs_const_f(Start, pData, Count);

    return m_pIDirect3DDevice9->SetVertexShaderConstantF(Start, pData, Count);
}
```

**Critical:** The tracer calls go to the **real device**, not through FFP. When tracing starts, FFP is disabled (`ffp_state::set_enabled(false)`), so all draw calls pass through with original shaders. The tracer captures exactly what the game sends.

**Performance:** The `tracer::get()` null check + `is_capturing()` bool check is a single predicted-not-taken branch — same overhead as the standalone tracer's `g_capture_active` check.

### Step 4: Mutual exclusion with FFP

When tracing starts:
1. `ffp_state::get().disengage(dev)` — restore game's shaders
2. `ffp_state::get().set_enabled(false)` — disable FFP conversion
3. Begin JSONL capture

When tracing stops:
1. Close JSONL file
2. `ffp_state::get().set_enabled(true)` — re-enable FFP
3. FFP will re-engage on next draw call automatically

This is handled inside `tracer::start_capture()` / `tracer::stop_capture()`.

### Step 5: Backtrace capture

The standalone tracer uses `CaptureStackBackTrace()` (Win32 API) for backtraces. Port this directly:

```cpp
void tracer::capture_backtrace(void** frames, int max_frames)
{
    CaptureStackBackTrace(2, max_frames, frames, nullptr);
}
```

Backtrace addresses are written as hex in the JSONL. The existing `--resolve-addrs` option in `analyze.py` maps them to function names via retools.

### Step 6: JSONL output format

Match the existing format exactly so `analyze.py` works unchanged:

```json
{"seq":0,"frame":0,"method":"SetVertexShaderConstantF","args":{"StartRegister":0,"Vector4fCount":4},"data":{"pConstantData":[1.0,0.0,...]},"bt":["0x401234","0x401500"]}
```

Each record is one line. Fields:
- `seq` — global sequence number
- `frame` — frame index (0-based within capture)
- `method` — D3D9 method name
- `args` — scalar arguments
- `data` — pointer-followed data (matrices, constants, shader bytes)
- `bt` — backtrace addresses (optional, configurable)

Use `std::format` or a lightweight JSON builder (no dependency needed — the format is simple enough for manual string construction).

### Step 7: ImGui "Tracer" tab

Add to the F4 debug menu:

```
[ Tracer ]
  Capture State: IDLE / CAPTURING (frame 1/3)
  Frames to capture: [slider 1-10]
  Backtrace depth: [slider 0-16]
  [Start Capture] / [Stop Capture]

  Last capture: frame_20260329_184500.jsonl (2.3 MB, 12,847 records)
  Output dir: <game_dir>/captures/
```

The start button:
1. Creates output file with timestamp name
2. Disables FFP
3. Sets `capturing_ = true`
4. On each Present, increments frame counter until done

### Step 8: Shader disassembly (optional, advanced)

The standalone tracer captures shader bytecodes and disassembles them in-process using the game's own `d3dx9_XX.dll` (`D3DXDisassembleShader`). This is the trickiest part to port because:

- Need to find which d3dx9 DLL the game loaded (or load one ourselves)
- `D3DXDisassembleShader` returns an `ID3DXBuffer*` with the disassembly text
- The disassembly includes CTAB (constant table) names, which is what `--shader-map` uses

**Approach:** Make this optional. If a d3dx9 DLL is available, disassemble. Otherwise, write raw shader bytecodes as hex arrays and let `analyze.py --shader-map` handle disassembly offline (it already supports this path).

### Step 9: Config and registration

Add to `remix-comp.ini`:

```ini
[Tracer]
BacktraceDepth=8
OutputDir=captures
```

The tracer module is always registered in `comp.cpp` (unconditionally) since it has zero overhead when idle.

## File Summary

| File | Action |
|------|--------|
| `src/comp/modules/tracer.hpp` | NEW — module class |
| `src/comp/modules/tracer.cpp` | NEW — capture logic, JSONL output |
| `src/comp/modules/tracer_dispatch.inc` | NEW — code-generated method dispatch table |
| `src/comp/modules/d3d9ex.cpp` | MODIFY — add tracer capture calls alongside FFP calls |
| `src/comp/modules/imgui.cpp` | MODIFY — add "Tracer" tab |
| `src/comp/comp.cpp` | MODIFY — register tracer module |
| `graphics/directx/dx9/tracer/cli.py` | MODIFY — add `codegen --format cpp` option |

## Advantages Over Standalone

| Feature | Standalone | Integrated |
|---------|-----------|------------|
| Deployment | Separate d3d9.dll + proxy.ini | Same DLL, always available |
| Trigger | File-based sentinel | ImGui button, instant |
| Access to FFP state | None | Full (tracked matrices, decoded decls) |
| Before/after comparison | Two separate deploys | Toggle FFP on/off between captures |
| Shader disassembly | In-process via game's d3dx9 | Same, or offline fallback |
| Analysis | Same `analyze.py` | Same `analyze.py` |
| Overhead when idle | ~0 (one branch per call) | ~0 (one branch per call) |

## Risks and Mitigations

**Risk:** Adding tracer calls to every D3D9Device method bloats d3d9ex.cpp.
**Mitigation:** Use the code-generated dispatch table. Each method gets one line: `TRACE_IF_ACTIVE(tracer, "MethodName", seq++, args...)`. The macro expands to the null check + bool check + dispatch.

**Risk:** JSONL output slows down the game during capture.
**Mitigation:** Write to a memory buffer, flush to disk on frame boundary. Use overlapped I/O if needed. The standalone tracer already handles this with a 4MB ring buffer.

**Risk:** FFP/tracer state machine gets confused if game crashes during capture.
**Mitigation:** `on_reset()` and destructor both call `stop_capture()` and re-enable FFP. The JSONL file is flushed per-frame so partial captures are still usable.

## Testing

1. Build remix-comp with tracer module
2. Deploy to a game that works with FFP conversion
3. Start game, verify FFP works (geometry visible through Remix)
4. Open ImGui (F4) → Tracer tab → Start Capture (3 frames)
5. Verify FFP disengages during capture (geometry reverts to shader rendering)
6. Verify JSONL file created in `captures/` directory
7. Run `python -m graphics.directx.dx9.tracer analyze <file.jsonl> --summary`
8. Verify output matches standalone tracer format
9. Stop capture, verify FFP re-engages automatically
