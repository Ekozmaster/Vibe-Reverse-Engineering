# renderdoctools/scripts/custom_shader.py
# Build and apply a custom visualization shader, then save the result.
# Runs inside RenderDoc Python 3.6.

event_id = _cfg.get("event_id")
shader_source = _cfg.get("shader_source", "")
output_path = _cfg.get("output_path", "")
encoding_name = _cfg.get("encoding", "")
entry_point = _cfg.get("entry_point", "main")

if event_id is None:
    _write_error("--event is required")
if not shader_source:
    _write_error("--source is required (shader source code)")
if not output_path:
    _write_error("--output is required (path to save result)")

_controller.SetFrameEvent(event_id, True)

# --- Determine shader encoding ---
supported = _controller.GetCustomShaderEncodings()
if not supported:
    _write_error("No custom shader encodings supported by this capture's API")

ENCODING_NAMES = {
    "hlsl": rd.ShaderEncoding.HLSL,
    "glsl": rd.ShaderEncoding.GLSL,
    "spirv": rd.ShaderEncoding.SPIRV,
    "dxbc": rd.ShaderEncoding.DXBC,
    "dxil": rd.ShaderEncoding.DXIL,
    "spirvasm": rd.ShaderEncoding.SPIRVAsm,
}

if encoding_name:
    key = encoding_name.lower().strip()
    if key not in ENCODING_NAMES:
        _write_error("Unknown encoding '%s'. Supported: %s" % (
            encoding_name, ", ".join(ENCODING_NAMES.keys())))
    source_encoding = ENCODING_NAMES[key]
    if source_encoding not in supported:
        _write_error("Encoding '%s' not supported for this capture. Supported: %s" % (
            encoding_name, ", ".join(str(e) for e in supported)))
else:
    # Auto-detect: prefer HLSL, then GLSL, then first available
    source_encoding = supported[0]
    for preferred in [rd.ShaderEncoding.HLSL, rd.ShaderEncoding.GLSL]:
        if preferred in supported:
            source_encoding = preferred
            break

# --- Build the custom shader ---
compile_flags = rd.ShaderCompileFlags()
source_bytes = shader_source.encode("utf-8") if isinstance(shader_source, str) else shader_source

shader_id, errors = _controller.BuildCustomShader(
    entry_point,
    source_encoding,
    source_bytes,
    compile_flags,
    rd.ShaderStage.Pixel,
)

if shader_id == rd.ResourceId.Null():
    _write_error("Shader compilation failed: %s" % errors)

# --- Find the target texture (first color output of the draw) ---
def _find_action(eid):
    """Find action by event ID, searching children recursively."""
    def _search(action):
        cur = action
        while cur is not None:
            if cur.eventId == eid:
                return cur
            for child in cur.children:
                found = _search(child)
                if found is not None:
                    return found
            cur = cur.next
        return None
    for root in _controller.GetRootActions():
        found = _search(root)
        if found is not None:
            return found
    return None

action = _find_action(event_id)
if action is None:
    _controller.FreeCustomShader(shader_id)
    _write_error("Event %d not found" % event_id)

# Pick the first valid color output as the texture to apply the custom shader to
target_tex = rd.ResourceId.Null()
if action.outputs:
    for o in action.outputs:
        if o != rd.ResourceId.Null():
            target_tex = o
            break

if target_tex == rd.ResourceId.Null():
    _controller.FreeCustomShader(shader_id)
    _write_error("No render target found at event %d to apply custom shader to" % event_id)

# --- Create a headless texture output and render with the custom shader ---
# Look up target texture dimensions
_all_textures = {}
for t in _controller.GetTextures():
    _all_textures[int(t.resourceId)] = t

tex_desc = _all_textures.get(int(target_tex))
tex_w = tex_desc.width if tex_desc else 1920
tex_h = tex_desc.height if tex_desc else 1080

wdata = rd.CreateHeadlessWindowingData(tex_w, tex_h)
output = _controller.CreateOutput(wdata, rd.ReplayOutputType.Texture)

tex_display = rd.TextureDisplay()
tex_display.resourceId = target_tex
tex_display.customShaderId = shader_id
tex_display.rangeMin = 0.0
tex_display.rangeMax = 1.0
tex_display.scale = 1.0
tex_display.red = True
tex_display.green = True
tex_display.blue = True
tex_display.alpha = True
tex_display.linearDisplayAsGamma = True
tex_display.rawOutput = False

output.SetTextureDisplay(tex_display)
output.Display()

# --- Save the custom shader result texture ---
custom_tex_id = output.GetCustomShaderTexID()

if custom_tex_id == rd.ResourceId.Null():
    _controller.FreeCustomShader(shader_id)
    _write_error("Custom shader produced no output texture")

# Determine file format from extension
ext = output_path.rsplit(".", 1)[-1].lower() if "." in output_path else "png"
FORMAT_MAP = {
    "png": rd.FileType.PNG,
    "jpg": rd.FileType.JPG,
    "dds": rd.FileType.DDS,
    "hdr": rd.FileType.HDR,
    "bmp": rd.FileType.BMP,
    "tga": rd.FileType.TGA,
}
file_type = FORMAT_MAP.get(ext, rd.FileType.PNG)

os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)

texsave = rd.TextureSave()
texsave.resourceId = custom_tex_id
texsave.alpha = rd.AlphaMapping.Preserve
texsave.mip = 0
texsave.slice.sliceIndex = 0
texsave.destType = file_type
_controller.SaveTexture(texsave, output_path)

# --- Build encoding name for output ---
ENC_TO_NAME = {}
for name, enc in ENCODING_NAMES.items():
    ENC_TO_NAME[enc] = name
encoding_used = ENC_TO_NAME.get(source_encoding, str(source_encoding))

# --- Clean up ---
_controller.FreeCustomShader(shader_id)

_write_output({
    "success": True,
    "event_id": event_id,
    "shader_id": str(int(shader_id)),
    "encoding": encoding_used,
    "entry_point": entry_point,
    "target_texture": str(int(target_tex)),
    "custom_texture": str(int(custom_tex_id)),
    "saved": output_path,
    "compile_warnings": errors if errors else "",
})
_shutdown()
sys.exit(0)
