# renderdoctools/scripts/textures.py
# Texture listing and export at a specific event.
# Runs inside RenderDoc Python 3.6.

event_id = _cfg.get("event_id")
save_all_dir = _cfg.get("save_all", "")
save_rid = _cfg.get("save_rid", "")
save_format = _cfg.get("format", "png")
save_output = _cfg.get("save_output", "")

if event_id is None:
    _write_error("--event is required")

_controller.SetFrameEvent(event_id, True)
state = _controller.GetPipelineState()

FORMAT_MAP = {
    "png": rd.FileType.PNG,
    "jpg": rd.FileType.JPG,
    "dds": rd.FileType.DDS,
    "hdr": rd.FileType.HDR,
    "bmp": rd.FileType.BMP,
    "tga": rd.FileType.TGA,
}

# Build a lookup of all textures in the capture
_all_textures = {}
for t in _controller.GetTextures():
    _all_textures[int(t.resourceId)] = t


def get_texture_info(rid):
    """Get texture metadata for a resource ID."""
    rid_int = int(rid)
    if rid_int not in _all_textures:
        return None
    tex_desc = _all_textures[rid_int]
    # Build format string safely
    fmt = tex_desc.format
    try:
        fmt_str = fmt.Name()
    except Exception:
        try:
            fmt_str = "%s_%s%d" % (str(fmt.type), str(fmt.compType), fmt.compByteWidth * 8)
        except Exception:
            fmt_str = "unknown"

    return {
        "resourceId": str(rid_int),
        "name": tex_desc.name if hasattr(tex_desc, "name") else "",
        "width": tex_desc.width,
        "height": tex_desc.height,
        "depth": tex_desc.depth,
        "mips": tex_desc.mips,
        "arraysize": tex_desc.arraysize,
        "format": fmt_str,
        "type": str(tex_desc.type),
    }


def save_texture(rid, filepath, fmt="png"):
    """Save a texture to disk."""
    texsave = rd.TextureSave()
    texsave.resourceId = rid
    texsave.alpha = rd.AlphaMapping.Preserve
    texsave.mip = 0
    texsave.slice.sliceIndex = 0
    texsave.destType = FORMAT_MAP.get(fmt, rd.FileType.PNG)
    _controller.SaveTexture(texsave, filepath)


# Collect all bound textures at this event
textures = []
seen = set()

# From render targets
for root_action in _controller.GetRootActions():
    cur = root_action
    while cur is not None:
        if cur.eventId == event_id:
            for o in cur.outputs:
                if o != rd.ResourceId.Null() and int(o) not in seen:
                    seen.add(int(o))
                    info = get_texture_info(o)
                    if info:
                        info["binding"] = "renderTarget"
                        textures.append(info)
            if cur.depthOut != rd.ResourceId.Null() and int(cur.depthOut) not in seen:
                seen.add(int(cur.depthOut))
                info = get_texture_info(cur.depthOut)
                if info:
                    info["binding"] = "depthTarget"
                    textures.append(info)
            break
        cur = cur.next

# From shader SRVs
for stage_name, stage_enum in [("vertex", rd.ShaderStage.Vertex), ("pixel", rd.ShaderStage.Pixel),
                                ("geometry", rd.ShaderStage.Geometry), ("compute", rd.ShaderStage.Compute)]:
    refl = state.GetShaderReflection(stage_enum)
    if refl is None:
        continue
    try:
        ro_binds = state.GetReadOnlyResources(stage_enum)
    except Exception:
        continue
    for i, res in enumerate(refl.readOnlyResources):
        if i < len(ro_binds) and len(ro_binds[i].resources) > 0:
            bind = ro_binds[i].resources[0]
            rid = bind.resourceId
            if rid != rd.ResourceId.Null() and int(rid) not in seen:
                seen.add(int(rid))
                info = get_texture_info(rid)
                if info:
                    info["binding"] = "%s:SRV[%d] %s" % (stage_name, i, res.name)
                    textures.append(info)

# Handle save operations
saved = []
if save_all_dir:
    os.makedirs(save_all_dir, exist_ok=True)
    for tex in textures:
        rid_int = int(tex["resourceId"])
        if rid_int in _all_textures:
            t = _all_textures[rid_int]
            fname = "%s_%s.%s" % (tex["resourceId"], tex.get("name", "").replace("/", "_").replace("\\", "_")[:32], save_format)
            fpath = os.path.join(save_all_dir, fname)
            save_texture(t.resourceId, fpath, save_format)
            saved.append(fpath)

elif save_rid and save_output:
    target_rid = int(save_rid)
    if target_rid in _all_textures:
        t = _all_textures[target_rid]
        save_texture(t.resourceId, save_output, save_format)
        saved.append(save_output)

_write_output({"textures": textures, "total": len(textures), "saved": saved})
_shutdown()
sys.exit(0)
