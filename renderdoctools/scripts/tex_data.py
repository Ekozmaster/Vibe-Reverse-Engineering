# renderdoctools/scripts/tex_data.py
# Extract raw texture pixel data via GetTextureData().
# Runs inside RenderDoc Python 3.6.

resource_id = _cfg.get("resource_id")
sub_mip = _cfg.get("sub_mip", 0)
sub_slice = _cfg.get("sub_slice", 0)
sub_sample = _cfg.get("sub_sample", 0)
output_path = _cfg.get("output_path", "")
hex_preview_bytes = _cfg.get("hex_preview_bytes", 256)

if resource_id is None:
    _write_error("--resource is required")

rid_int = int(resource_id)

# Find the texture descriptor
tex_desc = None
for t in _controller.GetTextures():
    if int(t.resourceId) == rid_int:
        tex_desc = t
        break

if tex_desc is None:
    _write_error("Resource ID %d not found among textures in this capture" % rid_int)

# Get resource name
res_name = ""
for r in _controller.GetResources():
    if int(r.resourceId) == rid_int:
        res_name = r.name
        break

# Build format string
fmt = tex_desc.format
try:
    fmt_str = fmt.Name()
except Exception:
    try:
        fmt_str = "%s_%s%d" % (str(fmt.type), str(fmt.compType), fmt.compByteWidth * 8)
    except Exception:
        fmt_str = "unknown"

# Build Subresource and fetch raw data
sub = rd.Subresource(sub_mip, sub_slice, sub_sample)
raw_bytes = _controller.GetTextureData(tex_desc.resourceId, sub)

result = {
    "resourceId": str(rid_int),
    "name": res_name,
    "width": tex_desc.width,
    "height": tex_desc.height,
    "depth": tex_desc.depth,
    "mips": tex_desc.mips,
    "arraysize": tex_desc.arraysize,
    "format": fmt_str,
    "type": str(tex_desc.type),
    "subresource": {
        "mip": sub_mip,
        "slice": sub_slice,
        "sample": sub_sample,
    },
    "byteSize": len(raw_bytes),
}

if output_path:
    # Write raw bytes to file
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(raw_bytes)
    result["savedTo"] = output_path
else:
    # Hex dump of first N bytes
    preview_len = min(hex_preview_bytes, len(raw_bytes))
    hex_lines = []
    for offset in range(0, preview_len, 16):
        chunk = raw_bytes[offset:offset + 16]
        hex_part = " ".join("%02x" % (b if isinstance(b, int) else ord(b)) for b in chunk)
        hex_lines.append("%08x  %s" % (offset, hex_part))
    result["hexPreview"] = hex_lines
    result["hexPreviewBytes"] = preview_len

_write_output(result)
_shutdown()
sys.exit(0)
