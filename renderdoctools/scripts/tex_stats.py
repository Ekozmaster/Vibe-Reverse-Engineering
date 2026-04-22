# renderdoctools/scripts/tex_stats.py
# Texture min/max/histogram analysis for HDR range debugging.
# Runs inside RenderDoc Python 3.6.

resource_id = _cfg.get("resource_id")
sub_mip = _cfg.get("sub_mip", 0)
sub_slice = _cfg.get("sub_slice", 0)
sub_sample = _cfg.get("sub_sample", 0)
do_histogram = _cfg.get("histogram", False)
hist_min = _cfg.get("histogram_min", 0.0)
hist_max = _cfg.get("histogram_max", 1.0)

if resource_id is None:
    _write_error("--resource is required")

# Resolve the resource ID
rid_int = int(resource_id)

# Look up texture metadata
_all_textures = {}
for t in _controller.GetTextures():
    _all_textures[int(t.resourceId)] = t

if rid_int not in _all_textures:
    _write_error("Resource ID %d not found in capture" % rid_int)

tex_desc = _all_textures[rid_int]
tex_rid = tex_desc.resourceId

# Build resource name lookup
_resource_names = {}
for r in _controller.GetResources():
    _resource_names[int(r.resourceId)] = r.name

# Format string
try:
    fmt_str = tex_desc.format.Name()
except Exception:
    try:
        fmt = tex_desc.format
        fmt_str = "%s_%s%d" % (str(fmt.type), str(fmt.compType), fmt.compByteWidth * 8)
    except Exception:
        fmt_str = "unknown"

# Build Subresource
sub = rd.Subresource(sub_mip, sub_slice, sub_sample)

# GetMinMax: returns (PixelValue min, PixelValue max)
minmax = _controller.GetMinMax(tex_rid, sub, rd.CompType.Typeless)
min_val = minmax[0]
max_val = minmax[1]

result = {
    "resourceId": str(rid_int),
    "name": _resource_names.get(rid_int, ""),
    "width": tex_desc.width,
    "height": tex_desc.height,
    "depth": tex_desc.depth,
    "mips": tex_desc.mips,
    "format": fmt_str,
    "subresource": {"mip": sub_mip, "slice": sub_slice, "sample": sub_sample},
    "min": {
        "r": float(min_val.floatValue[0]),
        "g": float(min_val.floatValue[1]),
        "b": float(min_val.floatValue[2]),
        "a": float(min_val.floatValue[3]),
    },
    "max": {
        "r": float(max_val.floatValue[0]),
        "g": float(max_val.floatValue[1]),
        "b": float(max_val.floatValue[2]),
        "a": float(max_val.floatValue[3]),
    },
}

# Optional histogram
if do_histogram:
    channels = (True, True, True, True)
    buckets = _controller.GetHistogram(tex_rid, sub, rd.CompType.Typeless,
                                       float(hist_min), float(hist_max), channels)
    result["histogram"] = {
        "min_range": hist_min,
        "max_range": hist_max,
        "bucket_count": len(buckets),
        "buckets": [int(b) for b in buckets],
    }

_write_output(result)
_shutdown()
sys.exit(0)
