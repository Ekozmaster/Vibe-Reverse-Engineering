# renderdoctools/scripts/pick_pixel.py
# Pick a single pixel value from a texture or render target.
# Runs inside RenderDoc Python 3.6.

resource_id = _cfg.get("resource_id")
x = _cfg.get("x")
y = _cfg.get("y")
sub_mip = _cfg.get("sub_mip", 0)
sub_slice = _cfg.get("sub_slice", 0)
sub_sample = _cfg.get("sub_sample", 0)
comp_type = _cfg.get("comp_type", "")

if resource_id is None:
    _write_error("--resource is required")
if x is None or y is None:
    _write_error("--x and --y are required")

# Resolve resource ID
rid = rd.ResourceId()
rid_int = int(resource_id)

# Find the matching ResourceId object from the capture's resource list
found_rid = None
for r in _controller.GetResources():
    if int(r.resourceId) == rid_int:
        found_rid = r.resourceId
        break

if found_rid is None:
    # Try textures list as fallback
    for t in _controller.GetTextures():
        if int(t.resourceId) == rid_int:
            found_rid = t.resourceId
            break

if found_rid is None:
    _write_error("Resource ID %s not found in capture" % resource_id)

# Build Subresource
sub = rd.Subresource(int(sub_mip), int(sub_slice), int(sub_sample))

# Resolve CompType
COMP_TYPE_MAP = {
    "": rd.CompType.Typeless,
    "typeless": rd.CompType.Typeless,
    "float": rd.CompType.Float,
    "unorm": rd.CompType.UNorm,
    "snorm": rd.CompType.SNorm,
    "uint": rd.CompType.UInt,
    "sint": rd.CompType.SInt,
    "uscaled": rd.CompType.UScaled,
    "sscaled": rd.CompType.SScaled,
    "depth": rd.CompType.Depth,
    "unormsrgb": rd.CompType.UNormSRGB,
}

type_cast = COMP_TYPE_MAP.get(comp_type.lower(), rd.CompType.Typeless)

# Pick the pixel
pixel = _controller.PickPixel(found_rid, int(x), int(y), sub, type_cast)

# Look up texture metadata for context
tex_info = None
for t in _controller.GetTextures():
    if int(t.resourceId) == rid_int:
        try:
            fmt_str = t.format.Name()
        except Exception:
            try:
                fmt_str = "%s_%s%d" % (str(t.format.type), str(t.format.compType), t.format.compByteWidth * 8)
            except Exception:
                fmt_str = "unknown"
        tex_info = {
            "width": t.width,
            "height": t.height,
            "depth": t.depth,
            "mips": t.mips,
            "arraysize": t.arraysize,
            "format": fmt_str,
        }
        break

# Look up resource name
res_name = ""
for r in _controller.GetResources():
    if int(r.resourceId) == rid_int:
        res_name = r.name
        break

# Extract all union interpretations
result = {
    "resourceId": str(rid_int),
    "name": res_name,
    "x": int(x),
    "y": int(y),
    "subresource": {
        "mip": int(sub_mip),
        "slice": int(sub_slice),
        "sample": int(sub_sample),
    },
    "compType": comp_type if comp_type else "Typeless",
    "value": {
        "float": [pixel.floatValue[i] for i in range(4)],
        "uint": [pixel.uintValue[i] for i in range(4)],
        "int": [pixel.intValue[i] for i in range(4)],
    },
}

if tex_info:
    result["texture"] = tex_info

_write_output(result)
_shutdown()
sys.exit(0)
