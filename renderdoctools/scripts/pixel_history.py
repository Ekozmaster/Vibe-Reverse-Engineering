# renderdoctools/scripts/pixel_history.py
# Pixel history -- "what drew to this pixel?" for a given render target at (x, y).
# Runs inside RenderDoc Python 3.6. _cfg, _controller, _cap, rd available from base header.

event_id = _cfg.get("event_id")
resource_id = _cfg.get("resource_id")
px = _cfg.get("x")
py = _cfg.get("y")
sub_mip = _cfg.get("sub_mip", 0)
sub_slice = _cfg.get("sub_slice", 0)
sub_sample = _cfg.get("sub_sample", 0)

if event_id is None:
    _write_error("--event is required")
if resource_id is None:
    _write_error("--resource is required")
if px is None or py is None:
    _write_error("--x and --y are required")

# Move to the requested event so the replay state is correct
_controller.SetFrameEvent(event_id, True)

# Resolve the resource ID -- accept int or string
rid = rd.ResourceId()
rid_int = int(resource_id)

# Walk resources to find the matching one
found = False
for r in _controller.GetResources():
    if int(r.resourceId) == rid_int:
        rid = r.resourceId
        found = True
        break

if not found:
    _write_error("Resource ID %s not found in capture" % resource_id)

sub = rd.Subresource(sub_mip, sub_slice, sub_sample)

# PixelHistory(ResourceId texture, uint32_t x, uint32_t y, Subresource sub, CompType typeCast)
modifications = _controller.PixelHistory(rid, int(px), int(py), sub, rd.CompType.Typeless)

# Build action lookup for event names
sf = _controller.GetStructuredFile()
_action_map = {}

def _walk(action):
    _action_map[action.eventId] = action
    for child in action.children:
        _walk(child)

for root in _controller.GetRootActions():
    _walk(root)


def _extract_color(mod_value):
    """Extract RGBA floats from a ModificationValue."""
    col = mod_value.col
    return {
        "r": col.floatValue[0],
        "g": col.floatValue[1],
        "b": col.floatValue[2],
        "a": col.floatValue[3],
    }


results = []
for mod in modifications:
    action = _action_map.get(mod.eventId)
    is_clear = False
    is_draw = False
    action_name = ""
    if action is not None:
        action_name = action.GetName(sf)
        is_draw = bool(action.flags & rd.ActionFlags.Drawcall)
        is_clear = bool(action.flags & rd.ActionFlags.Clear)

    passed = mod.Passed()

    # Collect all test results
    tests = {
        "sampleMasked": mod.sampleMasked,
        "backfaceCulled": mod.backfaceCulled,
        "depthClipped": mod.depthClipped,
        "depthBoundsFailed": mod.depthBoundsFailed,
        "viewClipped": mod.viewClipped,
        "scissorClipped": mod.scissorClipped,
        "shaderDiscarded": mod.shaderDiscarded,
        "depthTestFailed": mod.depthTestFailed,
        "stencilTestFailed": mod.stencilTestFailed,
    }

    # Gather failed tests as a list for convenience
    failed_tests = [name for name, val in tests.items() if val]

    entry = {
        "eventId": mod.eventId,
        "name": action_name,
        "passed": passed,
        "isDraw": is_draw,
        "isClear": is_clear,
        "directShaderWrite": mod.directShaderWrite,
        "unboundPS": mod.unboundPS,
        "fragIndex": mod.fragIndex,
        "primitiveID": mod.primitiveID,
        "preMod": _extract_color(mod.preMod),
        "preModDepth": mod.preMod.depth,
        "preModStencil": mod.preMod.stencil,
        "shaderOut": _extract_color(mod.shaderOut),
        "shaderOutDepth": mod.shaderOut.depth,
        "shaderOutStencil": mod.shaderOut.stencil,
        "postMod": _extract_color(mod.postMod),
        "postModDepth": mod.postMod.depth,
        "postModStencil": mod.postMod.stencil,
        "tests": tests,
        "failedTests": failed_tests,
    }

    results.append(entry)

_write_output({
    "pixel": {"x": int(px), "y": int(py)},
    "resourceId": str(rid_int),
    "modifications": results,
    "total": len(results),
})
_shutdown()
sys.exit(0)
