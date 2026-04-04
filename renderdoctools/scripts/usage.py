# renderdoctools/scripts/usage.py
# Resource usage tracking -- find which events read/write a given resource.
# Runs inside RenderDoc Python 3.6. _cfg, _controller, _cap, rd available from base header.

resource_id_str = _cfg.get("resource_id", "")
usage_filter = _cfg.get("usage_filter", "all").lower()

if not resource_id_str:
    _write_error("--resource is required")

# Parse resource ID (accept integer or string representation)
try:
    rid_int = int(resource_id_str)
except ValueError:
    _write_error("Invalid resource ID: %s (must be an integer)" % resource_id_str)

# Build a ResourceId from the integer
target_rid = rd.ResourceId()
# ResourceId can be set via its id() accessor or constructed; use the int directly
# In RenderDoc Python, ResourceId has an id() method that returns the int, and we
# can find it by scanning GetResources()
resources = _controller.GetResources()
found_rid = None
resource_name = ""
resource_type = ""
for res in resources:
    if int(res.resourceId) == rid_int:
        found_rid = res.resourceId
        resource_name = res.name
        resource_type = str(res.type)
        break

if found_rid is None:
    _write_error("Resource ID %d not found in capture" % rid_int)

# Get all usages for this resource
usages = _controller.GetUsage(found_rid)

# Build event name lookup from the action tree
sf = _controller.GetStructuredFile()
event_names = {}
def _collect_event_names(action):
    event_names[action.eventId] = action.GetName(sf)
    for child in action.children:
        _collect_event_names(child)
for root_action in _controller.GetRootActions():
    _collect_event_names(root_action)

# Classify usage types for filtering
# "read" usages: constants, resources (SRVs), vertex/index buffers, copy source, resolve source, indirect
# "write" usages: RW resources (UAVs), color targets, depth targets, copy dest, resolve dest, clear, stream out
READ_USAGES = {
    "VertexBuffer", "IndexBuffer",
    "VS_Constants", "HS_Constants", "DS_Constants", "GS_Constants",
    "PS_Constants", "CS_Constants", "TS_Constants", "MS_Constants", "All_Constants",
    "VS_Resource", "HS_Resource", "DS_Resource", "GS_Resource",
    "PS_Resource", "CS_Resource", "TS_Resource", "MS_Resource", "All_Resource",
    "InputTarget", "Indirect", "CopySrc", "ResolveSrc",
}
WRITE_USAGES = {
    "VS_RWResource", "HS_RWResource", "DS_RWResource", "GS_RWResource",
    "PS_RWResource", "CS_RWResource", "TS_RWResource", "MS_RWResource", "All_RWResource",
    "ColorTarget", "DepthStencilTarget",
    "StreamOut", "CopyDst", "ResolveDst",
    "Clear", "Discard", "GenMips", "CPUWrite",
}

entries = []
for u in usages:
    usage_str = str(u.usage)
    # Strip enum prefix if present (e.g. "ResourceUsage.ColorTarget" -> "ColorTarget")
    short_usage = usage_str.split(".")[-1] if "." in usage_str else usage_str

    # Determine read/write category
    if short_usage in READ_USAGES:
        category = "read"
    elif short_usage in WRITE_USAGES:
        category = "write"
    else:
        # Copy, Resolve, Barrier -- treat as read+write
        category = "readwrite"

    # Apply filter
    if usage_filter == "read" and category not in ("read", "readwrite"):
        continue
    if usage_filter == "write" and category not in ("write", "readwrite"):
        continue

    entries.append({
        "eventId": u.eventId,
        "eventName": event_names.get(u.eventId, "(unknown)"),
        "usage": short_usage,
        "category": category,
    })

_write_output({
    "resourceId": rid_int,
    "resourceName": resource_name,
    "resourceType": resource_type,
    "filter": usage_filter,
    "total": len(entries),
    "usages": entries,
})
_shutdown()
sys.exit(0)
