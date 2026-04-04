# renderdoctools/scripts/events.py
# Event browser -- enumerate draw calls and events from a capture.
# Runs inside RenderDoc Python 3.6. _cfg, _controller, _cap, rd available from base header.

draws_only = _cfg.get("draws_only", False)
name_filter = _cfg.get("filter", "")


def walk_actions(action, depth=0):
    """Recursively walk the action tree, collecting event info."""
    sf = _controller.GetStructuredFile()
    name = action.GetName(sf)

    include = True
    if draws_only and not (action.flags & rd.ActionFlags.Drawcall):
        include = False
    if name_filter and name_filter.lower() not in name.lower():
        include = False

    entry = None
    if include:
        entry = {
            "eid": action.eventId,
            "name": name,
            "depth": depth,
            "flags": int(action.flags),
            "draw": bool(action.flags & rd.ActionFlags.Drawcall),
            "clear": bool(action.flags & rd.ActionFlags.Clear),
            "numIndices": action.numIndices,
            "numInstances": action.numInstances,
        }

    children = []
    for child in action.children:
        children.extend(walk_actions(child, depth + 1))

    results = []
    if entry is not None:
        results.append(entry)
    results.extend(children)
    return results


events = []
for root_action in _controller.GetRootActions():
    events.extend(walk_actions(root_action))

_write_output({"events": events, "total": len(events)})
_shutdown()
sys.exit(0)
