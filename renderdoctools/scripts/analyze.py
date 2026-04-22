# renderdoctools/scripts/analyze.py
# Capture-wide analysis and statistics.
# Runs inside RenderDoc Python 3.6.

show_summary = _cfg.get("summary", False)
biggest_n = _cfg.get("biggest_draws", 0)
show_render_targets = _cfg.get("render_targets", False)

sf = _controller.GetStructuredFile()

all_actions = []
def collect(d, depth=0):
    all_actions.append((d, depth))
    for c in d.children:
        collect(c, depth + 1)
for a in _controller.GetRootActions():
    collect(a)

draws = [(a, dep) for a, dep in all_actions if a.flags & rd.ActionFlags.Drawcall]
clears = [(a, dep) for a, dep in all_actions if a.flags & rd.ActionFlags.Clear]

result = {}

if show_summary or (not biggest_n and not show_render_targets):
    total_indices = sum(a.numIndices for a, _ in draws)
    total_instances = sum(a.numInstances for a, _ in draws)
    result["summary"] = {
        "totalEvents": len(all_actions),
        "totalDraws": len(draws),
        "totalClears": len(clears),
        "totalIndices": total_indices,
        "totalInstances": total_instances,
    }

if biggest_n:
    sorted_draws = sorted(draws, key=lambda x: x[0].numIndices, reverse=True)
    top = sorted_draws[:biggest_n]
    result["biggestDraws"] = [{
        "eid": a.eventId,
        "name": a.GetName(sf),
        "numIndices": a.numIndices,
        "numInstances": a.numInstances,
    } for a, _ in top]

if show_render_targets:
    rt_map = {}
    for a, _ in draws:
        for o in a.outputs:
            if o != rd.ResourceId.Null():
                key = str(int(o))
                if key not in rt_map:
                    rt_map[key] = []
                rt_map[key].append(a.eventId)
    result["renderTargets"] = [{
        "resourceId": k,
        "drawCount": len(v),
        "firstEid": v[0],
        "lastEid": v[-1],
    } for k, v in sorted(rt_map.items(), key=lambda x: -len(x[1]))]

_write_output(result)
_shutdown()
sys.exit(0)
