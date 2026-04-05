# renderdoctools/scripts/counters.py
# GPU performance counter queries.
# Runs inside RenderDoc Python 3.6.

fetch_name = _cfg.get("fetch", "")
zero_samples = _cfg.get("zero_samples", False)

counters = _controller.EnumerateCounters()
sf = _controller.GetStructuredFile()

def _collect_all_actions():
    result = {}
    def _walk(d):
        result[d.eventId] = d
        for c in d.children:
            _walk(c)
    for a in _controller.GetRootActions():
        _walk(a)
    return result

if not fetch_name and not zero_samples:
    counter_list = []
    for c in counters:
        desc = _controller.DescribeCounter(c)
        counter_list.append({
            "id": int(c),
            "name": desc.name,
            "description": desc.description,
            "unit": str(desc.unit),
            "resultType": str(desc.resultType),
            "resultByteWidth": desc.resultByteWidth,
        })
    _write_output({"mode": "list", "counters": counter_list})

elif zero_samples:
    if not (rd.GPUCounter.SamplesPassed in counters):
        _write_error("SamplesPassed counter not supported")

    results = _controller.FetchCounters([rd.GPUCounter.SamplesPassed])
    desc = _controller.DescribeCounter(rd.GPUCounter.SamplesPassed)

    actions = _collect_all_actions()

    zero_draws = []
    for r in results:
        if r.eventId not in actions:
            continue
        draw = actions[r.eventId]
        if not (draw.flags & rd.ActionFlags.Drawcall):
            continue
        if desc.resultType == rd.CompType.Float:
            val = r.value.f if desc.resultByteWidth == 4 else r.value.d
        else:
            val = r.value.u32 if desc.resultByteWidth == 4 else r.value.u64
        if val == 0:
            zero_draws.append({
                "eid": r.eventId,
                "name": draw.GetName(sf),
                "numIndices": draw.numIndices,
            })

    _write_output({"mode": "zero_samples", "draws": zero_draws, "total": len(zero_draws)})

else:
    target_counter = None
    for c in counters:
        desc = _controller.DescribeCounter(c)
        if desc.name.lower() == fetch_name.lower():
            target_counter = c
            break

    if target_counter is None:
        _write_error("Counter '%s' not found" % fetch_name)

    results = _controller.FetchCounters([target_counter])
    desc = _controller.DescribeCounter(target_counter)

    actions = _collect_all_actions()

    entries = []
    for r in results:
        if r.eventId not in actions:
            continue
        draw = actions[r.eventId]
        if desc.resultType == rd.CompType.Float:
            val = r.value.f if desc.resultByteWidth == 4 else r.value.d
        else:
            val = r.value.u32 if desc.resultByteWidth == 4 else r.value.u64
        entries.append({
            "eid": r.eventId,
            "name": draw.GetName(sf),
            "value": val,
        })

    _write_output({"mode": "fetch", "counter": desc.name, "unit": str(desc.unit), "results": entries})

_shutdown()
sys.exit(0)
