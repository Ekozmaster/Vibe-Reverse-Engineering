# renderdoctools/scripts/api_calls.py
# Structured API call log -- enumerate every API call with parameters.
# Runs inside RenderDoc Python 3.6. _cfg, _controller, _cap, rd available from base header.

event_id = _cfg.get("event_id", 0)
name_filter = _cfg.get("filter", "")
range_start = _cfg.get("range_start", 0)
range_end = _cfg.get("range_end", 0)

sf = _controller.GetStructuredFile()


def format_value(obj):
    """Extract a human-readable value from an SDObject."""
    bt = obj.type.basetype

    if bt == rd.SDBasic.Null:
        return None

    if bt == rd.SDBasic.String:
        return obj.data.str

    if bt == rd.SDBasic.Boolean:
        return obj.data.basic.b

    if bt == rd.SDBasic.UnsignedInteger:
        return obj.data.basic.u

    if bt == rd.SDBasic.SignedInteger:
        return obj.data.basic.i

    if bt == rd.SDBasic.Float:
        return obj.data.basic.d

    if bt == rd.SDBasic.Enum:
        # Enums have a custom string and integer storage
        s = obj.data.str
        if s:
            return s
        return obj.data.basic.u

    if bt == rd.SDBasic.Resource:
        return "RID:%d" % obj.data.basic.id

    if bt == rd.SDBasic.Character:
        return obj.data.basic.c

    if bt == rd.SDBasic.Buffer:
        return "<buffer %d bytes>" % obj.type.byteSize

    if bt == rd.SDBasic.GPUAddress:
        return "0x%x" % obj.data.basic.u

    if bt == rd.SDBasic.Array:
        items = []
        for i in range(obj.NumChildren()):
            child = obj.GetChild(i)
            items.append(format_value(child))
        return items

    if bt == rd.SDBasic.Struct or bt == rd.SDBasic.Chunk:
        members = {}
        for i in range(obj.NumChildren()):
            child = obj.GetChild(i)
            members[child.name] = format_value(child)
        return members

    return "<unknown type %s>" % str(bt)


def format_value_inline(obj):
    """Format a value as a compact inline string for one-line display."""
    bt = obj.type.basetype

    if bt == rd.SDBasic.Null:
        return "NULL"

    if bt == rd.SDBasic.String:
        s = obj.data.str
        if len(s) > 40:
            return '"%s..."' % s[:37]
        return '"%s"' % s

    if bt == rd.SDBasic.Boolean:
        return "true" if obj.data.basic.b else "false"

    if bt == rd.SDBasic.UnsignedInteger:
        v = obj.data.basic.u
        if v > 0xFFFF:
            return "0x%x" % v
        return str(v)

    if bt == rd.SDBasic.SignedInteger:
        return str(obj.data.basic.i)

    if bt == rd.SDBasic.Float:
        return "%.4g" % obj.data.basic.d

    if bt == rd.SDBasic.Enum:
        s = obj.data.str
        if s:
            return s
        return str(obj.data.basic.u)

    if bt == rd.SDBasic.Resource:
        return "RID:%d" % obj.data.basic.id

    if bt == rd.SDBasic.GPUAddress:
        return "0x%x" % obj.data.basic.u

    if bt == rd.SDBasic.Buffer:
        return "<buf:%dB>" % obj.type.byteSize

    if bt == rd.SDBasic.Array:
        n = obj.NumChildren()
        if n == 0:
            return "[]"
        if n <= 4:
            parts = []
            for i in range(n):
                parts.append(format_value_inline(obj.GetChild(i)))
            return "[%s]" % ", ".join(parts)
        return "[%d items]" % n

    if bt == rd.SDBasic.Struct or bt == rd.SDBasic.Chunk:
        n = obj.NumChildren()
        if n == 0:
            return "{}"
        # Show up to 3 members inline
        parts = []
        for i in range(min(n, 3)):
            child = obj.GetChild(i)
            parts.append("%s=%s" % (child.name, format_value_inline(child)))
        s = "{%s}" % ", ".join(parts)
        if n > 3:
            s = s[:-1] + ", ...}"
        return s

    return "?"


def param_detail(obj):
    """Build a detailed parameter dict for JSON output."""
    return {
        "name": obj.name,
        "type": obj.type.name,
        "basetype": str(obj.type.basetype),
        "value": format_value(obj),
    }


# Build event_id -> chunk_index mapping by walking actions
eid_to_chunk = {}


def map_events(action):
    for ev in action.events:
        if ev.chunkIndex != 0xFFFFFFFF:  # APIEvent.NoChunk
            eid_to_chunk[ev.eventId] = ev.chunkIndex
    for child in action.children:
        map_events(child)


for root_action in _controller.GetRootActions():
    map_events(root_action)


# --- Single event detail mode ---
if event_id:
    chunk_idx = eid_to_chunk.get(event_id, -1)
    if chunk_idx < 0 or chunk_idx >= len(sf.chunks):
        _write_error("Event ID %d not found or has no chunk" % event_id)

    chunk = sf.chunks[chunk_idx]
    params = []
    for i in range(chunk.NumChildren()):
        child = chunk.GetChild(i)
        params.append(param_detail(child))

    meta = chunk.metadata
    result = {
        "event_id": event_id,
        "chunk_index": chunk_idx,
        "function": chunk.name,
        "parameters": params,
        "metadata": {
            "chunkID": meta.chunkID,
            "length": meta.length,
            "threadID": meta.threadID,
            "durationMicro": meta.durationMicro,
            "timestampMicro": meta.timestampMicro,
        },
    }
    _write_output(result)
    _shutdown()
    sys.exit(0)


# --- Listing mode ---
# If range is specified, filter to that range
if range_start or range_end:
    eid_list = sorted(eid_to_chunk.keys())
    if range_start:
        eid_list = [e for e in eid_list if e >= range_start]
    if range_end:
        eid_list = [e for e in eid_list if e <= range_end]
else:
    eid_list = sorted(eid_to_chunk.keys())

calls = []
for eid in eid_list:
    chunk_idx = eid_to_chunk[eid]
    if chunk_idx >= len(sf.chunks):
        continue
    chunk = sf.chunks[chunk_idx]
    fn_name = chunk.name

    if name_filter and name_filter.lower() not in fn_name.lower():
        continue

    # Build compact parameter summary
    param_parts = []
    for i in range(chunk.NumChildren()):
        child = chunk.GetChild(i)
        param_parts.append("%s=%s" % (child.name, format_value_inline(child)))

    calls.append({
        "eid": eid,
        "function": fn_name,
        "params_inline": ", ".join(param_parts),
        "num_params": chunk.NumChildren(),
    })

_write_output({"calls": calls, "total": len(calls)})
_shutdown()
sys.exit(0)
