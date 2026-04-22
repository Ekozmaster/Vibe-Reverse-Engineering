# renderdoctools/scripts/mesh.py
# Vertex/mesh data decode at a draw call.
# Runs inside RenderDoc Python 3.6.

import struct

event_id = _cfg.get("event_id")
post_vs = _cfg.get("post_vs", False)
index_range = _cfg.get("indices", "")
max_verts = 64

if event_id is None:
    _write_error("--event is required")

start_idx, end_idx = 0, max_verts
if index_range:
    parts = index_range.split("-")
    start_idx = int(parts[0])
    end_idx = int(parts[1]) if len(parts) > 1 else start_idx + 1

_controller.SetFrameEvent(event_id, True)
state = _controller.GetPipelineState()

FORMAT_CHARS = {
    int(rd.CompType.UInt):  "xBHxIxxxL",
    int(rd.CompType.SInt):  "xbhxixxxl",
    int(rd.CompType.Float): "xxexfxxxd",
}
FORMAT_CHARS[int(rd.CompType.UNorm)] = FORMAT_CHARS[int(rd.CompType.UInt)]
FORMAT_CHARS[int(rd.CompType.SNorm)] = FORMAT_CHARS[int(rd.CompType.SInt)]
FORMAT_CHARS[int(rd.CompType.UScaled)] = FORMAT_CHARS[int(rd.CompType.UInt)]
FORMAT_CHARS[int(rd.CompType.SScaled)] = FORMAT_CHARS[int(rd.CompType.SInt)]


def unpack_data(fmt, data):
    char = FORMAT_CHARS.get(int(fmt.compType), "")
    if not char or fmt.compByteWidth >= len(char):
        return None
    c = char[fmt.compByteWidth]
    if c == "x":
        return None
    vert_fmt = str(fmt.compCount) + c
    try:
        value = struct.unpack_from(vert_fmt, data, 0)
    except struct.error:
        return None
    if fmt.compType == rd.CompType.UNorm:
        divisor = float((2 ** (fmt.compByteWidth * 8)) - 1)
        value = tuple(float(i) / divisor for i in value)
    elif fmt.compType == rd.CompType.SNorm:
        max_neg = -float(2 ** (fmt.compByteWidth * 8)) / 2
        divisor = float(-(max_neg - 1))
        value = tuple((float(i) if i == max_neg else float(i) / divisor) for i in value)
    return list(value)


action = None
for root_action in _controller.GetRootActions():
    cur = root_action
    while cur is not None:
        if cur.eventId == event_id:
            action = cur
            break
        cur = cur.next
    if action:
        break

if action is None:
    _write_error("Event %d not found" % event_id)

mesh_data = {"event_id": event_id, "post_vs": post_vs, "attributes": [], "vertices": []}

if post_vs:
    postvs = _controller.GetPostVSData(0, 0, rd.MeshDataStage.VSOut)
    vs_refl = state.GetShaderReflection(rd.ShaderStage.Vertex)
    if vs_refl:
        attrs = []
        for attr in vs_refl.outputSignature:
            name = attr.semanticIdxName if attr.varName == "" else attr.varName
            attrs.append({
                "name": name,
                "compCount": attr.compCount,
            })
        mesh_data["attributes"] = attrs

        if postvs.numIndices > 0:
            data = _controller.GetBufferData(postvs.vertexResourceId, postvs.vertexByteOffset, 0)
            stride = postvs.vertexByteStride
            num_verts = min(postvs.numIndices, end_idx)

            for i in range(start_idx, num_verts):
                vert = {"index": i}
                offset = i * stride
                attr_offset = 0
                for attr in vs_refl.outputSignature:
                    name = attr.semanticIdxName if attr.varName == "" else attr.varName
                    comp_count = attr.compCount
                    byte_size = comp_count * 4
                    try:
                        vals = struct.unpack_from("%df" % comp_count, data, offset + attr_offset)
                        vert[name] = list(vals)
                    except struct.error:
                        pass
                    attr_offset += byte_size
                mesh_data["vertices"].append(vert)
                if len(mesh_data["vertices"]) >= max_verts:
                    break
else:
    ib = state.GetIBuffer()
    vbs = state.GetVBuffers()
    attrs = state.GetVertexInputs()

    for attr in attrs:
        mesh_data["attributes"].append({
            "name": attr.name,
            "format": str(attr.format),
            "buffer": attr.vertexBuffer,
            "offset": attr.byteOffset,
        })

    if ib.resourceId != rd.ResourceId.Null() and (action.flags & rd.ActionFlags.Indexed):
        idx_fmt = "H" if ib.byteStride == 2 else "I"
        ibdata = _controller.GetBufferData(ib.resourceId, ib.byteOffset, 0)
        num = min(action.numIndices, end_idx)
        indices = []
        for i in range(start_idx, num):
            offset = (action.indexOffset + i) * ib.byteStride
            try:
                val = struct.unpack_from(idx_fmt, ibdata, offset)[0]
                indices.append(val + action.baseVertex)
            except struct.error:
                break
    else:
        indices = list(range(start_idx, min(action.numIndices, end_idx)))

    for idx in indices:
        vert = {"index": idx}
        for attr in attrs:
            if attr.perInstance:
                continue
            vb = vbs[attr.vertexBuffer]
            offset = attr.byteOffset + vb.byteOffset + idx * vb.byteStride
            data = _controller.GetBufferData(vb.resourceId, offset, attr.format.compByteWidth * attr.format.compCount)
            vals = unpack_data(attr.format, data)
            vert[attr.name] = vals
        mesh_data["vertices"].append(vert)
        if len(mesh_data["vertices"]) >= max_verts:
            break

_write_output(mesh_data)
_shutdown()
sys.exit(0)
