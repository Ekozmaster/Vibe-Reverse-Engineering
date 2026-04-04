# renderdoctools/scripts/descriptors.py
# Low-level descriptor access auditing at a specific event.
# Lists all descriptors accessed via GetDescriptorAccess() and fetches their contents.
# Runs inside RenderDoc Python 3.6.

event_id = _cfg.get("event_id")
type_filter = _cfg.get("type_filter", "all")

if event_id is None:
    _write_error("--event is required")

_controller.SetFrameEvent(event_id, True)

# Build resource name lookup
_resource_names = {}
for r in _controller.GetResources():
    _resource_names[int(r.resourceId)] = r.name

# Build texture metadata lookup
_all_textures = {}
for t in _controller.GetTextures():
    _all_textures[int(t.resourceId)] = t

STAGES = [
    ("vertex", rd.ShaderStage.Vertex),
    ("hull", rd.ShaderStage.Hull),
    ("domain", rd.ShaderStage.Domain),
    ("geometry", rd.ShaderStage.Geometry),
    ("pixel", rd.ShaderStage.Pixel),
    ("compute", rd.ShaderStage.Compute),
]

STAGE_MAP = {v: k for k, v in STAGES}

# Map type_filter strings to category check functions
FILTER_CATEGORIES = {
    "sampler": lambda t: rd.IsSamplerDescriptor(t),
    "cbuffer": lambda t: rd.IsConstantBlockDescriptor(t),
    "srv": lambda t: rd.IsReadOnlyDescriptor(t),
    "uav": lambda t: rd.IsReadWriteDescriptor(t),
    "all": lambda t: True,
}

filter_fn = FILTER_CATEGORIES.get(type_filter, FILTER_CATEGORIES["all"])

# Get all descriptor accesses at this event
accesses = _controller.GetDescriptorAccess()

# Get shader reflection for binding name lookups
state = _controller.GetPipelineState()


def _get_binding_name(access):
    """Look up the shader reflection name for a descriptor access."""
    if access.index == 0xFFFF:  # NoShaderBinding
        return "(direct heap access)"
    refl = state.GetShaderReflection(access.stage)
    if refl is None:
        return ""
    cat = rd.CategoryForDescriptorType(access.type)
    try:
        if cat == rd.DescriptorCategory.ConstantBlock:
            if access.index < len(refl.constantBlocks):
                return refl.constantBlocks[access.index].name
        elif cat == rd.DescriptorCategory.Sampler:
            if access.index < len(refl.samplers):
                return refl.samplers[access.index].name
        elif cat == rd.DescriptorCategory.ReadOnlyResource:
            if access.index < len(refl.readOnlyResources):
                return refl.readOnlyResources[access.index].name
        elif cat == rd.DescriptorCategory.ReadWriteResource:
            if access.index < len(refl.readWriteResources):
                return refl.readWriteResources[access.index].name
    except Exception:
        pass
    return ""


def _format_name(fmt):
    """Safely format a ResourceFormat to string."""
    try:
        return fmt.Name()
    except Exception:
        try:
            return "%s_%s%d" % (str(fmt.type), str(fmt.compType), fmt.compByteWidth * 8)
        except Exception:
            return "unknown"


descriptors_out = []

for access in accesses:
    # Apply type filter
    if not filter_fn(access.type):
        continue

    # Skip statically unused if flagged
    stage_name = STAGE_MAP.get(access.stage, str(access.stage))
    desc_type = str(access.type)
    binding_name = _get_binding_name(access)

    entry = {
        "stage": stage_name,
        "descriptorType": desc_type,
        "index": access.index,
        "arrayElement": access.arrayElement,
        "bindingName": binding_name,
        "descriptorStore": str(int(access.descriptorStore)),
        "byteOffset": access.byteOffset,
        "byteSize": access.byteSize,
        "staticallyUnused": access.staticallyUnused,
    }

    # Fetch descriptor contents
    desc_range = rd.DescriptorRange()
    desc_range.offset = access.byteOffset
    desc_range.descriptorSize = access.byteSize
    desc_range.count = 1
    desc_range.type = access.type

    # Fetch normal descriptor contents
    try:
        descs = _controller.GetDescriptors(access.descriptorStore, [desc_range])
        if descs and len(descs) > 0:
            desc = descs[0]
            rid = int(desc.resource)
            entry["resourceId"] = str(rid)
            entry["resourceName"] = _resource_names.get(rid, "")
            entry["viewFormat"] = _format_name(desc.format)
            entry["descriptorByteOffset"] = desc.byteOffset
            entry["descriptorByteSize"] = desc.byteSize
            entry["textureType"] = str(desc.textureType)
            entry["elementByteSize"] = desc.elementByteSize

            # Add texture-specific info if this is a texture resource
            if rid in _all_textures:
                tex = _all_textures[rid]
                entry["textureWidth"] = tex.width
                entry["textureHeight"] = tex.height
                entry["textureDepth"] = tex.depth
                entry["textureMips"] = tex.mips
                entry["textureArraySize"] = tex.arraysize
                entry["textureFormat"] = _format_name(tex.format)
    except Exception:
        pass

    # Fetch sampler descriptor contents for sampler types
    if rd.IsSamplerDescriptor(access.type) or access.type == rd.DescriptorType.ImageSampler:
        try:
            samplers = _controller.GetSamplerDescriptors(access.descriptorStore, [desc_range])
            if samplers and len(samplers) > 0:
                samp = samplers[0]
                entry["samplerObject"] = str(int(samp.object))
                entry["samplerAddressU"] = str(samp.addressU)
                entry["samplerAddressV"] = str(samp.addressV)
                entry["samplerAddressW"] = str(samp.addressW)
                entry["samplerFilter"] = str(samp.filter)
        except Exception:
            pass

    descriptors_out.append(entry)

_write_output({
    "event_id": event_id,
    "type_filter": type_filter,
    "total": len(descriptors_out),
    "descriptors": descriptors_out,
})
_shutdown()
sys.exit(0)
