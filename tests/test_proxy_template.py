"""The remix-comp-proxy template's INI file against the code that reads it."""

import re

import pytest

from proxy_template import TEMPLATE, keys_of, keys_the_proxy_reads, shipped_ini

_CONFIG_HEADER = TEMPLATE / "src" / "shared" / "common" / "config.hpp"


def _built_in_default(member: str) -> int:
    """The initial value config.hpp gives the int *member*."""
    declaration = re.search(rf"\bint {member} = (\d+);", _CONFIG_HEADER.read_text(encoding="utf-8"))
    assert declaration, f"config.hpp declares no int {member}"
    return int(declaration.group(1))


def test_the_shipped_ini_lists_exactly_the_keys_the_proxy_reads():
    assert keys_of(shipped_ini()) == keys_the_proxy_reads()


@pytest.mark.parametrize("section, key, member", [
    ("FFP.Registers", "ViewStart", "view_start"),
    ("FFP.Registers", "ViewEnd", "view_end"),
    ("FFP.Registers", "ProjStart", "proj_start"),
    ("FFP.Registers", "ProjEnd", "proj_end"),
    ("FFP.Registers", "WorldStart", "world_start"),
    ("FFP.Registers", "WorldEnd", "world_end"),
    ("Skinning", "BoneThreshold", "bone_threshold"),
    ("Skinning", "RegsPerBone", "regs_per_bone"),
    ("Skinning", "BoneMinRegs", "bone_min_regs"),
])
def test_the_shipped_ini_gives_each_layout_key_its_built_in_default(section, key, member):
    assert shipped_ini().getint(section, key) == _built_in_default(member)


_DEVICE_WRAPPER = TEMPLATE / "src" / "comp" / "modules" / "d3d9ex.cpp"
_TRACER_DISPATCH = TEMPLATE / "src" / "comp" / "modules" / "tracer_dispatch.inc"


def _dispatch_functions_leaving_their_record_open() -> set[str]:
    """Names of the tracer's dispatch functions that begin a record and leave it for trace_created to end."""
    source = _TRACER_DISPATCH.read_text(encoding="utf-8")
    bodies = re.findall(r"inline void (trace_\w+)\(tracer& t[^)]*\)\s*\{(.*?)\n\}", source, re.DOTALL)
    return {name for name, body in bodies if "record_begin" in body and "record_end" not in body}


def test_no_trace_record_stays_open_across_a_call_into_the_driver():
    open_records = _dispatch_functions_leaving_their_record_open()
    assert open_records, "tracer_dispatch.inc has no Create* dispatch functions left to check"
    source = _DEVICE_WRAPPER.read_text(encoding="utf-8")
    spanning = []
    for opened in re.finditer(r"\b(" + "|".join(sorted(open_records)) + r")\b", source):
        statement = source[source.rfind("\n", 0, opened.start()):source.find(";", opened.end())]
        if "TRACE_CREATION_IF_ACTIVE" in statement:
            continue    # begins and ends the record in one statement, after the driver call
        closed = source.find("trace_created", opened.end())
        if closed < 0 or "m_pIDirect3DDevice9->" in source[opened.end():closed]:
            spanning.append(opened.group(1))
    assert not spanning
