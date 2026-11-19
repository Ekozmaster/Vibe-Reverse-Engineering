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
