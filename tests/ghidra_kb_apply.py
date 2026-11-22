"""Analyse a binary into a new Ghidra project, apply a kb.h, and report what the project then holds.

Run as a script, which keeps the Java virtual machine that pyghidra starts out of
the test process:

    python ghidra_kb_apply.py <binary> <project dir> <kb.h> <function address>...

Prints one line starting ``REPORT `` followed by a JSON object:
    analysis     what ``analyze`` returned
    summary      what ``kb_apply`` returned
    summary_of_second_run   what it returned when the same kb.h was applied again
    types        {data type name: member or value names} for the types of the program
                 whose names start with "Kb"
    prototypes   {address: prototype} of the function at each address given
    decompiled   {address: C} of the same functions
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import pyghidra_backend as backend  # noqa: E402


def _members(data_type) -> list[str]:
    from ghidra.program.model.data import Composite, Enum
    if isinstance(data_type, Composite):
        return [str(component.getFieldName()) for component in data_type.getComponents()]
    if isinstance(data_type, Enum):
        return sorted(str(name) for name in data_type.getNames())
    return []


def _project_state(binary: str, project: str, addresses: list[int]) -> dict:
    import pyghidra
    with pyghidra.open_program(binary, project_location=project, project_name=Path(binary).stem, analyze=False) as flat:
        program = flat.getCurrentProgram()
        listing = program.getListing()
        space = program.getAddressFactory().getDefaultAddressSpace()
        return {
            "types": {str(dt.getName()): _members(dt) for dt in program.getDataTypeManager().getAllDataTypes()
                      if str(dt.getName()).startswith("Kb")},
            "prototypes": {f"{va:#x}": str(listing.getFunctionContaining(space.getAddress(va))
                                           .getSignature().getPrototypeString(True)) for va in addresses},
        }


def main() -> None:
    binary, project, kb_path, *addresses = sys.argv[1:]
    addresses = [int(address, 16) for address in addresses]
    report = {"analysis": backend.analyze(binary, project)}
    report["summary"] = backend.kb_apply(project, binary, kb_path)
    report["summary_of_second_run"] = backend.kb_apply(project, binary, kb_path)
    report.update(_project_state(binary, project, addresses))
    report["decompiled"] = {f"{va:#x}": backend.decompile(project, binary, va) for va in addresses}
    print("REPORT " + json.dumps(report))


if __name__ == "__main__":
    main()
