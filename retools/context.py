#!/usr/bin/env python3
"""RAG context assembly and mechanical post-processing for decompiler output.

Subcommands:

  assemble     Gather structured analysis context for a function
  postprocess  Mechanical text substitutions on decompiler output (reads stdin)

Usage:
    python -m retools.context assemble <binary> <va> --project <dir> [--db path]
    python -m retools.context postprocess <binary> <va> --project <dir>
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary
from funcinfo import find_start, analyze
from structrefs import aggregate_struct
from search import find_strings
from sigdb import SignatureDB, extract_structural_sig

# Pattern: fcn.XXXXXXXX where X is hex (case-insensitive)
_FCN_RE = re.compile(r"fcn\.([0-9a-fA-F]{8})")

# Pattern: *(type *)(var + 0xOFFSET)
_STRUCT_ACCESS_RE = re.compile(
    r"\*\(\s*\w[\w\s]*\*\s*\)\s*\((\w+)\s*\+\s*0x([0-9a-fA-F]+)\)"
)


# ---------------------------------------------------------------------------
# KB parsing
# ---------------------------------------------------------------------------

def _parse_kb_names(kb_path: Path) -> dict[int, str]:
    """Parse ``@ 0xADDR sig;`` lines and extract the function name.

    Handles signatures like:
        @ 0x401000 void __cdecl ProcessInput(int key);
        @ 0xDEAD _malloc;
    """
    if not kb_path.is_file():
        return {}
    names: dict[int, str] = {}
    for line in kb_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("@ "):
            continue
        # Split: "@", "0xADDR", rest...
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            va = int(parts[1], 16)
        except ValueError:
            continue
        sig = parts[2].rstrip(";").strip()
        # Extract name: last identifier before '(' or the whole token
        paren = sig.find("(")
        if paren != -1:
            pre = sig[:paren].strip()
        else:
            pre = sig
        # Name is the last whitespace-separated token
        name = pre.rsplit(None, 1)[-1] if pre else ""
        # Strip pointer/ref decorators
        name = name.lstrip("*&")
        if name:
            names[va] = name
    return names


def _parse_kb_globals(kb_path: Path) -> dict[int, str]:
    """Parse ``$ 0xADDR type name`` lines and extract the global name.

    Handles lines like:
        $ 0x7C5548 Object* g_mainObject
        $ 0x7C554C Flags g_renderFlags
    """
    if not kb_path.is_file():
        return {}
    globals_: dict[int, str] = {}
    for line in kb_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("$ "):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            va = int(parts[1], 16)
        except ValueError:
            continue
        # Name is the last token (type may have pointer decorators)
        name = parts[-1]
        if name:
            globals_[va] = name
    return globals_


# ---------------------------------------------------------------------------
# postprocess
# ---------------------------------------------------------------------------

def postprocess(raw_output: str, kb_names: dict[int, str],
                struct_fields: dict[int, tuple[str, str]] | None = None) -> str:
    """Mechanical text substitutions on decompiler output.

    Args:
        raw_output: Raw decompiler text.
        kb_names: Map of VA to function name for fcn.XXXXXXXX replacement.
        struct_fields: Map of offset to (type, field_name) for struct access
            replacement. ``*(type *)(var + 0xOFFSET)`` becomes ``var->field_name``.

    Returns:
        Transformed text.
    """
    result = _FCN_RE.sub(
        lambda m: kb_names.get(int(m.group(1), 16), m.group(0)),
        raw_output,
    )
    if struct_fields:
        result = _STRUCT_ACCESS_RE.sub(
            lambda m: (
                f"{m.group(1)}->{struct_fields[int(m.group(2), 16)][1]}"
                if int(m.group(2), 16) in struct_fields
                else m.group(0)
            ),
            result,
        )
    return result


# ---------------------------------------------------------------------------
# assemble
# ---------------------------------------------------------------------------

def _find_kb_path(project_dir: str, project_dir_for_kb: str | None = None) -> Path:
    """Locate kb.h: try explicit override, then patches/<project>/kb.h."""
    if project_dir_for_kb:
        p = Path(project_dir_for_kb) / "kb.h"
        if p.is_file():
            return p
    proj_name = Path(project_dir).name
    p = Path(project_dir).parent / "patches" / proj_name / "kb.h"
    if p.is_file():
        return p
    # Also try patches/ relative to project_dir
    p = Path(project_dir) / "kb.h"
    if p.is_file():
        return p
    return Path(project_dir) / "kb.h"  # may not exist -- callers handle missing


def assemble(b: Binary, va: int, project_dir: str, db_path: str | None = None,
             project_dir_for_kb: str | None = None) -> str:
    """Gather structured analysis context for a function.

    Args:
        b: Loaded PE binary.
        va: Virtual address of the function (or address inside it).
        project_dir: Project directory path.
        db_path: Optional path to sigdb database.
        project_dir_for_kb: Optional override directory containing kb.h.

    Returns:
        Formatted text block with context sections.
    """
    w = 16 if b.is_64 else 8
    start = find_start(b, va) or va
    lines: list[str] = [f"=== CONTEXT FOR 0x{start:0{w}X} ==="]

    # -- KB lookup --
    kb_path = _find_kb_path(project_dir, project_dir_for_kb)
    kb_names = _parse_kb_names(kb_path)
    kb_globals = _parse_kb_globals(kb_path)

    # -- Identity --
    if start in kb_names:
        lines.append(f"[identity] {kb_names[start]} (from KB)")
    else:
        lines.append(f"[identity] unknown function at 0x{start:0{w}X}")

    # -- Callees --
    rets, calls, end_va = analyze(b, start, max_size=0x2000)
    lines.append("[callees]")
    seen_targets: set[int | str] = set()
    for _, target in calls:
        if target in seen_targets:
            continue
        seen_targets.add(target)
        if isinstance(target, int):
            name = kb_names.get(target, "unknown")
            lines.append(f"  0x{target:0{w}X}: {name}")
        else:
            lines.append(f"  {target}: indirect call")

    # -- Struct fields (best-effort) --
    try:
        fields = aggregate_struct(b, start, fn_size=end_va - start or 0x2000)
        if fields:
            lines.append("[struct]")
            for fa in fields:
                lines.append(
                    f"  +0x{fa.offset:03X}: {fa.type_name} "
                    f"({fa.access}, {len(fa.refs)} refs)"
                )
    except Exception:
        pass

    # Shared disassembly for strings + globals sections
    func_size = end_va - start or 0x2000
    try:
        func_insns = b.disasm(start, count=2000, max_bytes=func_size)
    except Exception:
        func_insns = []

    # -- Strings (best-effort, O(1) lookup via VA dict) --
    try:
        all_strings = find_strings(b, min_len=4)
        if all_strings:
            # Build O(1) lookup by VA
            str_by_va: dict[int, str] = {
                s.va: s.value for s in all_strings if s.va is not None
            }
            # Collect memory refs from function's instructions
            found_strings: list[tuple[str, int]] = []
            for insn in func_insns:
                for ref_va in b.abs_imm_refs(insn) + b.abs_mem_refs(insn):
                    if ref_va in str_by_va:
                        found_strings.append((str_by_va[ref_va], ref_va))
            if found_strings:
                lines.append("[strings]")
                seen_str_vas: set[int] = set()
                for val, sva in found_strings:
                    if sva in seen_str_vas:
                        continue
                    seen_str_vas.add(sva)
                    lines.append(f'  "{val}" at 0x{sva:0{w}X}')
    except Exception:
        pass

    # -- Globals (cross-ref KB globals with function memory refs) --
    if kb_globals:
        found_globals: list[tuple[int, str]] = []
        for insn in func_insns:
            for ref_va in b.abs_mem_refs(insn) + b.abs_imm_refs(insn):
                if ref_va in kb_globals:
                    found_globals.append((ref_va, kb_globals[ref_va]))
        if found_globals:
            lines.append("[globals]")
            seen_gvas: set[int] = set()
            for gva, gname in found_globals:
                if gva in seen_gvas:
                    continue
                seen_gvas.add(gva)
                lines.append(f"  {gname} at 0x{gva:0{w}X}")

    # -- Sigdb structural match (best-effort) --
    if db_path:
        try:
            db = SignatureDB(db_path)
            sig = extract_structural_sig(b, start)
            if sig:
                matches = db.match_structural(
                    sig["block_count"], sig["edge_count"], sig["call_count"],
                    sig["mnemonic_hash"], sig["constants"],
                )
                if matches:
                    m = matches[0]
                    lines.append(
                        f"[similar] {m.source}: {m.name} "
                        f"(block_count={sig['block_count']}, "
                        f"call_count={sig['call_count']})"
                    )
            db.close()
        except Exception:
            pass

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # -- assemble --
    s = sub.add_parser("assemble", help="Gather context for a function")
    s.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    s.add_argument("va", help="Function virtual address (hex)")
    s.add_argument("--project", required=True, help="Project directory")
    s.add_argument("--db", default=None, help="Signature DB path")

    # -- postprocess --
    s = sub.add_parser("postprocess", help="Apply text substitutions (reads stdin)")
    s.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    s.add_argument("va", help="Function virtual address (hex)")
    s.add_argument("--project", required=True, help="Project directory")

    args = p.parse_args(argv)

    if args.command == "assemble":
        b = Binary(args.binary)
        va = int(args.va, 16)
        result = assemble(b, va, args.project, db_path=args.db)
        print(result, end="")

    elif args.command == "postprocess":
        b = Binary(args.binary)
        va = int(args.va, 16)
        start = find_start(b, va) or va

        # Load KB names for substitution
        proj_name = Path(args.project).name
        kb_path = Path(args.project) / "kb.h"
        if not kb_path.is_file():
            kb_path = Path("patches") / proj_name / "kb.h"
        kb_names = _parse_kb_names(kb_path)

        # Struct fields from analysis
        fields = aggregate_struct(b, start, fn_size=0x2000)
        struct_fields: dict[int, tuple[str, str]] | None = None
        if fields:
            struct_fields = {
                fa.offset: (fa.type_name, f"field_{fa.offset:X}")
                for fa in fields
            }

        raw = sys.stdin.read()
        result = postprocess(raw, kb_names, struct_fields)
        print(result, end="")


if __name__ == "__main__":
    main()
