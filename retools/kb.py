"""Single source of truth for the kb.h grammar.

kb.h lines take three shapes:
    @ 0xADDR <signature>;      -- function at an address
    $ 0xADDR <type...> <name>  -- global variable at an address
    <C declaration>            -- bare typedef / struct / enum
Lines that are blank or begin with ``//`` are ignored. A declaration may span
lines: it runs until its braces are closed and a line ends in ``;`` or the next
line starts another declaration (``typedef``, ``struct``, ``union``, ``enum``,
``class``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class KbFunction:
    address: int
    signature: str  # no leading "@ 0xADDR", no trailing ";"
    name: str


@dataclass(frozen=True)
class KbGlobal:
    address: int
    type: str  # "" when the line is "$ 0xADDR name"
    name: str


@dataclass
class Kb:
    functions: list[KbFunction] = field(default_factory=list)
    globals: list[KbGlobal] = field(default_factory=list)
    typedefs: list[str] = field(default_factory=list)  # one declaration each, on one line


def extract_function_name(sig: str) -> str:
    """Extract the function name from a signature (no address, no ';').

    Name is the last whitespace-separated token before '(' (or the whole
    pre-paren text), with leading pointer/reference decorators stripped.
    """
    paren = sig.find("(")
    pre = sig[:paren] if paren != -1 else sig
    pre = pre.strip()
    if not pre:
        return ""
    return pre.rsplit(None, 1)[-1].lstrip("*&")


_DECLARATION_KEYWORDS = frozenset(("typedef", "struct", "union", "enum", "class"))


def _complete(lines: list[str]) -> bool:
    """Whether the lines so far can be a whole declaration: braces and parentheses
    closed, and more than declaration keywords (``typedef`` alone on its line is not)."""
    text = " ".join(lines)
    return (text.count("{") <= text.count("}") and text.count("(") <= text.count(")")
            and not set(text.split()) <= _DECLARATION_KEYWORDS)


def parse_kb(text_or_path: str | Path) -> Kb:
    """Parse kb.h content or a file.

    A ``Path`` is read from disk; a ``str`` is always treated as content. Callers
    that hold a filesystem path pass a ``Path`` so a one-line kb string is never
    mistaken for a filename.
    """
    text = (text_or_path.read_text(encoding="utf-8", errors="replace")
            if isinstance(text_or_path, Path) else text_or_path)
    kb = Kb()
    declaration: list[str] = []  # lines of the declaration being read

    def end_declaration() -> None:
        if declaration:
            kb.typedefs.append(" ".join(declaration))
            declaration.clear()

    for raw in text.splitlines():
        # Inline comments never reach entries: signatures/names/types feed
        # backend command strings (r2, Ghidra) where stray text is unsafe.
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue

        if line.startswith(("@ ", "$ ")):
            end_declaration()

        if line.startswith("@ "):
            parts = line[2:].split(None, 1)
            if len(parts) < 2:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            sig = parts[1].rstrip(";").strip()
            kb.functions.append(
                KbFunction(address=addr, signature=sig, name=extract_function_name(sig))
            )
        elif line.startswith("$ "):
            parts = line[2:].split()
            if len(parts) < 2:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            name = parts[-1]
            type_ = " ".join(parts[1:-1])
            kb.globals.append(KbGlobal(address=addr, type=type_, name=name))
        else:
            # A declaration runs until its braces and parentheses are closed and either a
            # line ends in ";" or the next line opens a new declaration, so "struct Foo" /
            # "{" and "typedef struct { ... }" / "Foo;" each stay one entry while a
            # declaration missing its ";" does not swallow the one after it.
            if declaration and _complete(declaration) and (
                    declaration[-1].endswith(";") or line.split(None, 1)[0] in _DECLARATION_KEYWORDS):
                end_declaration()
            declaration.append(line)
    end_declaration()
    return kb


def read_existing_addresses(path: str | Path) -> set[int]:
    """Return the addresses of ``@`` function and ``$`` global entries in a kb.h file.

    Used by bootstrap to skip addresses that already have an entry.
    Returns an empty set if the file does not exist.
    """
    if not os.path.isfile(path):
        return set()
    kb = parse_kb(Path(path))
    return {f.address for f in kb.functions} | {g.address for g in kb.globals}
