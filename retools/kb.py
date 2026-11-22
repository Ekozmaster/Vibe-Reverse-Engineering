"""Single source of truth for the kb.h grammar.

kb.h lines take three shapes:
    @ 0xADDR <signature>;      -- function at an address
    $ 0xADDR <type...> <name>  -- global variable at an address
    <C declaration>            -- bare typedef / struct / enum
Blank lines and ``//`` and ``/* */`` comments are ignored; inside a string or
character literal those markers are text. A declaration that starts with
``typedef``, ``struct``, ``union``, ``enum`` or ``class`` may span lines: it
continues while its braces or parentheses are open, its opening brace may stand
on the line after its name, and the declarators of a ``typedef`` (``Foo, *PFoo;``)
on the line after its closing brace. A declaration whose brace or parenthesis is
never closed ends where the next line starts with one of those keywords. Every
other line, a preprocessor line included, is one entry.
"""

from __future__ import annotations

import os
import re
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


# A literal is matched first, so a comment marker inside it never starts a comment.
# A character literal holds one character or one escape: an apostrophe elsewhere
# (``Foo::`vftable'``) opens nothing.
_LITERAL_OR_COMMENT = re.compile(
    r"""(?P<literal>"(?:\\.|[^"\\\n])*"|'(?:\\.[^'\n]*|[^'\\\n])')"""
    r"""|[ \t]*(?://[^\n]*|/\*.*?(?:\*/|\Z))[ \t]*""",
    re.DOTALL,
)
_FIRST_WORD = re.compile(r"\w*")
# What may follow a typedef's closing brace on a line of its own: "Foo;", "Foo, *PFoo;", "Vec[4];"
_DECLARATORS = re.compile(r"[*&\s]*\w+(?:\s*\[\w*\])*(?:\s*,[*&\s]*\w+(?:\s*\[\w*\])*)*\s*;")


def _without_comments(text: str) -> str:
    """*text* with each comment and the blanks around it replaced by one space, keeping
    the line breaks a block comment spans. String and character literals stay as written."""
    def replacement(match: re.Match) -> str:
        if match.group("literal"):
            return match.group()
        return " " + "\n" * match.group().count("\n")

    return _LITERAL_OR_COMMENT.sub(replacement, text)


def _first_word(text: str) -> str:
    return _FIRST_WORD.match(text).group()


def _is_open(text: str) -> bool:
    """Whether *text* has a brace or parenthesis that is not closed, literals aside."""
    code = text
    if '"' in text or "'" in text:
        code = _LITERAL_OR_COMMENT.sub(lambda match: "" if match.group("literal") else match.group(), text)
    return code.count("{") > code.count("}") or code.count("(") > code.count(")")


def _continues(declaration: list[str], line: str) -> bool:
    """Whether *line* belongs to the declaration read so far.

    "struct Foo" / "{" and "typedef struct { ... }" / "Foo;" each stay one entry,
    while a declaration missing its ";" does not swallow the line after it.
    """
    text = " ".join(declaration)
    if _first_word(text) not in _DECLARATION_KEYWORDS:
        return False
    if _is_open(text):
        return True
    if set(text.split()) <= _DECLARATION_KEYWORDS:
        return True
    if text.endswith("}") and line == ";":
        return True
    if text.endswith(";") or line.startswith("#") or _first_word(line) in _DECLARATION_KEYWORDS:
        return False
    if _first_word(text) == "typedef" and text.endswith("}"):
        return _DECLARATORS.fullmatch(line) is not None
    return "{" not in text and line.startswith("{")


def _declarations(lines: list[str]) -> list[str]:
    """Group *lines* into declarations, each joined onto one line.

    A member line may start with a keyword (``struct Node *next;``, ``union {``),
    so only a brace or parenthesis that is still open at the last line shows that
    a declaration was never closed. Such a declaration ends where the next line
    starts with a declaration keyword, and grouping resumes from that line.
    """
    entries: list[str] = []
    first = 0
    while first < len(lines):
        end = first + 1
        while end < len(lines) and _continues(lines[first:end], lines[end]):
            end += 1
        if _is_open(" ".join(lines[first:end])):
            end = next((i for i in range(first + 1, end)
                        if _first_word(lines[i]) in _DECLARATION_KEYWORDS), end)
        entries.append(" ".join(lines[first:end]))
        first = end
    return entries


def parse_kb(text_or_path: str | Path) -> Kb:
    """Parse kb.h content or a file.

    A ``Path`` is read from disk; a ``str`` is always treated as content. Callers
    that hold a filesystem path pass a ``Path`` so a one-line kb string is never
    mistaken for a filename.
    """
    text = (text_or_path.read_text(encoding="utf-8", errors="replace")
            if isinstance(text_or_path, Path) else text_or_path)
    kb = Kb()
    declaration_lines: list[str] = []  # the lines since the last function or global

    def end_declarations() -> None:
        kb.typedefs.extend(_declarations(declaration_lines))
        declaration_lines.clear()

    # Comments never reach entries: signatures/names/types feed backend command
    # strings (r2, Ghidra) where stray text is unsafe.
    for raw in _without_comments(text).splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith(("@ ", "$ ")):
            end_declarations()

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
            declaration_lines.append(line)
    end_declarations()
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
