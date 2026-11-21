"""What the remix-comp-proxy template's sources say about its INI file."""

import configparser
import re
import textwrap
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "remix-comp-proxy"

_KEY_READ = re.compile(r'get_(?:int|bool|string|float)\(\s*"([^"]+)"\s*,\s*"([^"]+)"')


def keys_the_proxy_reads() -> set[tuple[str, str]]:
    """Every (section, key) the proxy's config loader asks the INI for."""
    source = (TEMPLATE / "src" / "shared" / "common" / "config.cpp").read_text(encoding="utf-8")
    return set(_KEY_READ.findall(source))


def parse_ini(text: str) -> configparser.ConfigParser:
    """*text* as the proxy reads it: key names keep their case, ';' starts a comment line."""
    parser = configparser.ConfigParser(comment_prefixes=(";",), interpolation=None)
    parser.optionxform = str
    parser.read_string(textwrap.dedent(text))
    return parser


def shipped_ini() -> configparser.ConfigParser:
    return parse_ini((TEMPLATE / "assets" / "remix-comp-proxy.ini").read_text(encoding="utf-8"))


def keys_of(ini: configparser.ConfigParser) -> set[tuple[str, str]]:
    return {(section, key) for section in ini.sections() for key in ini[section]}


def ini_section_in(report: str, section: str) -> configparser.ConfigParser:
    """The INI section a scanner script prints inside *report*: its header line up to the next blank line."""
    lines = report.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == f"[{section}]")
    end = next((i for i in range(start, len(lines)) if not lines[i].strip()), len(lines))
    return parse_ini("\n".join(lines[start:end]))
