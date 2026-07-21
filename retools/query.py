"""Read-only SQL front-end for the per-game index.

Opens index.db read-only (file: URI) so a query can never mutate the index.
Text mode column-aligns; --json emits the idasql envelope.

Usage:
    python -m retools.query <Game> "SELECT ..." [--db PATH] [--json]
    python -m retools.query <Game> --list-tables
    python -m retools.query <Game> --schema funcs
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from index import GameIndex


DEFAULT_LIMIT = 1000


def run_query(conn: sqlite3.Connection, sql: str, limit: int = DEFAULT_LIMIT) -> dict:
    """Execute *sql* on a read-only connection, returning an envelope result.

    At most *limit* rows are returned (0 = unlimited); ``truncated`` in the
    envelope tells the caller more rows existed. Tables like xrefs hold
    millions of rows, so an uncapped ``SELECT *`` must not flood the caller.
    """
    t0 = time.perf_counter()
    try:
        cur = conn.execute(sql)
        rows = cur.fetchmany(limit + 1) if limit > 0 else cur.fetchall()
        truncated = limit > 0 and len(rows) > limit
        if truncated:
            rows = rows[:limit]
        columns = [d[0] for d in cur.description] if cur.description else []
        elapsed = (time.perf_counter() - t0) * 1000.0
        return {
            "columns": columns,
            "rows": [list(r) for r in rows],
            "row_count": len(rows),
            "truncated": truncated,
            "elapsed_ms": round(elapsed, 3),
            "error": None,
        }
    except (sqlite3.Error, sqlite3.Warning) as e:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return {
            "columns": [],
            "rows": [],
            "row_count": 0,
            "truncated": False,
            "elapsed_ms": round(elapsed, 3),
            "error": str(e),
        }


def _format_text(res: dict) -> str:
    if res["error"] is not None:
        return f"[error] {res['error']}"
    if not res["columns"]:
        return "(no columns)"
    cols = res["columns"]
    widths = [len(c) for c in cols]
    str_rows = [[("" if v is None else str(v)) for v in row] for row in res["rows"]]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(cols))]
    lines.append("  ".join("-" * widths[i] for i in range(len(cols))))
    for row in str_rows:
        lines.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)))
    lines.append(f"({res['row_count']} rows, {res['elapsed_ms']} ms)")
    if res["truncated"]:
        lines.append(f"[truncated at {res['row_count']} rows -- add a LIMIT clause "
                     "or pass --limit 0 for everything]")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="retools.query", description="Read-only SQL over index.db")
    p.add_argument("game", help="Game/project name (patches/<game>/index.db)")
    p.add_argument("sql", nargs="?", default="", help="SQL query (SELECT ...)")
    p.add_argument("--db", default=None, help="Explicit index.db path")
    p.add_argument("--json", action="store_true", help="Emit the idasql JSON envelope")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                   help=f"Max rows returned (default {DEFAULT_LIMIT}, 0 = unlimited)")
    p.add_argument("--list-tables", action="store_true", help="List tables/views and exit")
    p.add_argument("--schema", metavar="TABLE", help="Print PRAGMA table_info for TABLE and exit")
    args = p.parse_args(argv)

    db_path = GameIndex.resolve_db(args.game, args.db)

    conn = GameIndex.open_ro(db_path)
    try:
        if args.list_tables:
            sql = ("SELECT name, type FROM sqlite_master "
                   "WHERE type IN ('table','view') ORDER BY type, name")
        elif args.schema:
            sql = f"PRAGMA table_info({args.schema})"
        else:
            if not args.sql:
                print("[error] provide a SQL query, --list-tables, or --schema TABLE",
                      file=sys.stderr)
                raise SystemExit(1)
            sql = args.sql

        res = run_query(conn, sql, limit=args.limit)
    finally:
        conn.close()

    if args.json:
        print(json.dumps({"success": res["error"] is None, "results": [res]}))
    else:
        print(_format_text(res))
        if res["error"] is not None:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
