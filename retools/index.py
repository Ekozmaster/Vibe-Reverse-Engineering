"""Per-game SQLite analysis index (idasql-aligned).

Owns the schema and the GameIndex writer. Two producers populate it,
distinguished by a ``source`` column so authoritative Ghidra rows replace
provisional bootstrap rows (delete-by-source then insert, transactionally).

Addresses are stored raw as signed-64 INTEGER (idasql convention). User-mode
PE image bases are positive and fit; rows whose address has bit 63 set are
skipped with a warning rather than corrupting ORDER BY. Render addresses with
SQLite's built-in printf('0x%x', address) -- no UDF, so the read-only
connection stays callback-free.

CLI:
    python -m retools.index status <Game> [--db PATH]
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

_PROJECT = Path(__file__).resolve().parent.parent

SCHEMA_VERSION = 1

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS funcs (address INTEGER PRIMARY KEY, end_ea INTEGER, name TEXT, size INTEGER,
                    flags INTEGER, prototype TEXT, comment TEXT, source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS names (address INTEGER, name TEXT, source TEXT NOT NULL, PRIMARY KEY(address, name));
CREATE TABLE IF NOT EXISTS xrefs (from_ea INTEGER, to_ea INTEGER, type TEXT, is_code INTEGER,
                    from_func INTEGER, source TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_xrefs_to ON xrefs(to_ea);
CREATE INDEX IF NOT EXISTS ix_xrefs_from ON xrefs(from_ea);
CREATE TABLE IF NOT EXISTS strings (address INTEGER PRIMARY KEY, length INTEGER, type TEXT, encoding TEXT,
                      content TEXT, source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS imports (address INTEGER, name TEXT, module TEXT, ordinal INTEGER, source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entries (ordinal INTEGER, address INTEGER, name TEXT, source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS segments (start_ea INTEGER, end_ea INTEGER, name TEXT, class TEXT, perm INTEGER,
                       source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blocks (func_ea INTEGER, start_ea INTEGER, end_ea INTEGER, size INTEGER, source TEXT NOT NULL);

CREATE VIEW IF NOT EXISTS callers AS SELECT x.from_func AS caller, x.to_ea AS callee_addr, f.name AS callee
  FROM xrefs x LEFT JOIN funcs f ON f.address = x.to_ea WHERE x.is_code=1 AND x.type='call';
CREATE VIEW IF NOT EXISTS callees AS SELECT x.from_func AS caller, x.to_ea AS callee_addr
  FROM xrefs x WHERE x.is_code=1 AND x.type='call';
CREATE VIEW IF NOT EXISTS grep AS
        SELECT 'func' AS entity, address, name FROM funcs WHERE name IS NOT NULL
  UNION ALL SELECT 'name',   address, name    FROM names
  UNION ALL SELECT 'import', address, name    FROM imports
  UNION ALL SELECT 'export', address, name    FROM entries
  UNION ALL SELECT 'string', address, content FROM strings;
"""

# Column order per table (source is always last; it is injected by replace()).
_TABLE_COLUMNS = {
    "funcs":    ["address", "end_ea", "name", "size", "flags", "prototype", "comment", "source"],
    "names":    ["address", "name", "source"],
    "xrefs":    ["from_ea", "to_ea", "type", "is_code", "from_func", "source"],
    "strings":  ["address", "length", "type", "encoding", "content", "source"],
    "imports":  ["address", "name", "module", "ordinal", "source"],
    "entries":  ["ordinal", "address", "name", "source"],
    "segments": ["start_ea", "end_ea", "name", "class", "perm", "source"],
    "blocks":   ["func_ea", "start_ea", "end_ea", "size", "source"],
}

_MAX_ADDR = (1 << 63) - 1


def _is_addr_col(col: str) -> bool:
    return col == "address" or col.endswith("_ea") or col == "from_func"


class GameIndex:
    """SQLite-backed per-game analysis index.

    Args:
        path: Filesystem path to the index database file.
    """

    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        mode = self._conn.execute("PRAGMA journal_mode").fetchone()[0]
        if str(mode).lower() != "wal":
            self._conn.execute("PRAGMA journal_mode=DELETE")
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        )
        if cur.fetchone() is not None:
            row = self._conn.execute("SELECT version FROM schema_version").fetchone()
            if row and row[0] > SCHEMA_VERSION:
                self._conn.close()
                self._conn = None
                raise RuntimeError(
                    f"Index schema version {row[0]} is newer than code version "
                    f"{SCHEMA_VERSION}. Update the code."
                )
            return
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
        self._conn.commit()

    def replace(self, table: str, rows: list[dict], source: str) -> int:
        """Replace all *source* rows in *table* with *rows*, transactionally.

        Rows are dicts keyed by column name (``source`` is injected). Any row
        whose address column exceeds signed-64 range is skipped with a warning.
        If a row's address collides with a row from another source, it overwrites it
        (last writer wins), allowing authoritative sources (e.g. Ghidra) to replace
        provisional data (e.g. bootstrap). This is a plain address-keyed upsert with
        no source-priority check, so re-running bootstrap AFTER a ghidra export
        overwrites the authoritative source='ghidra' funcs row with a provisional
        source='bootstrap' row (name=NULL) at the same address; recovery is to
        re-run export.

        Returns:
            Number of rows inserted.
        """
        if table not in _TABLE_COLUMNS:
            raise KeyError(f"unknown table: {table}")
        cols = _TABLE_COLUMNS[table]
        data_cols = [c for c in cols if c != "source"]
        addr_cols = [c for c in data_cols if _is_addr_col(c)]

        tuples: list[tuple] = []
        skipped = 0
        for r in rows:
            bad = False
            for c in addr_cols:
                v = r.get(c)
                if v is not None and (v < 0 or v > _MAX_ADDR):
                    bad = True
                    break
            if bad:
                skipped += 1
                continue
            tuples.append(tuple(r.get(c) for c in data_cols) + (source,))

        if skipped:
            print(f"[index] skipped {skipped} {table} row(s) with out-of-range address",
                  file=sys.stderr)

        placeholders = ",".join("?" * len(cols))
        insert_sql = f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
        with self._conn:  # single transaction
            self._conn.execute(f"DELETE FROM {table} WHERE source=?", (source,))
            self._conn.executemany(insert_sql, tuples)
        return len(tuples)

    def counts(self) -> dict[str, int]:
        return {
            t: self._conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
            for t in _TABLE_COLUMNS
        }

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    @classmethod
    def open_ro(cls, path: str) -> sqlite3.Connection:
        """Open *path* read-only via a file: URI (never mutates the index)."""
        uri = f"file:{Path(path).as_posix()}?mode=ro"
        return sqlite3.connect(uri, uri=True)

    @staticmethod
    def default_db_path(game: str) -> str:
        return str(_PROJECT / "patches" / game / "index.db")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="retools.index", description="Per-game SQLite index")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("status", help="Show per-table counts + schema version")
    s.add_argument("game", help="Game/project name (patches/<game>/index.db)")
    s.add_argument("--db", default=None, help="Explicit index.db path")
    args = p.parse_args(argv)

    db_path = args.db or GameIndex.default_db_path(args.game)
    if not Path(db_path).is_file():
        print(f"[error] no index at {db_path}. Run bootstrap or 'pyghidra_backend export' first.",
              file=sys.stderr)
        raise SystemExit(1)

    gi = GameIndex(db_path)
    ver = gi._conn.execute("SELECT version FROM schema_version").fetchone()[0]
    counts = gi.counts()
    gi.close()
    print(f"index: {db_path}  (schema_version={ver})")
    for table, n in counts.items():
        print(f"  {table:10s} {n}")


if __name__ == "__main__":
    main()
