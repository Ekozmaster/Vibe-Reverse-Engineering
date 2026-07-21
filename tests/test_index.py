"""Tests for retools/index.py -- per-game SQLite index."""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestGameIndex:
    def test_creates_schema_and_version(self, tmp_path):
        from index import GameIndex, SCHEMA_VERSION
        gi = GameIndex(str(tmp_path / "index.db"))
        ver = gi._conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert ver == SCHEMA_VERSION
        gi.close()

    def test_replace_inserts_rows(self, tmp_path):
        from index import GameIndex
        gi = GameIndex(str(tmp_path / "index.db"))
        n = gi.replace("imports", [
            {"address": 0x1000, "name": "malloc", "module": "msvcrt.dll", "ordinal": None},
        ], source="bootstrap")
        assert n == 1
        assert gi.counts()["imports"] == 1
        gi.close()

    def test_replace_by_source_is_isolated(self, tmp_path):
        from index import GameIndex
        gi = GameIndex(str(tmp_path / "index.db"))
        gi.replace("funcs", [{"address": 0x1000, "name": "a"}], source="bootstrap")
        gi.replace("funcs", [{"address": 0x2000, "name": "b"}], source="ghidra")
        # Re-running bootstrap replaces only bootstrap rows, leaves ghidra intact.
        gi.replace("funcs", [{"address": 0x1500, "name": "a2"}], source="bootstrap")
        rows = gi._conn.execute("SELECT address FROM funcs ORDER BY address").fetchall()
        assert [r[0] for r in rows] == [0x1500, 0x2000]
        gi.close()

    def test_skips_high_bit_address(self, tmp_path):
        from index import GameIndex
        gi = GameIndex(str(tmp_path / "index.db"))
        n = gi.replace("funcs", [
            {"address": 0x148000000, "name": "ok"},       # positive, fits
            {"address": 0x8000000000000000, "name": "bad"},  # bit 63 set
        ], source="bootstrap")
        assert n == 1
        assert gi.counts()["funcs"] == 1
        gi.close()

    def test_open_ro_is_read_only(self, tmp_path):
        from index import GameIndex
        db = str(tmp_path / "index.db")
        gi = GameIndex(db)
        gi.replace("funcs", [{"address": 0x1000, "name": "a"}], source="bootstrap")
        gi.close()
        conn = GameIndex.open_ro(db)
        assert conn.execute("SELECT count(*) FROM funcs").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO funcs (address, source) VALUES (1, 'x')")
        conn.close()

    def test_default_db_path(self):
        from index import GameIndex
        p = GameIndex.default_db_path("MyGame")
        assert p.replace("\\", "/").endswith("patches/MyGame/index.db")

    def test_newer_schema_raises(self, tmp_path):
        from index import GameIndex, SCHEMA_VERSION
        db = str(tmp_path / "index.db")
        GameIndex(db).close()
        conn = sqlite3.connect(db)
        conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION + 1,))
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError):
            GameIndex(db)

    def test_cross_source_overwrite(self, tmp_path):
        from index import GameIndex
        gi = GameIndex(str(tmp_path / "index.db"))
        # Bootstrap writes a func with None name
        gi.replace("funcs", [{"address": 0x1000, "name": None}], source="bootstrap")
        # Ghidra overwrites the same address with a real name
        gi.replace("funcs", [{"address": 0x1000, "name": "Foo"}], source="ghidra")
        # Should have 1 row, with name='Foo' from ghidra source
        assert gi.counts()["funcs"] == 1
        row = gi._conn.execute("SELECT name, source FROM funcs").fetchone()
        assert row[0] == "Foo"
        assert row[1] == "ghidra"
        gi.close()

    def test_from_func_high_bit_skipped(self, tmp_path):
        from index import GameIndex
        gi = GameIndex(str(tmp_path / "index.db"))
        n = gi.replace("xrefs", [
            {"from_ea": 0x1000, "to_ea": 0x2000, "type": "call", "is_code": 1, "from_func": 0x8000000000000000}
        ], source="ghidra")
        assert n == 0
        assert gi.counts()["xrefs"] == 0
        gi.close()

    def test_empty_schema_version_recovers(self, tmp_path):
        """A crash between schema DDL and the version INSERT leaves schema_version
        created-but-empty; reopening must repair it, not silently skip the insert."""
        from index import GameIndex, SCHEMA_VERSION
        db = str(tmp_path / "index.db")
        GameIndex(db).close()
        # Simulate the crash window: drop the version row, keep the table.
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM schema_version")
        conn.commit()
        conn.close()
        gi = GameIndex(db)  # must not leave the DB versionless
        ver = gi._conn.execute("SELECT version FROM schema_version").fetchone()
        gi.close()
        assert ver is not None and ver[0] == SCHEMA_VERSION

    def test_bootstrap_rerun_does_not_downgrade_ghidra(self, tmp_path):
        """Re-running bootstrap after a ghidra export must not overwrite the
        authoritative ghidra funcs row with a provisional bootstrap row."""
        from index import GameIndex
        gi = GameIndex(str(tmp_path / "index.db"))
        gi.replace("funcs", [{"address": 0x1000, "name": None}], source="bootstrap")
        gi.replace("funcs", [{"address": 0x1000, "name": "RealName"}], source="ghidra")
        # Second bootstrap pass re-seeds the same provisional address.
        gi.replace("funcs", [{"address": 0x1000, "name": None}], source="bootstrap")
        row = gi._conn.execute("SELECT name, source FROM funcs WHERE address=0x1000").fetchone()
        gi.close()
        assert row == ("RealName", "ghidra")

    def test_xrefs_from_func_is_indexed(self, tmp_path):
        """The callees view and context lookups filter on xrefs.from_func;
        it must have a supporting index so the lookup is not a full scan."""
        from index import GameIndex
        db = str(tmp_path / "index.db")
        GameIndex(db).close()
        conn = sqlite3.connect(db)
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM xrefs WHERE from_func = 0x1000"
        ).fetchall()
        conn.close()
        assert any("ix_xrefs_from_func" in " ".join(str(c) for c in row) for row in plan)

    def test_project_db_path(self, tmp_path):
        from index import GameIndex
        p = GameIndex.project_db_path(str(tmp_path / "patches" / "MyGame"))
        assert p.replace("\\", "/").endswith("patches/MyGame/index.db")

    def test_resolve_db_returns_existing(self, tmp_path):
        from index import GameIndex
        db = str(tmp_path / "index.db")
        GameIndex(db).close()
        assert GameIndex.resolve_db("ignored", db) == db

    def test_resolve_db_exits_when_absent(self, tmp_path):
        from index import GameIndex
        with pytest.raises(SystemExit):
            GameIndex.resolve_db("NoSuchGame", str(tmp_path / "absent.db"))
