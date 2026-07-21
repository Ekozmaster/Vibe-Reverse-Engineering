"""Tests for retools/query.py -- read-only SQL front-end."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


def _make_db(tmp_path):
    from index import GameIndex
    db = str(tmp_path / "index.db")
    gi = GameIndex(db)
    gi.replace("imports", [
        {"address": 0x1000, "name": "malloc", "module": "msvcrt.dll", "ordinal": None},
        {"address": 0x1008, "name": "free", "module": "msvcrt.dll", "ordinal": None},
    ], source="bootstrap")
    gi.close()
    return db


class TestRunQuery:
    def test_select_returns_rows(self, tmp_path):
        from index import GameIndex
        from query import run_query
        db = _make_db(tmp_path)
        conn = GameIndex.open_ro(db)
        res = run_query(conn, "SELECT count(*) AS n FROM imports")
        conn.close()
        assert res["error"] is None
        assert res["columns"] == ["n"]
        assert res["rows"][0][0] == 2
        assert res["row_count"] == 1
        assert isinstance(res["elapsed_ms"], (int, float))

    def test_syntax_error_captured(self, tmp_path):
        from index import GameIndex
        from query import run_query
        db = _make_db(tmp_path)
        conn = GameIndex.open_ro(db)
        res = run_query(conn, "SELCT bogus")
        conn.close()
        assert res["error"] is not None
        assert res["rows"] == []

    def test_write_is_rejected(self, tmp_path):
        from index import GameIndex
        from query import run_query
        db = _make_db(tmp_path)
        conn = GameIndex.open_ro(db)
        res = run_query(conn, "DELETE FROM imports")
        conn.close()
        assert res["error"] is not None  # read-only connection


class TestCli:
    def test_missing_db_directs_user(self, tmp_path, capsys):
        from query import main
        with pytest.raises(SystemExit):
            main(["NoSuchGame", "SELECT 1", "--db", str(tmp_path / "absent.db")])
        err = capsys.readouterr().err
        assert "bootstrap" in err.lower() or "export" in err.lower()

    def test_json_envelope_shape(self, tmp_path, capsys):
        import json
        from query import main
        db = _make_db(tmp_path)
        main(["Game", "SELECT name FROM imports ORDER BY name", "--db", db, "--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is True
        assert len(out["results"]) == 1
        r = out["results"][0]
        assert r["columns"] == ["name"]
        assert r["row_count"] == 2
        assert r["error"] is None

    def test_list_tables(self, tmp_path, capsys):
        from query import main
        db = _make_db(tmp_path)
        main(["Game", "", "--db", db, "--list-tables"])
        out = capsys.readouterr().out
        assert "imports" in out and "funcs" in out
