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

    @pytest.mark.parametrize("statement", [
        "ATTACH DATABASE '{other}' AS other",
        "VACUUM INTO '{other}'",
    ])
    def test_statement_that_would_create_another_file_is_refused(self, tmp_path, statement):
        from index import GameIndex
        from query import run_query
        db = _make_db(tmp_path)
        other = tmp_path / "other.db"
        conn = GameIndex.open_ro(db)
        res = run_query(conn, statement.format(other=other.as_posix()))
        conn.close()
        assert res["error"] is not None
        assert not other.exists()


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

    def test_a_failing_query_prints_the_error_and_exits_1(self, tmp_path, capsys):
        from query import main
        db = _make_db(tmp_path)
        with pytest.raises(SystemExit) as exc:
            main(["Game", "SELECT nope FROM imports", "--db", db])
        assert exc.value.code == 1
        assert capsys.readouterr().out.startswith("[error] ")

    def test_no_query_exits_1(self, tmp_path):
        from query import main
        db = _make_db(tmp_path)
        with pytest.raises(SystemExit) as exc:
            main(["Game", "--db", db])
        assert exc.value.code == 1

    def test_schema_lists_the_table_columns(self, tmp_path, capsys):
        from query import main
        db = _make_db(tmp_path)
        main(["Game", "--db", db, "--schema", "imports"])
        out = capsys.readouterr().out
        for column in ("address", "name", "module", "ordinal", "source"):
            assert column in out

    def test_text_output_is_an_aligned_table_with_a_row_count(self, tmp_path, capsys):
        from query import main
        db = _make_db(tmp_path)
        main(["Game", "SELECT name, module FROM imports ORDER BY name", "--db", db])
        lines = capsys.readouterr().out.splitlines()
        assert lines[0].split() == ["name", "module"]
        assert lines[1] == "-" * len("malloc") + "  " + "-" * len("msvcrt.dll")
        assert lines[2:4] == ["free    msvcrt.dll", "malloc  msvcrt.dll"]
        assert lines[4].startswith("(2 rows, ")
