"""End-to-end integration test: build -> bootstrap -> context."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

from common import Binary


class TestEndToEnd:
    """Full pipeline: sigdb build -> bootstrap -> context assemble."""

    def test_full_pipeline(self, sample_binary, tmp_path):
        from sigdb import SignatureDB, extract_byte_sig
        from bootstrap import bootstrap
        from context import assemble, postprocess, _parse_kb_names

        b = Binary(sample_binary)
        if not b.func_table:
            pytest.skip("No functions")

        # 1. Build a small signature DB from the binary itself
        db_path = str(tmp_path / "test_sigs.db")
        db = SignatureDB(db_path)
        for va in b.func_table[:5]:
            byte_sig = extract_byte_sig(b, va)
            if byte_sig:
                pattern, mask, tail_crc, size = byte_sig
                db.add_byte_sig(
                    pattern=pattern, mask=mask, tail_crc=tail_crc,
                    name=f"func_{va:X}", compiler="test",
                    source="self", func_size=size, category="crt")
        db.close()

        # 2. Run bootstrap
        project_dir = str(tmp_path / "TestProject")
        stats = bootstrap(sample_binary, project_dir, db_path=db_path)

        # Verify KB was created
        kb_path = Path(project_dir) / "kb.h"
        assert kb_path.exists()

        # Verify report was created
        report_path = Path(project_dir) / "bootstrap_report.txt"
        assert report_path.exists()
        report = report_path.read_text()
        assert "Compiler:" in report

        # 3. Assemble context for a function
        va = b.func_table[0]
        ctx = assemble(b, va, project_dir, db_path=db_path)
        assert "CONTEXT FOR" in ctx
        assert isinstance(ctx, str)

        # 4. Postprocess
        fake_decomp = f"call fcn.{b.func_table[0]:08x};"
        kb_names = _parse_kb_names(kb_path)
        result = postprocess(fake_decomp, kb_names)
        assert isinstance(result, str)
