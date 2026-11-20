"""Tests for retools/kb.py -- consolidated kb.h grammar."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestParseKb:
    def test_function_line(self):
        from kb import parse_kb
        kb = parse_kb("@ 0x401000 void __cdecl ProcessInput(int key);")
        assert len(kb.functions) == 1
        f = kb.functions[0]
        assert f.address == 0x401000
        assert f.name == "ProcessInput"
        assert f.signature == "void __cdecl ProcessInput(int key)"

    def test_function_pointer_return_strips_decorator(self):
        from kb import parse_kb
        kb = parse_kb("@ 0x401000 Foo* GetFoo(void);")
        assert kb.functions[0].name == "GetFoo"

    def test_function_no_parens(self):
        from kb import parse_kb
        kb = parse_kb("@ 0xDEAD _malloc;")
        assert kb.functions[0].address == 0xDEAD
        assert kb.functions[0].name == "_malloc"

    def test_global_with_type(self):
        from kb import parse_kb
        kb = parse_kb("$ 0x7C5548 Object* g_mainObject")
        assert len(kb.globals) == 1
        g = kb.globals[0]
        assert g.address == 0x7C5548
        assert g.name == "g_mainObject"
        assert g.type == "Object*"

    def test_global_no_type(self):
        from kb import parse_kb
        kb = parse_kb("$ 0x7C554C g_flag")
        assert kb.globals[0].name == "g_flag"
        assert kb.globals[0].type == ""

    def test_typedef_line(self):
        from kb import parse_kb
        kb = parse_kb("struct Foo { int x; float y; };")
        assert kb.typedefs == ["struct Foo { int x; float y; };"]

    def test_comments_and_blanks_skipped(self):
        from kb import parse_kb
        kb = parse_kb("// a comment\n\n// another\n")
        assert kb.functions == []
        assert kb.globals == []
        assert kb.typedefs == []

    def test_malformed_address_skipped(self):
        from kb import parse_kb
        kb = parse_kb("@ 0xZZZZ notahex(void);")
        assert kb.functions == []

    def test_parses_from_path(self, tmp_path):
        from kb import parse_kb
        p = tmp_path / "kb.h"
        p.write_text("@ 0x401000 void Foo(void);\n")
        kb = parse_kb(p)
        assert kb.functions[0].name == "Foo"

    def test_existing_meccha_kb_all_comments(self):
        # The real freeform kb.h is entirely // comments + typedefs at its head;
        # it must parse without error and yield zero function/global entries there.
        from kb import parse_kb
        meccha = Path(__file__).resolve().parent.parent / "patches" / "MecchaChameleon" / "kb.h"
        if not meccha.is_file():
            pytest.skip("MecchaChameleon kb.h not present")
        kb = parse_kb(meccha)  # must not raise
        assert isinstance(kb.functions, list)


class TestInlineComments:
    def test_function_inline_comment_stripped(self):
        from kb import parse_kb
        kb = parse_kb(
            "@ 0x4CE130 void RenderScene_WorldGeom(void)"
            "            // iterate visible cells -> RenderCell (2nd render path)"
        )
        f = kb.functions[0]
        assert f.signature == "void RenderScene_WorldGeom(void)"
        assert f.name == "RenderScene_WorldGeom"

    def test_function_comment_after_semicolon_stripped(self):
        from kb import parse_kb
        kb = parse_kb("@ 0x401000 void Foo(void); // does stuff -> g_bar")
        assert kb.functions[0].signature == "void Foo(void)"

    def test_global_inline_comment_stripped(self):
        from kb import parse_kb
        kb = parse_kb(
            "$ 0x007A84D8 void* PTR_texResolveById"
            "   // fn ptr: (uint16 texture_id)->texhandle; render poly +0x20"
        )
        g = kb.globals[0]
        assert g.name == "PTR_texResolveById"
        assert g.type == "void*"

    def test_typedef_inline_comment_stripped(self):
        from kb import parse_kb
        kb = parse_kb("struct Foo { int x; }; // !=0 => skip cell (cleared each load)")
        assert kb.typedefs == ["struct Foo { int x; };"]


class TestDeclarationsOverSeveralLines:
    def test_struct_with_one_member_per_line_is_one_declaration(self):
        from kb import parse_kb
        kb = parse_kb("struct Foo {\n    int x;\n    float y;\n};\n")
        assert kb.typedefs == ["struct Foo { int x; float y; };"]

    def test_brace_on_its_own_line_belongs_to_the_line_before(self):
        from kb import parse_kb
        kb = parse_kb("struct Foo\n{\n    int x;\n};\n")
        assert kb.typedefs == ["struct Foo { int x; };"]

    def test_typedef_struct_ends_at_the_name_after_the_brace(self):
        from kb import parse_kb
        kb = parse_kb("typedef struct _Foo {\n    int x;\n} Foo;\nenum Mode { MODE_A=0 };\n")
        assert kb.typedefs == ["typedef struct _Foo { int x; } Foo;", "enum Mode { MODE_A=0 };"]

    def test_typedef_name_on_the_line_after_the_closing_brace(self):
        from kb import parse_kb
        kb = parse_kb("typedef struct {\n    int x;\n}\nFoo;\nstruct Bar { int y; };\n")
        assert kb.typedefs == ["typedef struct { int x; } Foo;", "struct Bar { int y; };"]

    def test_nested_braces_stay_in_one_declaration(self):
        from kb import parse_kb
        kb = parse_kb("struct Outer {\n    union {\n        int i;\n        float f;\n    } value;\n    int tail;\n};\n")
        assert kb.typedefs == ["struct Outer { union { int i; float f; } value; int tail; };"]

    def test_enum_with_one_value_per_line(self):
        from kb import parse_kb
        kb = parse_kb("enum Mode {\n    MODE_A = 0,   // first\n    MODE_B = 1,\n};\n")
        assert kb.typedefs == ["enum Mode { MODE_A = 0, MODE_B = 1, };"]

    def test_complete_lines_stay_separate(self):
        from kb import parse_kb
        kb = parse_kb("typedef int Handle;\nstruct Foo { int x; };\n")
        assert kb.typedefs == ["typedef int Handle;", "struct Foo { int x; };"]

    def test_function_and_global_lines_end_an_unclosed_declaration(self):
        from kb import parse_kb
        kb = parse_kb("struct Broken {\n    int x;\n@ 0x401000 void Foo(void);\n$ 0x7C5548 int g_x\n")
        assert kb.typedefs == ["struct Broken { int x;"]
        assert [f.name for f in kb.functions] == ["Foo"]
        assert [g.name for g in kb.globals] == ["g_x"]


class TestParseKbInputHandling:
    def test_content_that_names_a_file_is_parsed_as_content(self, tmp_path, monkeypatch):
        """A one-line kb string is parsed as content even if it happens to match
        an existing filename -- parse_kb must not sniff strings as paths."""
        from kb import parse_kb
        monkeypatch.chdir(tmp_path)
        # Create a file whose name equals the content we pass.
        content = "@ 0x401000 void Foo(void);"
        (tmp_path / content.replace("/", "_")).write_text("@ 0xDEAD void Other(void);\n")
        kb = parse_kb(content)  # str -> treated as content, never read as a path
        assert kb.functions[0].name == "Foo"
        assert kb.functions[0].address == 0x401000

    def test_path_is_read(self, tmp_path):
        from kb import parse_kb
        p = tmp_path / "kb.h"
        p.write_text("@ 0x402000 void Bar(void);\n")
        kb = parse_kb(p)
        assert kb.functions[0].name == "Bar"

    def test_a_file_with_a_stray_non_utf8_byte_is_still_read(self, tmp_path):
        from kb import parse_kb
        p = tmp_path / "kb.h"
        p.write_bytes(b"// caf\xe9\n@ 0x402000 void Bar(void);\n")
        assert [f.name for f in parse_kb(p).functions] == ["Bar"]

    def test_malformed_entries_are_skipped_without_ending_the_parse(self):
        from kb import parse_kb
        kb = parse_kb("@ 0x401000\n"
                      "@ 0xZZZZ void Bad(void);\n"
                      "$ 0x7C5548\n"
                      "$ 0xZZZZ int g_bad\n"
                      "@ 0x402000 void Good(void);\n"
                      "$ 0x7C554C int g_good\n")
        assert [(f.address, f.name) for f in kb.functions] == [(0x402000, "Good")]
        assert [(g.address, g.name) for g in kb.globals] == [(0x7C554C, "g_good")]
        assert kb.typedefs == []


class TestReadExistingAddresses:
    def test_collects_function_and_global_addresses(self, tmp_path):
        from kb import read_existing_addresses
        p = tmp_path / "kb.h"
        p.write_text("@ 0x401000 void Foo(void);\n$ 0x7C5548 int g_x\n")
        addrs = read_existing_addresses(p)
        assert addrs == {0x401000, 0x7C5548}

    def test_missing_file_empty_set(self, tmp_path):
        from kb import read_existing_addresses
        assert read_existing_addresses(tmp_path / "nope.h") == set()
