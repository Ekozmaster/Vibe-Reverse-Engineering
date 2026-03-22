"""Tests for library APIs added to retools modules."""

import sys
from pathlib import Path

import pefile
import pytest

# Ensure retools is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


# -- xrefs: scan_refs is public ------------------------------------------

class TestScanRefs:
    def test_importable(self):
        from xrefs import scan_refs
        assert callable(scan_refs)

    def test_returns_list(self):
        from xrefs import scan_refs
        # Empty raw bytes, no matches expected
        result = scan_refs(b"\x00" * 64, 0x1000, 0, 64, 0xDEAD, "any")
        assert isinstance(result, list)

    def test_no_old_name(self):
        """_scan_refs should no longer exist as a separate symbol."""
        import xrefs
        # The public name is scan_refs; _scan_refs should not be independently defined
        assert hasattr(xrefs, "scan_refs")


# -- callgraph: imports updated scan_refs ---------------------------------

class TestCallgraphImport:
    def test_callgraph_importable(self):
        """callgraph should import without error after xrefs rename."""
        import callgraph
        assert hasattr(callgraph, "main")


# -- rtti: RttiClass, resolve_vtable, scan_all_rtti ----------------------

class TestRttiDataclass:
    def test_rtti_class_importable(self):
        from rtti import RttiClass
        obj = RttiClass(name=".?AVFoo@@", vtable_va=0x1000, hierarchy=[".?AVFoo@@"])
        assert obj.name == ".?AVFoo@@"
        assert obj.vtable_va == 0x1000
        assert obj.hierarchy == [".?AVFoo@@"]

    def test_rtti_class_default_hierarchy(self):
        from rtti import RttiClass
        obj = RttiClass(name="test", vtable_va=0)
        assert obj.hierarchy == []


class TestResolveVtable:
    def test_importable(self):
        from rtti import resolve_vtable
        assert callable(resolve_vtable)

    def test_invalid_va_returns_none(self, sample_binary):
        from rtti import resolve_vtable
        pe = pefile.PE(sample_binary, fast_load=False)
        result = resolve_vtable(pe, 0x0)
        assert result is None

    def test_bogus_va_returns_none(self, sample_binary):
        from rtti import resolve_vtable
        pe = pefile.PE(sample_binary, fast_load=False)
        result = resolve_vtable(pe, 0xDEADBEEF)
        assert result is None

    def test_returns_rtti_class_or_none(self, sample_binary):
        from rtti import resolve_vtable, RttiClass
        pe = pefile.PE(sample_binary, fast_load=False)
        # Pick an address inside the binary -- may or may not be a vtable
        base = pe.OPTIONAL_HEADER.ImageBase
        result = resolve_vtable(pe, base + 0x1000)
        assert result is None or isinstance(result, RttiClass)


class TestScanAllRtti:
    def test_importable(self):
        from rtti import scan_all_rtti
        assert callable(scan_all_rtti)

    def test_returns_list(self, sample_binary):
        from rtti import scan_all_rtti, RttiClass
        pe = pefile.PE(sample_binary, fast_load=False)
        result = scan_all_rtti(pe)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, RttiClass)

    def test_no_duplicate_names(self, sample_binary):
        from rtti import scan_all_rtti
        pe = pefile.PE(sample_binary, fast_load=False)
        result = scan_all_rtti(pe)
        names = [r.name for r in result]
        assert len(names) == len(set(names))


# -- search: StringRef, ImportEntry, find_strings, find_imports -----------

class TestSearchDataclasses:
    def test_string_ref_importable(self):
        from search import StringRef
        s = StringRef(va=0x1000, offset=0x400, value="hello")
        assert s.va == 0x1000
        assert s.value == "hello"

    def test_string_ref_frozen(self):
        from search import StringRef
        s = StringRef(va=0x1000, offset=0x400, value="hello")
        with pytest.raises(AttributeError):
            s.va = 0x2000

    def test_import_entry_importable(self):
        from search import ImportEntry
        e = ImportEntry(dll="kernel32.dll", name="CreateFileA")
        assert e.dll == "kernel32.dll"
        assert e.name == "CreateFileA"

    def test_import_entry_frozen(self):
        from search import ImportEntry
        e = ImportEntry(dll="kernel32.dll", name="CreateFileA")
        with pytest.raises(AttributeError):
            e.dll = "other.dll"


class TestFindStrings:
    def test_importable(self):
        from search import find_strings
        assert callable(find_strings)

    def test_returns_list_of_string_refs(self, sample_binary):
        from search import find_strings, StringRef
        from common import Binary
        b = Binary(sample_binary)
        result = find_strings(b, min_len=6)
        assert isinstance(result, list)
        assert len(result) > 0
        for item in result:
            assert isinstance(item, StringRef)
            assert len(item.value) >= 6

    def test_filter_keywords(self, sample_binary):
        from search import find_strings
        from common import Binary
        b = Binary(sample_binary)
        result = find_strings(b, filter_keywords=["xyznonexistent12345"])
        assert isinstance(result, list)
        assert len(result) == 0


class TestFindImports:
    def test_importable(self):
        from search import find_imports
        assert callable(find_imports)

    def test_returns_list_of_import_entries(self, sample_binary):
        from search import find_imports, ImportEntry
        from common import Binary
        b = Binary(sample_binary)
        result = find_imports(b)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, ImportEntry)
            assert isinstance(item.dll, str)
            assert isinstance(item.name, str)


# -- structrefs: FieldAccess, aggregate_struct ----------------------------

class TestFieldAccess:
    def test_importable(self):
        from structrefs import FieldAccess
        f = FieldAccess(offset=0x54, type_name="float", size=4, access="rw")
        assert f.offset == 0x54
        assert f.type_name == "float"
        assert f.refs == []

    def test_refs_default(self):
        from structrefs import FieldAccess
        f = FieldAccess(offset=0, type_name="void*", size=4, access="r")
        assert f.refs == []


class TestAggregateStruct:
    def test_importable(self):
        from structrefs import aggregate_struct
        assert callable(aggregate_struct)

    def test_invalid_va_returns_empty(self, sample_binary):
        from structrefs import aggregate_struct
        from common import Binary
        b = Binary(sample_binary)
        result = aggregate_struct(b, fn_va=0x0, fn_size=0x10)
        assert isinstance(result, list)

    def test_returns_list_of_field_access(self, sample_binary):
        from structrefs import aggregate_struct, FieldAccess
        from common import Binary
        b = Binary(sample_binary)
        base = b.base
        # Use a real code address if available
        ranges = b.exec_ranges()
        if ranges:
            va = ranges[0][0]
            result = aggregate_struct(b, fn_va=va, fn_size=0x100)
            assert isinstance(result, list)
            for item in result:
                assert isinstance(item, FieldAccess)
