---
name: sigdb-signature-curation
description: Use when building, importing into, or scanning the sigdb signature DB, or importing FLIRT .pat files.
category: static-analysis
---

# Curate sigdb sources so names transfer only where code is identical

Import only names for code that compiles identically in other binaries: statically linked library code (MSVC CRT/STL, Havok, Gamebryo, RenderWare, zlib). Game-specific names mislabel other games and slow every scan, so keep them out of the shared DB.

- Check the source's target before reading any external symbol source (PDB, decomp repo, symbol list). Its CPU, OS and compiler must match the target binary: a PowerPC Xbox 360 PDB cannot label x86 PE code, and Linux ELF symbols or a rebuild with a different compiler (VC6/VC7.1 vs retail) only transfer after byte-verified matching.
- Filter before building: drop functions under 16 bytes (generic first-32-byte patterns), and drop any byte prefix that maps to more than one name. `sigdb import-pat` does both for FLIRT `.pat` files; do the same by hand for CSV maps.
- Keep provenance: prefer tagged library subsets (for example HAVOK_LIB, GAMEBRYO_LIB) over GUESS, COMMUNITY, or XBOX_* names. Record compiler and source per sig.
- Label every sig with its exact MSVC version (`msvc2008`, `msvc6.0`, `msvc2003_2005`). Matching skips sigs whose versions are absent from the binary's Rich header; a bare `msvc` label is never skipped, so it scans VC6 games against VS2008 code.
- Prefer sources with a FLIRT CRC16 (`.pat` lines): matching rejects a sig whose CRC over the bytes after the prefix fails. Sigs that fit in the 32-byte prefix carry no CRC and stay unverified.
- Bootstrap writes every sig match into kb.h with no confidence floor. `scan` already drops a name that is the best match at more than one address; tiny generic functions (MFC `CRect` constructors in a non-MFC game) can still be named wrongly.
- The byte tier wildcards only E8/E9 rel32 operands. Absolute addresses (globals, vtables, IAT calls) are not wildcarded, so names carry only to identically laid-out binaries.
- Validate before publishing: build from a subset, scan the source exe (expect near 100%), scan a second game on the same library version, and score the hits by hand.
- Build and test candidates on copies. Opening a schema-1 DB migrates it in place, so copy `retools/data/signatures.db` first, scan the same binaries with the old copy and the candidate, diff the hits, and confirm `git status retools/data/` is clean.
- After editing `retools/sigdb.py`, run `python -m pytest tests/test_sigdb.py -q` and the CI lint: `ruff check --select F --ignore F401,F541,F841 --exclude tools,rtx_remix_tools/dx/remix-comp-proxy/deps .`

Measured facts about candidate sources are in `references/decomp-sources.md`.
