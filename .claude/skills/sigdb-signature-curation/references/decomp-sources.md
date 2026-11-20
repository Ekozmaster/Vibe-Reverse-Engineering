# Candidate sigdb sources (checked 2026-11-20)

## momusdigital/fnv_decomp
- Byte-matching decompilation of FalloutNV.exe 1.4.0.525 (Steam PC). License CC0 1.0. CI rebuilds units with the original MSVC compilers and checks each function's bytes and call targets at its original address.
- build/units.json (about 26 MB): totals units 2989, functions 68657, bytes 11458056, eh_tails 1954. Each unit lists source, compiler, flags, and functions with address, MSVC-mangled symbol, and size, plus a symbols map.
- Compilers per function: sp1 67094, rtm 1362, vc8 211.
- Unique functions with non-placeholder names: 53396. Of those, 15184 are under 16 bytes.
- Provenance tag markers in src/ and third_party/ (markers cover globals and classes too, so these are not function counts): XBOX_PDB 8031, COMMUNITY 7173, GUESS 5674, XBOX_RETAIL_PDB 5172, HAVOK_LIB 1782, EXE 1007, XBOX_DEBUG_PDB 828, HAVOK_SRC 260, GAMEBRYO_LIB 217, GAMEBRYO_SRC 33. No CRT_LIB markers were found.
- Covers FNV only. Fallout 3 is not in this repo.
- Read it with a sparse clone of build/ and tools/ into an empty temp dir. Do not run its scripts.
