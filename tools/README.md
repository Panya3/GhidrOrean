# tools/ - offline (CPython 3) helpers

`Orean.py` is a Ghidra/Jython script: it needs the Ghidra globals and a cursor
placed on the VM entry, and it prints into Ghidra's console.  The scripts here
do the steps that do not need Ghidra at all, from a normal `python3`.

| file | what it does |
|---|---|
| `unpack_vlizer.py` | statically unpack an Oreans container (`*.xem`: custom header + x86/x64 LZMA stub + LZMA_Alone) into a PE whose `.vlizer` section already holds the decompressed bytecode |
| `xrkdecode.py` | decode a byte range of that bytecode with `xrkdsm` and print a listing / mnemonic histogram |
| `defus_offline.py` | the block-level `thobfus.Defus.Simple` dejunk pass, outside Ghidra |
| `peread.py` | read-only PE section table (shared) |
| `cli.py` | shared `-h` / arity / exit-code helpers (shared) |
| `selftest.py` | builds its own inputs and checks all of the above |

## Typical run

    python tools/unpack_vlizer.py sample.xem sample_unpacked.exe
    python tools/xrkdecode.py sample_unpacked.exe --size 0x400 --stats 10
    python tools/defus_offline.py sample_unpacked.exe --rva 0x2FC000 --size 0x1C2000 --out dejunk.lst

`xrkdecode` / `defus_offline` want the RVA of the VM bytecode; without `--rva`
they use the section's VirtualAddress, i.e. the whole blob.

## What is covered

* Container: the `vlizer` scheme (custom header + LZMA_Alone).  The field width
  is detected rather than hardcoded (32-bit builds use 4-byte fields, 64-bit
  builds 8-byte ones) by looking for two fields whose sum is the section's
  `SizeOfRawData`, and the section is taken from the family
  `.vlizer .themida .winlicen .oreans .boot`.
* Bytecode: whatever `xrkdsm` / `thobfus` in this repo support today (CISC).
* Verified on four builds (32- and 64-bit, two products): unpack -> decode ->
  dejunk runs to completion on the whole section.

## What is not covered

* `scheme=themida-boot` images and the `stPust` containers (`xmag`, `xnina`)
  are *detected* and reported, but not unpacked.
* Dejunk here is the peephole pass `Orean.py` falls back to when `GetVMSig()`
  finds no wild-VM signature; it is not whole-function CFG/liveness DCE.
* Decoding assumes the section is already decrypted/decompressed (it is, after
  `unpack_vlizer.py`).  On a protected file straight from disk the bytes are
  compressed+encrypted, the listing is meaningless by construction and the tool
  reports the invalid-byte ratio.

## Requirements

CPython 3, standard library only.  These files are deliberately not
Jython-compatible: they are not Ghidra scripts and are never imported by
`Orean.py`.

## Verify

    python tools/selftest.py
