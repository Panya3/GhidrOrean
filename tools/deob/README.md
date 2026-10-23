# deob - the full pipeline (static half + live trace), inside GhidrOrean

This is `_analysis\autodeob.py` from the parent research tree, shipped here so a
clone of this repo contains the whole tool.  One entry point, six stages:

    unpack -> decode -> dejunk -> CFG/DCE -> (trace) -> lift/inline

Stage 5-6 need the sample to *run*, everything before them does not.

```powershell
python tools/deob/autodeob.py sample.xem                 # static only, no execution
python tools/deob/autodeob.py sample.xem --run Host.exe   # + live trace, opcode -> handler
python tools/deob/autodeob.py sample.xem --run Host.exe `
    --run-snapshot 64 --run-state reg:esi                 # + per-opcode semantics, native x86
python tools/deob/autodeob.py --selftest-vm               # proves stages 5-6 on a synthetic VM
```

`--run` breaks on the dispatch site that the *static* half finds, so it needs a
host whose payload unpacks (`.vlizer`-style section).  For a plain PE there is
no such site and the trace fails with `no breakpoints`; trace that kind of
target with `vmtrace.py --exec <t> --bp-rva 0x<site>` and fold the result in
with `--trace <jsonl>` instead.

`--selftest-vm` builds its own VM (`vmfix.py`), traces it, lifts it, inlines it
and executes the result - nothing else is launched.  Frozen builds also accept
`--run`, but only for a target of the same bitness (a debugger cannot cross
WOW64).  The `.exe`s are built by `_analysis\build_exe.ps1` in the parent
research tree (it freezes this directory, `-Name deob32 -Python "py -3.11-32"`
for the 32-bit one, output in `dist\`); `tools\build_exe.ps1` in this repo is
for `OreanOffline.exe` only.

## Layout

| file | role |
|---|---|
| `autodeob.py` | CLI + the six stages |
| `defus.py`, `oreandec.py`, `unpack.py`, `peread.py`, `cli.py` | static stages (ports of the Ghidra code path) |
| `cfgpass.py` | CFG + liveness DCE for the decoded bytecode |
| `vmtrace.py` | Win32 debugger: breakpoint on the dispatch site, records opcode + state |
| `vmlift.py` | turns the trace into handlers, semantics and an x86-64 listing |
| `vminline.py` | inlines the observed opcode stream as native x86-64 |
| `vmfix.py` | synthetic VM used as the differential oracle (`--selftest-vm`) |

The VM suite is stdlib-only and Windows-only where it debugs (`ctypes`).
`peread`/`cli` are deliberately duplicated from `tools/`: this directory is
self-contained, so `python tools/deob/autodeob.py` works from a bare checkout.

Artefacts land in `out/auto/<sample>/` next to this file when run from source
(gitignored), and next to the `.exe` when frozen - pass `--out` to change it.

## Keeping it in sync

The research tree (`_analysis/`) is where these files are developed; this
directory is the published copy.  They must stay byte-identical:

```powershell
powershell -File tools/deob/sync.ps1                       # copy from ..\..\..\_analysis
powershell -File tools/deob/sync.ps1 -Check                 # exit 1 on drift
powershell -File tools/deob/sync.ps1 -From C:\path\_analysis # explicit source
```
