# deob - the full pipeline (static half + live trace), inside GhidrOrean

`_analysis\autodeob.py` in the parent research tree, shipped here so a clone of
this repo contains the whole tool.  One entry point, six stages:

    unpack -> decode -> dejunk -> CFG/DCE -> (trace) -> lift/inline

Stage 5-6 need the sample to *run*, everything before them does not.

```powershell
python tools/deob/autodeob.py sample.xem                 # static only, no execution
python tools/deob/autodeob.py sample.xem --run Host.exe   # + live trace, opcode -> handler
python tools/deob/autodeob.py sample.xem --run Host.exe `
    --run-snapshot 64 --run-state reg:esi                 # + per-opcode semantics, native x86
python tools/deob/autodeob.py --selftest-vm               # proves stages 5-6 on a synthetic VM
```

`--selftest-vm` builds its own VM (`vmfix.py`), traces it, lifts it, inlines it
and executes the result - nothing else is launched.  Frozen builds also accept
`--run`, but only for a target of the same bitness (a debugger cannot cross
WOW64): `tools/build_exe.ps1` in the parent repo builds `deob.exe` (x64) and
`deob32.exe` (x86).

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

## Keeping it in sync

The research tree (`_analysis/`) is where these files are developed; this
directory is the published copy.  They must stay byte-identical:

```powershell
powershell -File tools/deob/sync.ps1                       # copy from ..\..\..\_analysis
powershell -File tools/deob/sync.ps1 -Check                 # exit 1 on drift
powershell -File tools/deob/sync.ps1 -From C:\path\_analysis # explicit source
```
