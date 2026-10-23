# deob - the full pipeline (static half + live trace), inside GhidrOrean

This is `_analysis\autodeob.py` from the parent research tree, shipped here so a
clone of this repo contains the whole tool.  One entry point, seven stages:

    unpack -> decode -> dejunk -> CFG/DCE -> devirt -> (trace) -> lift/inline

Only the last two need the sample to *run*; everything before them does not.

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

Both builds carry every stage, native recovery included (`deob.exe` is x64,
13.4 MB; `deob32.exe` is i386, 11.2 MB).  A 32-bit freeze needs a 32-bit
capstone, and PyPI makes that a trap: 5.0.3+ publish no win32 wheel at all,
and 5.0.2's `py3-none-win32` wheel ships an **x64** `capstone.dll` (ctypes
answers `WinError 193 ... is not a valid Win32 application`).  5.0.1 is the
newest genuinely-i386 wheel, so pin it:

```
py -3.11-32 -m pip install --only-binary=:all: "capstone==5.0.1"
```

Both then agree on the totals (537179 instrs, 344419 reachable, 17.2%
padding) but not on the cuts: 5.0.1 reports operand/register detail slightly
differently, so x3 comes out at 50081 cut / 2426 reverted on the x86 build
against 49800 / 2385 on the x64 one (+0.08 pp).  Every cut is still proven
under the capstone that ran, and the x86 artefacts pass `verify_devirt.py`
15/15 under the x64 checker.

The prebuilt binaries are attached to the `deob-v1.0` release
(<https://github.com/Panya3/GhidrOrean/releases/tag/deob-v1.0>, tag on
`4d6d0b3`) together with `SHA256SUMS.txt`; a bare clone needs nothing but
Python 3 and capstone to run `autodeob.py` instead.

## Layout

| file | role |
|---|---|
| `autodeob.py` | CLI + the six stages |
| `defus.py`, `oreandec.py`, `unpack.py`, `peread.py`, `cli.py` | static stages (ports of the Ghidra code path) |
| `cfgpass.py` | CFG + liveness DCE for the decoded bytecode |
| `devirt.py` | native recovery on the whole image: padding/data split, reachability from real entries, proof-checked cuts NOPped in place (`41_devirt.lst`, `50_devirt.exe`) |
| `vmtrace.py` | Win32 debugger: breakpoint on the dispatch site, records opcode + state |
| `vmlift.py` | turns the trace into handlers, semantics and an x86-64 listing |
| `vminline.py` | inlines the observed opcode stream as native x86-64 |
| `vmfix.py` | synthetic VM used as the differential oracle (`--selftest-vm`) |
| `test_devirt_identity.py` | unit checks for the effect model behind every cut (17 cases, both bitnesses) |
| `verify_devirt.py` | re-checks 15 invariants of a finished run from `42_devirt.json` + `50_devirt.exe` |
| `VERIFY.md` | the write-up: measured numbers, the invariants, and what is deliberately *not* proved |

The VM suite is stdlib-only and Windows-only where it debugs (`ctypes`).
`peread`/`cli` are deliberately duplicated from `tools/`: this directory is
self-contained, so `python tools/deob/autodeob.py` works from a bare checkout.

Artefacts land in `out/auto/<sample>/` next to this file when run from source
(gitignored), and next to the `.exe` when frozen - pass `--out` to change it.

## Proving the cuts

`devirt.py` never cuts an instruction because a global liveness pass says its
value is dead: the DCE pass only *proposes* (`candidates`), and a local audit
disposes (`removed` / `reverted`).  A cut is accepted only when

* the same basic block redefines the written register before any read of it, or
* the instruction is a value-preserving identity (`add rax, 0`, `mov rax, rax`,
  `lea rax, [rax]`, `and rax, -1`) - flags aside, and the audit proves the flags
  dead separately.

A 32-bit operation in long mode is **not** an identity even when it reads and
writes the same register: `mov eax, eax` zero-extends, so dropping it would
change `rax`.  That one width test is what keeps the relaxation sound, and
`test_devirt_identity.py` pins it down for both bitnesses.

Measured on the four corpus builds (`--engine audit`, 2026-10-23):

| build | bits | cut | % of reachable | reverted | struct |
|---|---|---|---|---|---|
| x3 | 32 | 49800 | 14.46% | 2385 | ok |
| x3_x64 | 64 | 51780 | 11.02% | 10640 | ok |
| xcorona | 32 | 40630 | 12.09% | 2028 | ok |
| xcorona_x64 | 64 | 65060 | 13.93% | 9986 | ok |

Long mode reverts more often (17% vs 4-5%) because the audit insists on a
same-block redefinition while 16 GPRs spread the junk thin - the reported cut is
a floor, not a ceiling, on what is provably dead.  `VERIFY.md` lists the 15
invariants and the "not proved" items; `verify_devirt.py <artefact root> -v`
re-checks a finished run without re-decoding the section.

## Keeping it in sync

The research tree (`_analysis/`) is where these files are developed; this
directory is the published copy.  They must stay byte-identical:

```powershell
powershell -File tools/deob/sync.ps1                       # copy from ..\..\..\_analysis
powershell -File tools/deob/sync.ps1 -Check                 # exit 1 on drift
powershell -File tools/deob/sync.ps1 -From C:\path\_analysis # explicit source
```
