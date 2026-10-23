# devirt - verification

What was actually proved about the native-recovery stage (`devirt.py`), on which
inputs, and what is still only *modelled* rather than proved.

Reproduce everything below with:

    cd _analysis
    python test_devirt_identity.py          # 17 unit cases, exit 0
    python verify_devirt.py out/corpus -v   # 60 artifact checks, exit 0
    python devirt.py out/corpus/x3/10_unpacked.exe --out-dir out/corpus/x3 -v

The two checkers and this file also ship as `tools/deob/*` (kept
byte-identical by `tools/deob/sync.ps1`), so a clone runs the same checks against
artefact trees it produced itself: `python verify_devirt.py <artefact root>`.

Last full run: 2026-10-23, all four corpus builds rebuilt from scratch
(`41_devirt.lst`, `42_devirt.json`, `50_devirt.exe` regenerated).

## Measured (per build)

| build | bits | `.vlizer` | instrs | padding | reachable | junk/data | candidates | cut | cut % of reachable | reverted | struct |
|---|---|---|---|---|---|---|---|---|---|---|---|
| x3 | 32 | 1C2000 | 537179 | 17.25% | 75.35% | 7.33% | 52185 | 49800 | 14.46% | 2385 | ok |
| x3_x64 | 64 | 352000 | 898382 | 20.44% | 70.74% | 8.69% | 62420 | 51780 | 11.02% | 10640 | ok |
| xcorona | 32 | 1C2000 | 543460 | 18.83% | 73.83% | 7.28% | 42658 | 40630 | 12.09% | 2028 | ok |
| xcorona_x64 | 64 | 320000 | 804008 | 17.51% | 75.08% | 7.39% | 75046 | 65060 | 13.93% | 9986 | ok |

`reachable` is high by design: the mutation junk is interleaved with the real
code and *falls through* into it, so it is genuinely live - only the local proof
can cut it. `cut` is always a subset of `candidates`: the optimiser proposes,
the audit disposes.

## Invariants checked (`verify_devirt.py`, 15 per build, 60 total, 0 failed)

1. `candidates == removed + reverted` - no candidate disappears silently.
2. `removed_by` (dead store / dead register write / no effect) sums to `removed`.
3. `verify.status == "audit"`, `verify.proven == removed`,
   `verify.reverted == reverted` - nothing is cut without a local proof.
4. `kept + removed == reachable_instrs` - the listing is a partition.
5. `removed_pct`, `padding_pct`, `reachable_pct` recomputed from the raw counts.
6. The section's bytes partition into reachable + junk + padding + undecodable
   (residual matches `unreachable_pct` to within the 2-dp rounding).
7. `structural.status == "ok"`, `missing == changed == 0` - re-decoding the
   patched section reproduces the same instruction grid (487k / 846k / 502k /
   738k instructions re-checked). This is the "no byte ever moves" proof.
8. `50_devirt.exe` exists, keeps the input's file size, changes no byte outside
   the payload section, and every changed byte *is* `0x90` (227068 / 298418 /
   183753 / 390811 bytes in place).
9. Every byte before the payload section is byte-identical, and the patched file
   still parses with the same image base, entry point and section table.

## Why long mode keeps fewer cuts

`x3_x64` reverts 10640 of 62420 candidates (17%); the 32-bit builds revert 4-5%.
Every reverted sample is a *full-width* 64-bit write (`add r10, 0x33`,
`mov rax, 0`, `xor r9, r15`, `and r11, 0x78`): the whole-stream liveness says the
value is dead, but the audit only accepts a cut when the **same block**
redefines the register before any read of it - it must not trust the liveness
that produced the candidate. Long mode spreads the junk over 16 GPRs, so a given
`r8`-`r15` is rarely redefined inside the same 100-instruction block; in 32-bit
there are 7 GPRs and redefinitions are dense.

Concretely (`x3_x64`, block `+0`): `mov r10, 0` at `0x52B087` is cut,
`add r10, 0x33` at `0x52B0FB` is not - nothing later in that block writes `r10`.
That asymmetry is the audit working as intended, and it is why the reported
`cut %` is a floor, not a ceiling, on what is provably dead.

## End to end

* `autodeob.py` prints the devirt line and fills the `devirt (-%)` column plus
  the `41_devirt.lst` / `50_devirt.exe` artifact rows (`14.5%` on x3, ~155 s per
  build end to end, re-run after the change).
* the packaged `GhidrOrean\dist\deob.exe` (13.4 MB / 14,017,553 bytes, rebuilt
  after the stage-5b insert was fixed) produces output identical to the source
  run - `cut 49800 (14.46%), 2385 reverted, struct ok`, 155.2 s end to end -
  and passes its own `--selftest-vm` (8/8), which is what proves the trace
  stage survived the rebuild.
* the same stage runs in the 32-bit freeze (`dist\deob32.exe`, i386, 11.2 MB,
  capstone 5.0.1 - the newest genuinely-i386 wheel): x3 gives
  `cut 50081 (14.54%), 2426 reverted, struct ok` (77.3 s for that stage,
  85.9 s for the run), and those artefacts pass all 15 checks under the
  64-bit checker.  The +0.08 pp against the x64 build is capstone 5.0.1
  reporting operand detail slightly differently (same 537179 instrs /
  344419 reachable / 17.2% padding), not a difference in the proof.
* `tools\deob\sync.ps1 -Check` reports `in sync: 15 files` (exit 0) with
  `devirt.py`, `autodeob.py`, `cfgpass.py`, the two checkers and this file
  hash-identical to `_analysis`.

## Not proved

* **semantic equivalence with the original program** - no ground truth exists.
  The stage proves "this instruction cannot affect the rest of its block", not
  "the kept stream still behaves like the original"; everything that survives is
  simply outside the reach of a local proof.
* **seed completeness** - seeds come from entry points, external pointers and
  prologues. Code reachable only through a computed jump is treated as junk,
  which is why the `indirect` counters (1254-1557 `jmp-indirect`, 7-8 `call`,
  1-10 `jmp-out` per build) are reported instead of assumed to be zero.
* **`--engine unicorn`** - the cross-check is unavailable on this machine
  (`import unicorn` fails here), so it stays opt-in; the default `--engine audit`
  needs no third-party runtime and is what every number above was produced with.

## Unit cases (`test_devirt_identity.py`, 17/17 ok, exit 0)

Two separate predicates, and the width test is what keeps the relaxation sound
in long mode:

* `_identity(x)` - cutting it cannot change any register *value* (flags aside).
  Only this one lets the audit forget the register entirely.
* `_noop(x, flags_dead)` - *candidate* generator for the DCE pass. It may be
  optimistic (a 32-bit destination in long mode still zero-extends), because
  every candidate it proposes is re-proved by the audit before it is cut.

| instruction | 32-bit | 64-bit |
|---|---|---|
| `add eax, 0` | identity, noop | not identity (writes all of RAX); candidate only |
| `add rax, 0` | - | identity, noop |
| `mov eax, eax` | identity, noop | not identity (zero-extends); candidate only |
| `mov rax, rax` | - | identity, noop |
| `lea eax, [eax]` (+0 disp) | identity, noop | not identity (result is 32-bit) |
| `lea rax, [rax]` | - | identity, noop |
| `and eax, 0xffffffff` | identity, noop | - |
| `and rax, -1` | - | identity, noop |
| `or eax, 0xffffffff` | not identity, not noop (writes -1) | same |
| `shl eax, 0` | identity, noop | same |
| `cmp eax, 0` | not identity, not noop (reads, writes flags only) | same |
| `nop` | identity, noop | same |

The last check in the test file is the *ledger*: an instruction classified as
identity may write no register it does not also read - `mov rax, rax`,
`lea rax, [rax]`, `add rax, 0` all obey it, which is precisely why dropping them
cannot change a value. A 32-bit form in long mode is not on that list at all,
so it can never be dropped on the strength of the identity rule.

