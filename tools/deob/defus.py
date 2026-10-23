"""Offline (Ghidra-free) Oreans dejunk pass.

Port of the code path GhidrOrean's Orean.py uses when GetVMSig() returns 0
(no `push imm32 ; push imm32 ; jmp` wild-VM signature - which is exactly what
this build of x3.xem shows):

    walk the bytecode linearly, follow unconditional jmps, remember the last
    forward conditional jump, then run thobfus.Defus.Simple(vm, 0xfffd, 'D')
    over the collected basic block list.

thobfus/xrkasm/xrkdsm/xrktbl/xrkopr never touch the Ghidra API, so the whole
mutation-junk removal engine runs on plain CPython once the bytecode is
extracted (see unpack.py). The only upstream coupling is `vm.tp` (machine
type) and `xlog`.

Usage:
    python defus.py _analysis/out/x3_unpacked.exe --rva 0x2FC000 --size 0x2000
    python defus.py _analysis/out/x3_unpacked.exe --rva 0x2FC000 --size 0x1C2000 \
                   --out _analysis/out/x3_dejunk.lst
"""
import argparse
import contextlib
import io
import sys

from oreandec import GHIDROREAN, load_pe, pick_section

# The upstream files were Py2-era ones CPython 3 could not parse (mixed tab+space
# indentation, `\ #comment` inside parentheses).  That is fixed in this fork
# (GhidrOrean commit "make the helper modules import on Python 3"), so the
# sanitised copies in _analysis/py3 are no longer needed: import straight from
# GhidrOrean.  mkpy3.py can still regenerate them for an older checkout.
if GHIDROREAN not in sys.path:
    sys.path.insert(0, GHIDROREAN)

import xrkdsm  # noqa: E402
import xrkutil  # noqa: E402

# upstream mixes up the casing of OP_F30F1x / OP_F30f1x between xrktbl.py and
# xrkasm.py/xrkdsm.py; alias both spellings before the engine is imported.
import xrktbl  # noqa: E402
for _mod in (xrkdsm, xrktbl):
    if not hasattr(_mod, "OP_F30F1x") and hasattr(_mod, "OP_F30f1x"):
        _mod.OP_F30F1x = _mod.OP_F30f1x
    if not hasattr(_mod, "OP_F30f1x") and hasattr(_mod, "OP_F30F1x"):
        _mod.OP_F30f1x = _mod.OP_F30F1x

import thobfus  # noqa: E402  (import after xrktbl: xrkasm does `import thobfus`)


class _Log(object):
    """Stand-in for Defus.log - DebugErrModify appends to it on every edit."""

    def __init__(self):
        self.n = 0

    def append(self, _):
        self.n += 1


class _VM(object):
    """Duck-typed replacement for thcisc.CISC - Defus only reads `tp`."""

    tp = 1
    name = "cisc"


def decode_at(data, off):
    """Decode one Oreans instruction at payload offset `off`."""
    with contextlib.redirect_stdout(io.StringIO()):
        return xrkdsm.XrkDecode(data[off:off + 16] + b"\0" * 32)


def walk(data, start, limit=0):
    """Linear walk with jmp-following, as in Orean.py's vmSig == 0 branch."""
    out = []
    addr = start
    nextJZ = -1
    jzpos = -1
    while addr < len(data):
        if limit and len(out) >= limit:
            break
        size, rk = decode_at(data, addr)
        if not size or size > 15:
            break                       # undecodable -> end of this block
        if rk.ID == xrkdsm.OP_JMP:
            op = rk.operand[0]
            if op.ID == xrkdsm.ID_MEM32:
                out.append((rk, addr))  # `jmp [mem]` = block end / return
                break
            if op.TID() != xrkdsm.TID_VAL:
                break
            nxt = (addr + size + op.value) & 0xFFFFFFFF
            out.append((rk, addr))
            if nxt <= addr:             # backwards jump -> block end
                break
            addr = nxt
            continue
        add = True
        if rk.ID in range(xrkdsm.OP_JA, xrkdsm.OP_JCXZ + 1):
            if rk.operand[0].value != 0:
                nextJZ = (addr + size + rk.operand[0].value) & 0xFFFFFFFF
                jzpos = len(out)
                add = False             # jcc is not kept as-is
        if add:
            out.append((rk, addr))
        addr += size
        if addr >= len(data):
            break
    return out, nextJZ, jzpos


def walk_block(data, start, limit=0):
    """Decode one basic block; return (items, successors)."""
    items = []
    addr = start
    while addr < len(data):
        if limit and len(items) >= limit:
            return items, []
        size, rk = decode_at(data, addr)
        if not size or size > 15:
            return items, []
        op0 = rk.operand[0]
        if rk.ID == xrkdsm.OP_JMP:
            if op0.ID == xrkdsm.ID_MEM32:
                items.append((rk, addr))       # jmp [mem] -> block ends
                return items, []
            if op0.TID() != xrkdsm.TID_VAL:
                return items, []
            tgt = (addr + size + op0.value) & 0xFFFFFFFF
            items.append((rk, addr))
            return items, ([tgt] if tgt < len(data) and tgt != addr else [])
        if xrkdsm.OP_JA <= rk.ID <= xrkdsm.OP_JCXZ:
            # keep the jcc (it is real control flow), both edges are successors
            items.append((rk, addr))
            succ = [addr + size]
            if op0.TID() == xrkdsm.TID_VAL:
                tgt = (addr + size + op0.value) & 0xFFFFFFFF
                if tgt < len(data):
                    succ.append(tgt)
            return items, [s for s in succ if s < len(data)]
        if rk.ID in (xrkdsm.OP_RETN, xrkdsm.OP_IRET):
            items.append((rk, addr))
            return items, []
        items.append((rk, addr))
        addr += size
    return items, []


def walk_graph(data, start=0, cap=0):
    """Recursive traversal; returns (blocks, instruction count, bytes covered)."""
    todo = [start]
    seen = set()
    blocks = []
    total = 0
    while todo:
        a = todo.pop()
        if a in seen:
            continue
        items, succ = walk_block(data, a)
        if not items:
            continue
        for rk, ad in items:
            seen.add(ad)
        blocks.append(items)
        total += len(items)
        for s in succ:
            if s not in seen:
                todo.append(s)
        if cap and total >= cap:
            break
    return blocks, total, len(seen)


def _reg(op):
    """(register number, operand size code) for a register operand, else None."""
    if op.TID() != xrkdsm.TID_REG:
        return None
    b = op.GetB(0)
    return b >> 4, b & 0xF


def _uses(instr):
    """Registers read by an instruction (memory bases/indexes included)."""
    out = set()
    for op in instr.operand:
        if op.ID == 0:
            continue
        if op.TID() == xrkdsm.TID_REG:
            out.add(op.GetB(0) >> 4)
        elif op.TID() == xrkdsm.TID_MEM:
            # base is GetB(1); GetB(2) is an index (0 = none)
            out.add(op.GetB(1) >> 4)
            if op.GetB(2):
                out.add(op.GetB(2) >> 4)
    return out


def deadstore(items):
    """Sound dead-store removal for flag-neutral moves inside one block.

    A `MOV reg, src` that is overwritten by a later write of the same register
    (same or larger size) before any read of it cannot affect anything, and MOV
    does not touch flags -- so dropping it is semantics preserving regardless of
    what happens across the block boundary. Returns (kept, removed) lists.
    """
    pend = {}                    # reg -> (index, size code)
    dead = set()
    moves = (xrkdsm.OP_MOV, xrkdsm.OP_MOVZX, xrkdsm.OP_MOVSX)
    for i, (rk, _addr) in enumerate(items):
        dst = _reg(rk.operand[0]) if rk.ID in moves else None
        uses = _uses(rk)
        if dst:
            uses.discard(dst[0])        # operand 0 of a move is a pure write
        for r in uses:
            pend.pop(r, None)           # read -> the pending value was used
        if dst:
            prev = pend.get(dst[0])
            if prev is not None and prev[1] <= dst[1]:
                dead.add(prev[0])       # fully overwritten before any read
            pend[dst[0]] = (i, dst[1])
        else:
            # anything else may read or clobber; do not guess its defs
            for r in _uses(rk):
                pend.pop(r, None)
            o0 = _reg(rk.operand[0])
            if o0:
                pend.pop(o0[0], None)
    kept = [it for i, it in enumerate(items) if i not in dead]
    removed = [it for i, it in enumerate(items) if i in dead]
    return kept, removed


def regstats(items):
    """Per-register churn: who is actually consumed, who is pure junk."""
    names = "EAX ECX EDX EBX ESP EBP ESI EDI".split()
    w = [0] * 8
    r = [0] * 8
    base = [0] * 8          # used as memory base/index
    stored = [0] * 8        # value written to memory
    branch = [0] * 8        # used by cmp/test/jcc
    alu = (xrkdsm.OP_ADD, xrkdsm.OP_SUB, xrkdsm.OP_XOR, xrkdsm.OP_OR,
           xrkdsm.OP_AND, xrkdsm.OP_SHL, xrkdsm.OP_SHR, xrkdsm.OP_INC,
           xrkdsm.OP_DEC, xrkdsm.OP_NEG, xrkdsm.OP_NOT, xrkdsm.OP_MOV,
           xrkdsm.OP_MOVZX, xrkdsm.OP_MOVSX, xrkdsm.OP_POP, xrkdsm.OP_PUSH)
    for rk, _a in items:
        o0, o1 = rk.operand[0], rk.operand[1]
        for op in (o0, o1):
            if op.ID == 0:
                continue
            if op.TID() == xrkdsm.TID_REG:
                r[op.GetB(0) >> 4] += 1
            elif op.TID() == xrkdsm.TID_MEM:
                base[op.GetB(1) >> 4] += 1
                if op.GetB(2):
                    base[op.GetB(2) >> 4] += 1
        if o0.TID() == xrkdsm.TID_REG and rk.ID in alu:
            w[o0.GetB(0) >> 4] += 1
            r[o0.GetB(0) >> 4] -= 1     # operand 0 of a write is not a read
        if o0.TID() == xrkdsm.TID_MEM and o1.TID() == xrkdsm.TID_REG:
            stored[o1.GetB(0) >> 4] += 1
        if rk.ID == xrkdsm.OP_CMP or rk.ID in range(xrkdsm.OP_JA, xrkdsm.OP_JCXZ + 1):
            for op in (o0, o1):
                if op.TID() == xrkdsm.TID_REG:
                    branch[op.GetB(0) >> 4] += 1
    print("reg   writes  reads  asMemBase  storedToMem  inCmp/Jcc")
    for i, n in enumerate(names):
        print("%-4s %7d %6d %10d %12d %10d"
              % (n, w[i], r[i], base[i], stored[i], branch[i]))


def build(items):
    """Load (instr, addr) pairs into a Defus instance sized to fit."""
    d = thobfus.Defus()
    n = len(items)
    d.maxlen = n + 64 if n else 64
    d.heap = [thobfus.CmdEntry() for _ in range(d.maxlen)]
    for i, (rk, addr) in enumerate(items):
        d.heap[i] = thobfus.CmdEntry(rk, addr)
    d.count = n
    d.log = _Log()
    return d


def listing(d, limit=0):
    with contextlib.redirect_stdout(io.StringIO()):
        out = d.GetListing(True, True, True)
    return out[:limit] if limit else out


def sweep_iter(data, simple="D", deadstore_on=True, max_instr=0):
    """Every not-yet-covered valid offset becomes a block start.

    The real entry point is only known at runtime, so sweeping is the only
    static way to cover the payload. Yields one dict per block with cumulative
    counters, so callers can either total them (sweep_blocks) or write a
    dejunked listing (autodeob.py).
    """
    orig_xlog = xrkutil.xlog
    xrkutil.xlog = lambda *args: None
    covered = set()
    n0 = kept_total = dead_total = 0
    blocks = 0
    vm = _VM()
    try:
        for off in range(len(data)):
            if off in covered:
                continue
            size, _rk = decode_at(data, off)
            if not size or size > 15:
                continue
            items, _succ = walk_block(data, off)
            if not items:
                continue
            for _rk, ad in items:
                covered.add(ad)
            blocks += 1
            n0 += len(items)
            gone = []
            if deadstore_on:
                items, gone = deadstore(items)
                dead_total += len(gone)
            d = build(items)
            with contextlib.redirect_stdout(io.StringIO()):
                d.Simple(vm, 0xfffd, simple, dbg=False)
            kept_total += d.count
            yield dict(off=off, entry=d, before=len(items) + len(gone),
                       dead=len(gone), kept=d.count, blocks=blocks,
                       n0=n0, dead_total=dead_total, kept_total=kept_total,
                       covered=len(covered), data_size=len(data))
            if max_instr and n0 >= max_instr:
                break
    finally:
        xrkutil.xlog = orig_xlog


def sweep_blocks(data, a):
    """CLI wrapper: run sweep_iter and print the totals."""
    st = dict(blocks=0, n0=0, dead_total=0, kept_total=0, covered=0,
              data_size=len(data))
    for r in sweep_iter(data, a.simple, a.deadstore, a.max):
        st = r
    n0 = st["n0"]
    print("sweep: %d blocks, %d instructions, %d bytes covered of %d"
          % (st["blocks"], n0, st["covered"], st["data_size"]))
    if a.deadstore:
        print("deadstore removed %d (%.1f%%)"
              % (st["dead_total"], st["dead_total"] * 100.0 / n0 if n0 else 0.0))
    print("Simple(%s) left %d (%.1f%% removed overall)"
          % (a.simple, st["kept_total"],
             (n0 - st["kept_total"]) * 100.0 / n0 if n0 else 0.0))


def run_blocks(data, a):
    """Apply deadstore + Defus.Simple to every block reachable from offset 0."""
    orig_xlog = xrkutil.xlog
    xrkutil.xlog = lambda *args: None
    try:
        blocks, total, _seen = walk_graph(data, 0, a.max)
        vm = _VM()
        kept_total = dead_total = 0
        worst = []
        for items in blocks:
            n0 = len(items)
            if a.deadstore:
                items, gone = deadstore(items)
                dead_total += len(gone)
            d = build(items)
            with contextlib.redirect_stdout(io.StringIO()):
                d.Simple(vm, 0xfffd, a.simple, dbg=False)
            kept_total += d.count
            worst.append((n0, d.count))
    finally:
        xrkutil.xlog = orig_xlog

    n0 = total
    print("blocks %d, instructions %d" % (len(blocks), n0))
    if a.deadstore:
        print("deadstore removed %d (%.1f%%)"
              % (dead_total, dead_total * 100.0 / n0 if n0 else 0.0))
    print("Simple(%s) left %d (%.1f%% removed overall)"
          % (a.simple, kept_total,
             (n0 - kept_total) * 100.0 / n0 if n0 else 0.0))
    big = sorted(worst, key=lambda t: -t[0])[:5]
    print("largest blocks (before, after): " + ", ".join("%d->%d" % t for t in big))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--section", default=None,
                    help="section holding the payload "
                         "(default: first Oreans section present)")
    ap.add_argument("--raw", action="store_true", help="image is a raw payload blob")
    ap.add_argument("--rva", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0x1000)
    ap.add_argument("--max", type=int, default=0, help="cap instructions walked")
    ap.add_argument("--out", default=None)
    ap.add_argument("--simple", default="D", choices=list("ABCD"))
    ap.add_argument("--deadstore", action="store_true",
                    help="also run the sound overwritten-before-read MOV pass")
    ap.add_argument("--regs", action="store_true",
                    help="per-register read/write churn table for the block")
    ap.add_argument("--blocks", action="store_true",
                    help="recursive traversal: run the passes on every reachable block")
    ap.add_argument("--sweep", action="store_true",
                    help="cover every not-yet-covered valid offset as a block start")
    ap.add_argument("--trace", action="store_true", help="print every pass count")
    a = ap.parse_args()

    if a.raw:
        data = open(a.image, "rb").read()
        rva = a.rva
    else:
        d, _base, secs = load_pe(a.image)
        a.section = a.section or pick_section(secs)
        if a.section not in secs:
            raise SystemExit("%s: no %s section (have: %s)"
                             % (a.image, a.section, ", ".join(sorted(secs))))
        s = secs[a.section]
        rva = a.rva or s["va"]
        data = d[s["raw"] + (rva - s["va"]):]
    data = data[:a.size]
    print("%s  rva %08X  %X bytes" % (a.image, rva, len(data)))

    if a.sweep:
        sweep_blocks(data, a)
        return

    if a.blocks:
        run_blocks(data, a)
        return

    items, nextJZ, jzpos = walk(data, 0, a.max)
    print("walked %d instructions from +0  (unreached jcc target %s, pos %d)"
          % (len(items), ("+%X" % nextJZ) if nextJZ >= 0 else "-", jzpos))

    if a.regs:
        regstats(items)

    d = build(items)
    before = d.count

    if a.deadstore:
        kept, gone = deadstore(items)
        print("deadstore: %d MOVs provably overwritten before any read (-%d, %.1f%%)"
              % (len(gone), len(gone), len(gone) * 100.0 / before if before else 0.0))
        items = kept
        d = build(items)
        before = d.count

    # keep the engine's own chatter off stdout; counts are reported below
    orig_xlog = xrkutil.xlog
    xrkutil.xlog = lambda *args: None
    try:
        vm = _VM()
        with contextlib.redirect_stdout(io.StringIO()):
            d.Simple(vm, 0xfffd, a.simple, dbg=False)
    finally:
        xrkutil.xlog = orig_xlog

    print("Simple(%s): %d -> %d instructions  (-%d, %.1f%% removed; %d edits logged)"
          % (a.simple, before, d.count, before - d.count,
             (before - d.count) * 100.0 / before if before else 0.0, d.log.n))

    lines = listing(d)
    if a.out:
        open(a.out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        print("listing -> %s (%d lines)" % (a.out, len(lines)))
    else:
        for l in lines[:40]:
            print(l)


if __name__ == "__main__":
    main()
