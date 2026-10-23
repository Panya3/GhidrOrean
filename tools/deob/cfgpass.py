#!/usr/bin/env python3
"""cfgpass.py - whole-payload CFG, liveness and dead-code elimination.

`defus.py` (and therefore `autodeob.py`'s dejunk stage) works *block by block*:
`Defus.Simple` is a peephole engine, so it can only collapse junk that is local
to the window it is looking at.  Most of the churn in this build is longer:

    002FC01D  OR  ESI,0x1        <- 4-instruction chain computing a value
    002FC023  SUB ESI,EAX
    002FC027  XOR ESI,EDI
    002FC02E  SUB ESI,0x24
    002FC040  MOV ESI,0x1        <- ...that is overwritten before it is ever read

Only liveness over the whole stream can prove that and delete it.  This module
does exactly that, plus the control-flow graph the decoder never built:

    scan      every decodable offset, resynchronising on invalid bytes
    cfg       basic blocks, direct edges; an edge that leaves the decoded map
              (desync / data / indirect jump) becomes "unknown" -> conservative
    liveness  backward bitmask fixpoint over 8 registers + an EFLAGS
              pseudo-register (so `ADD r,x` cannot go while a `Jcc` reads CF)
    dce       delete pure-register instructions whose destination is dead,
              repeat to fixpoint (kills whole chains, not just the last write)
    listing   survivors with block headers, RVAs preserved

Soundness rules (deliberately conservative):
  * only instructions with no memory operand are removed (LEA counts as pure:
    it computes an address, it does not dereference)
  * `MOV [m],r`, PUSH/POP, string ops, IN/OUT, INT, HLT, ... are never removed
  * 8/16-bit register writes are treated as reads, so no full-width producer
    that only feeds them can be dropped
  * unknown mnemonics keep all their operands and are never removed
  * an unknown successor edge makes every register + flags live at that point

Usage (never executes the sample):
    python cfgpass.py out/auto/x3/10_unpacked.exe --out 40_cfg.lst
    python cfgpass.py <pe> --size 0x20000 --show-removed --stats
"""
import argparse
import collections
import contextlib
import io
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import defus as dz          # noqa: E402  (configures the GhidrOrean path)
import oreandec            # noqa: E402
import xrkdsm              # noqa: E402

# register file EAX ECX EDX EBX ESP EBP ESI EDI + EFLAGS
F = 8
FLAGS = 1 << F
ALL_REGS = (1 << 9) - 1
SIZE32 = 3


def _iset(*names):
    out = set()
    for n in names:
        v = getattr(xrkdsm, n, None)
        if v is not None:
            out.add(v)
    return out


def _iprefix(*prefixes):
    out = set()
    for n in dir(xrkdsm):
        if n.startswith("OP_") and any(n.startswith(p) for p in prefixes):
            out.add(getattr(xrkdsm, n))
    return out


# 0xA3..0xB3 = JA .. JCXZ
COND_JMP_IDS = set(range(getattr(xrkdsm, "OP_JA"),
                         getattr(xrkdsm, "OP_JCXZ") + 1))

# operand 0 is a pure destination, operands 1.. are sources
PURE_DST = _iset("OP_MOV", "OP_MOVZX", "OP_MOVSX", "OP_LEA", "OP_BSF", "OP_BSR") \
    | _iprefix("OP_SET")

# operand 0 is read *and* written
RMW = _iset("OP_ADD", "OP_SUB", "OP_AND", "OP_OR", "OP_XOR", "OP_SHL", "OP_SHR",
            "OP_SAR", "OP_ROL", "OP_ROR", "OP_RCL", "OP_RCR", "OP_ADC", "OP_SBB",
            "OP_INC", "OP_DEC", "OP_NEG", "OP_NOT", "OP_SHLD", "OP_SHRD",
            "OP_XADD", "OP_BT", "OP_BTS", "OP_BTR", "OP_BTC", "OP_XCHG",
            "OP_BSWAP") | _iprefix("OP_CMOV")

FLAG_ONLY = _iset("OP_CMP", "OP_TEST")

# instructions that define *all* arithmetic flags they are allowed to touch
FLAGS_WRITE_FULL = _iset(
    "OP_ADD", "OP_SUB", "OP_ADC", "OP_SBB", "OP_AND", "OP_OR", "OP_XOR",
    "OP_CMP", "OP_TEST", "OP_INC", "OP_DEC", "OP_NEG", "OP_SHL", "OP_SHR",
    "OP_SAR", "OP_ROL", "OP_ROR", "OP_RCL", "OP_RCR", "OP_SHLD", "OP_SHRD",
    "OP_BT", "OP_BTS", "OP_BTR", "OP_BTC", "OP_XADD", "OP_MUL", "OP_IMUL",
    "OP_DIV", "OP_IDIV", "OP_STC", "OP_CLC", "OP_CMC", "OP_STD", "OP_CLD",
    "OP_POPF", "OP_SAHF", "OP_IRET", "OP_AAA", "OP_AAS", "OP_AAD", "OP_AAM",
    "OP_DAA", "OP_DAS")

# write *some* flags only (BSF/BSR -> ZF): model as read+write so neither an
# earlier flag producer nor a later flag consumer can be mis-modelled
FLAGS_BARRIER = _iset("OP_BSF", "OP_BSR")

FLAGS_READ = _iset("OP_ADC", "OP_SBB", "OP_RCL", "OP_RCR", "OP_LAHF", "OP_PUSHF",
                   "OP_INTO", "OP_LOOP", "OP_LOOPE", "OP_LOOPNZ",
                   "OP_JCXZ") | COND_JMP_IDS | _iprefix("OP_CMOV", "OP_SET")

# instructions whose effect leaves the analysed stream (call/return/interrupt):
# registers may be observed by code we cannot see, so everything is live there
BARRIER = _iset("OP_CALL", "OP_RETN", "OP_RETF", "OP_IRET", "OP_INT", "OP_INT3",
                "OP_SYSCALL", "OP_SYSENTER", "OP_SYSEXIT", "OP_SYSRET", "OP_HLT",
                "OP_IN", "OP_OUT", "OP_CPUID", "OP_RDTSC")

# never deleted even though they may have no memory operand
NEVER_PURE = _iset("OP_CALL", "OP_PUSH", "OP_POP", "OP_PUSHF", "OP_PUSHA",
                   "OP_LEAVE", "OP_ENTER", "OP_RETN", "OP_RETF", "OP_IRET",
                   "OP_JMP", "OP_HLT", "OP_INT", "OP_INT3", "OP_IN", "OP_OUT",
                   "OP_INVD", "OP_WBINVD", "OP_RDMSR", "OP_WRMSR", "OP_RDTSC",
                   "OP_CPUID", "OP_SYSCALL", "OP_SYSENTER", "OP_SYSEXIT",
                   "OP_SYSRET", "OP_GETSEC", "OP_RSM", "OP_WAIT", "OP_UD2",
                   "OP_UNDEFINED")

class Ins(object):
    """One decoded instruction with pre-computed register/flag effects."""

    __slots__ = ("addr", "size", "rk", "uses", "defs", "pure", "mem",
                 "target", "kind", "_text")

    def __init__(self, addr, size, rk):
        self.addr = addr
        self.size = size
        self.rk = rk
        self.uses = 0
        self.defs = 0
        self.pure = False       # no side effect besides its register/flag write
        self.mem = False        # touches memory (load or store)
        self.target = None      # direct control-flow target
        self.kind = "other"     # jmp | jcc | call | ret | other
        self._text = None
        self._analyse()

    # -- rendering --------------------------------------------------------
    @property
    def text(self):
        if self._text is None:
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    t = xrkdsm.XrkText(self.rk)
                self._text = t if t else "<undecodable>"
            except Exception:
                try:
                    self._text = "%s <undecodable>" % self.rk.opInfo.MNEM
                except Exception:
                    self._text = "<undecodable %04X>" % self.rk.ID
        return self._text

    @property
    def mnem(self):
        return self.text.split(" ", 1)[0]

    # -- effect analysis --------------------------------------------------
    def _analyse(self):
        rk = self.rk
        rid = rk.ID
        o0, o1, o2 = rk.operand[0], rk.operand[1], rk.operand[2]
        reg0_full = _regnum(o0)
        reg0_any = _regnum(o0, full_only=False)

        if rid == xrkdsm.OP_JMP or rid in COND_JMP_IDS or rid == xrkdsm.OP_CALL:
            if o0.TID() == xrkdsm.TID_VAL:
                self.target = (self.addr + self.size + o0.value) & 0xFFFFFFFF
            self.uses = _operand_regs(o0)
            self.kind = ("jmp" if rid == xrkdsm.OP_JMP else
                         "jcc" if rid in COND_JMP_IDS else "call")
        elif rid in (xrkdsm.OP_RETN, xrkdsm.OP_RETF):
            self.kind = "ret"
        elif rid == xrkdsm.OP_IRET:
            self.kind = "ret"
            self.mem = True

        if rid in PURE_DST:
            for op in (o1, o2, rk.operand[3]):
                if op.ID:
                    self.uses |= _operand_regs(op)
                    if op.TID() == xrkdsm.TID_MEM:
                        self.mem = True
            if o0.TID() == xrkdsm.TID_MEM:
                self.mem = True
                self.uses |= _operand_regs(o0)
            if reg0_full is not None:
                self.defs |= 1 << reg0_full
            elif reg0_any is not None:
                self.uses |= 1 << reg0_any     # 8/16-bit write: upper bits survive
            self.pure = reg0_full is not None and rid not in NEVER_PURE
            if rid == xrkdsm.OP_LEA:
                self.pure = True               # address arithmetic only
                self.mem = False
        elif rid in RMW:
            self.uses |= (_operand_regs(o0) | _operand_regs(o1)
                          | _operand_regs(o2))
            if any(op.ID and op.TID() == xrkdsm.TID_MEM for op in rk.operand):
                self.mem = True
            if reg0_full is not None:
                self.defs |= 1 << reg0_full
            elif reg0_any is not None:
                self.pure = False              # partial RMW: keep, keep producer
            self.pure = (reg0_full is not None and not self.mem
                         and rid not in NEVER_PURE)
            if rid == xrkdsm.OP_XCHG:
                r1 = _regnum(o1)
                if r1 is not None:
                    self.defs |= 1 << r1
        elif rid in FLAG_ONLY:
            self.uses |= _operand_regs(o0) | _operand_regs(o1)
            if any(op.ID and op.TID() == xrkdsm.TID_MEM for op in rk.operand):
                self.mem = True
            self.pure = not self.mem
        else:
            # unknown / side-effecting instruction: read every operand, keep it,
            # and never claim a definition (so no producer can be dropped)
            self.uses |= (_operand_regs(o0) | _operand_regs(o1)
                          | _operand_regs(o2))
            if any(op.ID and op.TID() == xrkdsm.TID_MEM for op in rk.operand):
                self.mem = True
            self.pure = False

        if rid in FLAGS_WRITE_FULL:
            self.defs |= FLAGS
        if rid in FLAGS_READ or rid in FLAGS_BARRIER:
            self.uses |= FLAGS
        if rid in NEVER_PURE:
            self.pure = False


def _regnum(op, full_only=True):
    """Parent register index 0..7 of a TID_REG operand, or None.

    full_only=True returns None for 8/16-bit halves (AL/AX/...): those do not
    define the whole register, so they must not act as a full definition.
    8-bit codes 4..7 are AH/CH/DH/BH, i.e. the *high half* of EAX..EBX.
    """
    if op.ID == 0 or op.TID() != xrkdsm.TID_REG:
        return None
    b = op.GetB(0)
    if full_only and (b & 0xF) != SIZE32:
        return None
    r = b >> 4
    if (b & 0xF) == 1 and r >= 4:
        r -= 4
    return r


def _operand_regs(op):
    """Bitmask of registers read by one operand (itself + memory base/index)."""
    if op.ID == 0:
        return 0
    m = 0
    tid = op.TID()
    if tid == xrkdsm.TID_REG:
        b = op.GetB(0)
        r = b >> 4
        if (b & 0xF) == 1 and r >= 4:   # AH/CH/DH/BH live in EAX/ECX/EDX/EBX
            r -= 4
        m |= 1 << r
    elif tid == xrkdsm.TID_MEM:
        if op.GetB(1):
            m |= 1 << (op.GetB(1) >> 4)
        if op.GetB(2):
            m |= 1 << (op.GetB(2) >> 4)
    return m



# ------------------------------------------------------------------ scanning --
_NULL = io.StringIO()


def scan(data, limit=0):
    """Decode every offset the sweep can start at. Returns (insns, addr->idx, bad)."""
    ins = []
    by_addr = {}
    off = 0
    end = len(data) if not limit else min(len(data), limit)
    bad = 0
    dec = xrkdsm.XrkDecode
    while off < end:
        with contextlib.redirect_stdout(_NULL):
            size, rk = dec(data[off:off + 16] + b"\0" * 32)
        if not size or size > 15:
            bad += 1               # invalid byte: resynchronise, like decode_range
            off += 1
            continue
        by_addr[off] = len(ins)
        ins.append(Ins(off, size, rk))
        off += size
    return ins, by_addr, bad


# --------------------------------------------------------------- control flow --
def edges(ins, by_addr):
    """Per-instruction successors + 'unknown edge' flags (desync/indirect)."""
    n = len(ins)
    succ = [()] * n
    unknown = bytearray(n)
    for i in range(n):
        x = ins[i]
        nxt = i + 1
        nxt_ok = nxt < n and ins[nxt].addr == x.addr + x.size
        if x.rk.ID in BARRIER:
            # caller/callee/handler may read anything: mark the edge unknown so
            # liveness never assumes a register is dead across it
            unknown[i] = 1
        if x.kind == "ret":
            continue
        if x.kind == "jmp":
            t = by_addr.get(x.target) if x.target is not None else None
            if t is None:
                unknown[i] = 1
            else:
                succ[i] = (t,)
            continue
        if x.kind == "jcc":
            out = []
            if nxt_ok:
                out.append(nxt)
            else:
                unknown[i] = 1
            t = by_addr.get(x.target) if x.target is not None else None
            if t is None:
                unknown[i] = 1
            else:
                out.append(t)
            succ[i] = tuple(out)
            continue
        if x.kind == "call":
            out = []
            if nxt_ok:
                out.append(nxt)
            else:
                unknown[i] = 1
            if x.target is not None:
                t = by_addr.get(x.target)
                if t is not None:
                    out.append(t)
            succ[i] = tuple(out)
            continue
        if nxt_ok:
            succ[i] = (nxt,)
        else:
            unknown[i] = 1
    return succ, unknown


def predecessors(succ):
    pred = [[] for _ in succ]
    for i, ss in enumerate(succ):
        for s in ss:
            pred[s].append(i)
    return pred


def liveness(ins, succ, pred, unknown):
    """Backward bitmask fixpoint: live_in / live_out per instruction."""
    n = len(ins)
    live_in = [0] * n
    live_out = [0] * n
    in_q = bytearray(b"\x01") * n
    wl = collections.deque(range(n - 1, -1, -1))
    while wl:
        i = wl.popleft()
        in_q[i] = 0
        lo = 0
        for s in succ[i]:
            lo |= live_in[s]
        if unknown[i]:
            lo = ALL_REGS          # unknown edge: nothing may be assumed dead
        x = ins[i]
        li = x.uses | (lo & ~x.defs)
        if li != live_in[i] or lo != live_out[i]:
            live_in[i] = li
            live_out[i] = lo
            for p in pred[i]:
                if not in_q[p]:
                    in_q[p] = 1
                    wl.append(p)
    return live_in, live_out


# ------------------------------------------------------------------------ dce --
def run_dce(ins, rounds=8, unknown_is_live=True):
    """Liveness + dead-definition removal, iterated to a fixpoint."""
    cur = ins
    removed = set()
    by_mnem = collections.Counter()
    per_round = []
    for _ in range(rounds):
        by = {x.addr: i for i, x in enumerate(cur)}
        succ, unknown = edges(cur, by)
        if not unknown_is_live:
            unknown = bytearray(len(cur))
        pred = predecessors(succ)
        _li, live_out = liveness(cur, succ, pred, unknown)
        drop = [i for i, x in enumerate(cur)
                if x.pure and x.defs and not (x.defs & live_out[i])]
        if not drop:
            break
        ds = set(drop)
        for i in drop:
            removed.add(cur[i].addr)
            by_mnem[cur[i].mnem] += 1
        cur = [x for i, x in enumerate(cur) if i not in ds]
        per_round.append(len(drop))
        if len(cur) < 2:
            break
    return cur, dict(removed=len(removed), addrs=removed, per_round=per_round,
                     by_mnem=by_mnem)


# ------------------------------------------------------------------- listing --
def blocks(ins):
    """Split an instruction list into basic blocks (targets + terminators)."""
    if not ins:
        return []
    targets = set(x.target for x in ins if x.target is not None)
    out = []
    cur = []
    for x in ins:
        if cur:
            p = cur[-1]
            if (x.addr != p.addr + p.size or x.addr in targets
                    or p.kind in ("jmp", "jcc", "ret")):
                out.append(cur)
                cur = []
        cur.append(x)
    if cur:
        out.append(cur)
    return out


def render(ins, removed, rva, header=()):
    """Listing lines: survivors, with optional `; -` lines for what was cut."""
    lines = list(header)
    if not removed:
        for b in blocks(ins):
            lines.append("")
            lines.append("; ---- block +%X  (%d instrs)"
                         % (b[0].addr, len(b)))
            for x in b:
                lines.append("%08X  %s" % ((rva + x.addr) & 0xFFFFFFFF, x.text))
        return lines

    for b in blocks(ins):
        lines.append("")
        lines.append("; ---- block +%X  (%d instrs)"
                     % (b[0].addr, len(b)))
        for x in b:
            lines.append("%08X  %s" % ((rva + x.addr) & 0xFFFFFFFF, x.text))
    lines.append("")
    lines.append("; ---- removed instructions (dead, %d)" % len(removed))
    for a in sorted(removed):
        lines.append("%08X  ; dead" % ((rva + a) & 0xFFFFFFFF))
    return lines


def run(data, rva=0, limit=0, rounds=8, verify_trials=0, verbose=False):
    """scan -> cfg -> dce (+ optional differential verify)."""
    t0 = time.time()
    ins, by_addr, bad = scan(data, limit)
    t_scan = time.time() - t0
    if not ins:
        return dict(kept=[], removed=set(),
                    stats=dict(instructions=0, blocks=0, removed=0,
                               removed_pct=0.0, unknown_edges=0, rounds=[],
                               invalid_bytes=bad, seconds=round(t_scan, 1)))
    _succ, unknown = edges(ins, by_addr)
    nb = len(blocks(ins))
    t1 = time.time()
    kept, st = run_dce(ins, rounds=rounds)
    t_dce = time.time() - t1
    n = len(ins)
    top = sorted(st["by_mnem"].items(), key=lambda kv: -kv[1])[:10]
    stats = dict(instructions=n, blocks=nb, removed=st["removed"],
                 removed_pct=round(st["removed"] * 100.0 / n, 2),
                 unknown_edges=int(sum(unknown)), rounds=st["per_round"],
                 by_mnem=[dict(mnemonic=k, count=v) for k, v in top],
                 invalid_bytes=bad,
                 scan_seconds=round(t_scan, 1), dce_seconds=round(t_dce, 1))
    vres = None
    if verify_trials:
        t2 = time.time()
        vres = verify(ins, st["addrs"], trials=verify_trials)
        vres["seconds"] = round(time.time() - t2, 1)
        stats["verify"] = dict(tested=vres["tested"], skipped=vres["skipped"],
                               trials=vres["trials"],
                               failures=vres["failures_total"])
    stats["seconds"] = round(time.time() - t0, 1)
    if verbose:
        print("scan : %d instrs from %X bytes (%d invalid), %d blocks, "
              "%d unknown edges  [%.1fs]"
              % (n, len(data) if not limit else limit, bad, nb,
                 stats["unknown_edges"], t_scan))
        print("dce  : -%d instrs (%.2f%%) in %d rounds %s  [%.1fs]"
              % (st["removed"], stats["removed_pct"], len(st["per_round"]),
                 st["per_round"], t_dce))
        if top:
            print("top  : " + ", ".join("%s %d" % kv for kv in top))
        if vres:
            print("check: %d blocks x %d random states identical, %d skipped, "
                  "%d failures  [%.1fs]"
                  % (vres["tested"], vres["trials"], vres["skipped"],
                     vres["failures_total"], vres["seconds"]))
            for f in vres["failures"]:
                print("   !! block +%X mask %s: %s != %s"
                      % (f["block"], f["mask"], f["full"], f["cut"]))
    return dict(kept=kept, removed=st["addrs"], stats=stats, verify=vres)


def main():
    ap = argparse.ArgumentParser(
        description="CFG + liveness + DCE over an unpacked Oreans payload")
    ap.add_argument("image")
    ap.add_argument("--section", default=None,
                    help="section holding the payload "
                         "(default: first Oreans section present)")
    ap.add_argument("--raw", action="store_true",
                    help="image is a raw payload blob (--rva becomes a base RVA)")
    ap.add_argument("--rva", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--rounds", type=int, default=8,
                    help="max DCE iterations (default 8)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--show-removed", action="store_true",
                    help="also emit the addresses of deleted instructions")
    ap.add_argument("--verify", type=int, default=0, metavar="N",
                    help="differential-test each touched block on N random states")
    a = ap.parse_args()

    if a.raw:
        data = open(a.image, "rb").read()
        rva = a.rva
    else:
        d, _base, secs = oreandec.load_pe(a.image)
        a.section = a.section or oreandec.pick_section(secs)
        if a.section not in secs:
            raise SystemExit("%s: no %s section (have: %s)"
                             % (a.image, a.section, ", ".join(sorted(secs))))
        s = secs[a.section]
        rva = a.rva or s["va"]
        data = d[s["raw"] + (rva - s["va"]):s["raw"] + s["rs"]]
    if a.size:
        data = data[:a.size]
    print("%s  rva %08X  %X bytes" % (a.image, rva, len(data)))

    res = run(data, rva, rounds=a.rounds, verify_trials=a.verify, verbose=True)
    lines = [("; cfgpass - CFG + liveness + dead-code elimination"),
             "; %d instrs in, %d out (-%.2f%%), %d blocks, %d unknown edges"
             % (res["stats"]["instructions"],
                res["stats"]["instructions"] - res["stats"]["removed"],
                res["stats"]["removed_pct"], res["stats"]["blocks"],
                res["stats"]["unknown_edges"]),
             "; addresses are RVAs"]
    if res.get("verify"):
        v = res["verify"]
        lines.insert(3, "; verified: %d blocks x %d random states, %d failures "
                        "(%d skipped)"
                     % (v["tested"], v["trials"], v["failures_total"],
                        v["skipped"]))
    body = render(res["kept"], res["removed"] if a.show_removed else set(),
                  rva, lines)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(body) + "\n")
        print("listing -> %s (%d lines)" % (a.out, len(body)))
    else:
        for l in body[:60]:
            print(l)


# ---------------------------------------------------------------- verifier ----
# Concrete interpreter for the register/flag-only subset, used as a
# *differential oracle*: run a block before and after DCE from the same random
# machine state and require an identical final state.  Blocks that touch memory
# or use an unmodelled mnemonic are skipped (not counted as "passed").
class _Unsupported(Exception):
    pass


class _State(object):
    __slots__ = ("r", "m", "cf", "zf", "sf", "of", "pf")

    def __init__(self, r=None, fl=None, m=None):
        self.r = list(r) if r else [0] * 8
        self.m = dict(m) if m else {}
        if fl:
            self.cf, self.zf, self.sf, self.of, self.pf = fl
        else:
            self.cf = self.zf = self.sf = self.of = self.pf = False

    def copy(self):
        return _State(self.r, (self.cf, self.zf, self.sf, self.of, self.pf),
                      self.m)

    def key(self):
        return (tuple(self.r), self.cf, self.zf, self.sf, self.of, self.pf)


def _mask(sz):
    return {1: 0xFF, 2: 0xFFFF, 3: 0xFFFFFFFF}.get(sz, 0xFFFFFFFF)


def _op_size(op):
    return op.Size() or 3


def _ea(st, op):
    """Effective address.  Uninitialised bytes read as a fixed hash of the
    address, so two runs over the same code see the same 'memory'."""
    base = op.GetB(1) >> 4 if op.GetB(1) else None
    idx = op.GetB(2) >> 4 if op.GetB(2) else None
    a = op.val2 & 0xFFFFFFFF
    if base is not None:
        a += st.r[base]
    if idx is not None:
        a += st.r[idx] * (op.GetB(3) or 1)
    return a & 0xFFFFFFFF


def _mem_get(st, addr, sz):
    out = 0
    for i in range(sz):
        a = (addr + i) & 0xFFFFFFFF
        out |= st.m[a] << (8 * i) if a in st.m else \
            (((a * 2654435761) >> 7) & 0xFF) << (8 * i)
    return out & _mask({1: 1, 2: 2, 4: 4}[sz])


def _mem_put(st, addr, sz, val):
    for i in range(sz):
        st.m[(addr + i) & 0xFFFFFFFF] = (val >> (8 * i)) & 0xFF


def _rd(st, op):
    tid = op.TID()
    if tid == xrkdsm.TID_VAL:
        return op.value & 0xFFFFFFFF
    sz = _op_size(op)
    if tid == xrkdsm.TID_MEM:
        return _mem_get(st, _ea(st, op), {1: 1, 2: 2, 3: 4}[sz])
    reg = op.GetB(0) >> 4
    if sz == 1:
        return (st.r[reg - 4] >> 8) & 0xFF if reg >= 4 else st.r[reg] & 0xFF
    if sz == 2:
        return st.r[reg] & 0xFFFF
    return st.r[reg] & 0xFFFFFFFF


def _wr(st, op, val):
    tid = op.TID()
    sz = _op_size(op)
    reg = op.GetB(0) >> 4
    val &= _mask(sz)
    if tid == xrkdsm.TID_MEM:
        _mem_put(st, _ea(st, op), {1: 1, 2: 2, 3: 4}[sz], val)
        return
    if sz == 1:
        if reg >= 4:
            i = reg - 4
            st.r[i] = (st.r[i] & 0xFFFF00FF) | (val << 8)
        else:
            st.r[reg] = (st.r[reg] & 0xFFFFFF00) | val
    elif sz == 2:
        st.r[reg] = (st.r[reg] & 0xFFFF0000) | val
    else:
        st.r[reg] = val


def _flags(st, res, sz, cf=None, of=None):
    """Set ZF/SF/PF (and CF/OF when given) from a `sz`-sized result."""
    res &= _mask(sz)
    bits = sz * 8
    st.zf = res == 0
    st.sf = bool(res & (1 << (bits - 1)))
    st.pf = bin(res & 0xFF).count("1") % 2 == 0
    if cf is not None:
        st.cf = bool(cf)
    if of is not None:
        st.of = bool(of)
    return res


def _jcc_taken(rid, st):
    O = xrkdsm
    if rid == O.OP_JA:
        return not st.cf and not st.zf
    if rid == O.OP_JNB:
        return not st.cf
    if rid == O.OP_JB:
        return st.cf
    if rid == O.OP_JBE:
        return st.cf or st.zf
    if rid == O.OP_JE:
        return st.zf
    if rid == O.OP_JNZ:
        return not st.zf
    if rid == O.OP_JG:
        return not st.zf and st.sf == st.of
    if rid == O.OP_JGE:
        return st.sf == st.of
    if rid == O.OP_JL:
        return st.sf != st.of
    if rid == O.OP_JLE:
        return st.zf or st.sf != st.of
    if rid == O.OP_JO:
        return st.of
    if rid == O.OP_JNO:
        return not st.of
    if rid == O.OP_JS:
        return st.sf
    if rid == O.OP_JNS:
        return not st.sf
    if rid == O.OP_JP:
        return st.pf
    if rid == O.OP_JNP:
        return not st.pf
    raise _Unsupported("jcc %04X" % rid)


def _step(st, x):
    """Execute one instruction on `st`; True when it ends the block."""
    rk = x.rk
    rid = rk.ID
    O = xrkdsm
    o0, o1 = rk.operand[0], rk.operand[1]
    if o0.TID() == O.TID_REG:
        sz = _op_size(o0)
    elif o1.TID() == O.TID_REG:
        sz = _op_size(o1)
    else:
        sz = _op_size(o0)

    if rid == O.OP_MOV:
        _wr(st, o0, _rd(st, o1))
    elif rid in (O.OP_MOVZX, O.OP_MOVSX):
        v = _rd(st, o1)
        ssz = _op_size(o1) if o1.TID() != O.TID_VAL else sz
        if rid == O.OP_MOVSX and v & (1 << (ssz * 8 - 1)):
            v |= (0xFFFFFFFF ^ _mask(ssz))
        _wr(st, o0, v)
    elif rid == O.OP_LEA:
        if o1.TID() != O.TID_MEM:
            raise _Unsupported("lea")
        _wr(st, o0, _ea(st, o1))
    elif rid in (O.OP_ADD, O.OP_ADC, O.OP_SUB, O.OP_SBB, O.OP_AND,
                 O.OP_OR, O.OP_XOR):
        a = _rd(st, o0)
        b = _rd(st, o1)
        cy = 1 if st.cf else 0
        if rid in (O.OP_ADD, O.OP_ADC):
            b += cy if rid == O.OP_ADC else 0
            raw = a + b
            cf = raw >> (sz * 8)
            of = ((a ^ raw) & (b ^ raw)) >> (sz * 8 - 1) & 1
        elif rid in (O.OP_SUB, O.OP_SBB):
            b += cy if rid == O.OP_SBB else 0
            raw = a - b
            cf = (raw >> (sz * 8)) & 1
            of = ((a ^ b) & (a ^ raw)) >> (sz * 8 - 1) & 1
        else:
            raw = (a & b) if rid == O.OP_AND else (a | b) if rid == O.OP_OR else (a ^ b)
            cf = 0
            of = 0
        res = _flags(st, raw, sz, cf, of)
        _wr(st, o0, res)
    elif rid in (O.OP_INC, O.OP_DEC, O.OP_NEG, O.OP_NOT):
        a = _rd(st, o0)
        if rid == O.OP_NOT:
            _wr(st, o0, (~a) & _mask(sz))
        else:
            if rid == O.OP_INC:
                raw = a + 1
                of = (a & _mask(sz)) == _mask(sz) >> 1
            elif rid == O.OP_DEC:
                raw = a - 1
                of = (a & _mask(sz)) == (1 << (sz * 8 - 1))
            else:
                raw = 0 - a
                of = (a & _mask(sz)) == (1 << (sz * 8 - 1))
            res = _flags(st, raw, sz, None, of)
            _wr(st, o0, res)
    elif rid in (O.OP_SHL, O.OP_SHR, O.OP_SAR):
        a = _rd(st, o0) & _mask(sz)
        n = _rd(st, o1) & 0x1F
        bits = sz * 8
        if rid == O.OP_SHL:
            raw = a << n
            cf = ((a >> (bits - n)) & 1) if 0 < n <= bits else (0 if n else st.cf)
        elif rid == O.OP_SHR:
            raw = a >> n
            cf = ((a >> (n - 1)) & 1) if 0 < n <= bits else (0 if n else st.cf)
        else:
            sa = a - (1 << bits) if a & (1 << (bits - 1)) else a
            raw = sa >> n
            cf = ((sa >> (n - 1)) & 1) if 0 < n <= bits else (0 if n else st.cf)
        res = _flags(st, raw, sz, cf, False)
        _wr(st, o0, res)
    elif rid in (O.OP_CMP, O.OP_TEST):
        a = _rd(st, o0)
        b = _rd(st, o1)
        if rid == O.OP_TEST:
            raw = a & b
            cf, of = 0, 0
        else:
            raw = a - b
            cf = (raw >> (sz * 8)) & 1
            of = ((a ^ b) & (a ^ raw)) >> (sz * 8 - 1) & 1
        _flags(st, raw, sz, cf, of)
    elif rid == O.OP_XCHG:
        if o1.TID() != O.TID_REG:
            raise _Unsupported("xchg")
        a, b = _rd(st, o0), _rd(st, o1)
        _wr(st, o0, b)
        _wr(st, o1, a)
    elif rid == O.OP_JMP or rid in COND_JMP_IDS:
        if rid in COND_JMP_IDS:
            _jcc_taken(rid, st)
        return True
    elif rid == O.OP_NOP:
        pass
    else:
        raise _Unsupported("%s" % x.mnem)
    return False


def _exec_block(block, st):
    for x in block:
        if _step(st, x):
            break
    return st


def _random_state(rnd):
    return _State([rnd.getrandbits(32) for _ in range(8)],
                  [bool(rnd.getrandbits(1)) for _ in range(5)])


def verify(ins, removed, trials=64, seed=0x1234):
    """Differential oracle: run each block before/after DCE on random states.

    Only state that is *live out of the block* is compared (a deleted write to a
    dead register is exactly what DCE is supposed to do); when the block ends on
    an unknown edge every register and the flags are compared.  Blocks touching
    memory (or any mnemonic the interpreter does not model) are counted as
    skipped, never as passed.
    """
    import random
    rnd = random.Random(seed)
    by = {x.addr: i for i, x in enumerate(ins)}
    succ, unknown = edges(ins, by)
    pred = predecessors(succ)
    _li, live_out = liveness(ins, succ, pred, unknown)
    tested = skipped = 0
    fails = []
    for b in blocks(ins):
        kept = [x for x in b if x.addr not in removed]
        if not kept or len(kept) == len(b):
            continue                    # nothing was deleted here
        try:
            _exec_block(b, _random_state(rnd))
        except _Unsupported:
            skipped += 1
            continue
        mask = live_out[by[b[-1].addr]]
        ok = True
        for _ in range(trials):
            st0 = _random_state(rnd)
            try:
                full = _exec_block(b, st0.copy())
                cut = _exec_block(kept, st0.copy())
            except _Unsupported:
                ok = False
                skipped += 1
                break
            if _obs(full, mask) != _obs(cut, mask):
                ok = False
                fails.append(dict(block=b[0].addr, instrs=len(b),
                                  mask="%03X" % mask,
                                  full=_obs(full, mask),
                                  cut=_obs(cut, mask)))
                break
        if ok:
            tested += 1
    return dict(tested=tested, skipped=skipped, trials=trials,
                failures=fails[:5], failures_total=len(fails))


def _obs(st, mask):
    """Register/flag/memory state filtered to the live-out mask."""
    regs = tuple(st.r[i] for i in range(8) if mask & (1 << i))
    flg = (st.cf, st.zf, st.sf, st.of, st.pf) if mask & FLAGS else ()
    return (regs, flg, tuple(sorted(st.m.items())))


if __name__ == "__main__":
    main()
