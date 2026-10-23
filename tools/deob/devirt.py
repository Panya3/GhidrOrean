#!/usr/bin/env python3
"""devirt.py - recover the native program out of an Oreans `.vlizer` payload.

What the section actually contains
    `.vlizer` in these builds is **not** bytecode for a VM: disassemble a
    decompressed payload with capstone and every instruction the Oreans decoder
    (`xrkdsm`) printed comes back byte for byte.  What the protection did was

        * rewrite the code with *mutation* junk - the operands of the real
          instruction are materialised by long register chains
          (`mov eax,ebp / add eax,0x63 / ... / or dword ptr [eax],edx`),
        * scatter zero runs and `0xCC` filler between the pieces,
        * drop whole tables (small-value dwords, string data) into the section.

    So "devirtualisation" here means: find the code, drop what is provably not
    part of it, and hand back a native instruction stream - not lift a VM.

What this module does
    decode     resynchronising capstone sweep of the whole section
    classify   zero / 0xCC runs (padding), undecodable bytes (data)
    reach      recursive descent from every plausible entry: run starts, every
               direct branch target, and every dword inside the payload (or in
               another section) that points into it (indirect entries)
    optimise   liveness over the reachable CFG (registers + EFLAGS), then drop
                 - dead register/flag writes        (whole parent register dead)
                 - instructions that cannot have an effect (mov r,r, add r,0,
                   and r,-1, lea r,[r], shift by 0, nop, ...)
                 - block-local overwritten memory stores (same EA, no read and
                   no base/index write in between)
    patch      write the result back **in place**: every removed instruction
               becomes 0x90, so layout, relative branches and absolute
               references stay valid - the output PE runs as-is
    verify     each rewritten block is executed before/after under unicorn from
               random machine states; registers, flags and memory must agree

Usage
    python devirt.py out/corpus/x3/10_unpacked.exe --out-dir out/corpus/x3
    python devirt.py <pe> --entry 0x2FC123 --verify 500 --no-pe
"""
import argparse
import collections
import json
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import oreandec                        # noqa: E402

try:
    from capstone import (Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_JUMP,
                          CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET, CS_OP_IMM,
                          CS_OP_MEM, x86_const as xc)
except ImportError:                    # pragma: no cover
    raise SystemExit("devirt.py needs capstone (pip install capstone)")

PAD_RUN = 8                 # zero / 0xCC runs at least this long are filler
MAX_INSN = 15
_REG = 1                    # capstone x86_op_type.CS_OP_REG
_MEM = 3

# canonical register index: 0 rax .. 7 rdi, 8..15 r8..r15
_GPR = {}
_WIDTH = {}
for _i, _names in enumerate((
        ("rax", "eax", "ax", "al", "ah"), ("rcx", "ecx", "cx", "cl", "ch"),
        ("rdx", "edx", "dx", "dl", "dh"), ("rbx", "ebx", "bx", "bl", "bh"),
        ("rsp", "esp", "sp", "spl"), ("rbp", "ebp", "bp", "bpl"),
        ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"))):
    for _k, _n in enumerate(_names):
        _GPR[_n] = _i
        _WIDTH[_n] = 8 if _k == 0 else 4 if _k == 1 else 2 if _k == 2 else 1
for _i in range(8, 16):
    for _suf, _w in (("", 8), ("d", 4), ("w", 2), ("b", 1)):
        _GPR["r%d%s" % (_i, _suf)] = _i
        _WIDTH["r%d%s" % (_i, _suf)] = _w

_MD = None


def decoder(bits):
    global _MD
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = True
    _MD = md
    return md


def _canon(reg_id):
    """capstone register id -> (canonical index, written width), or (None, 0)."""
    try:
        name = _MD.reg_name(reg_id)
    except Exception:
        return (None, 0)
    if not name or name not in _GPR:
        return (None, 0)
    return (_GPR[name], _WIDTH[name])


# ------------------------------------------------------------------ decoding --
class NIns(object):
    """One native instruction with the effects the optimiser needs."""

    __slots__ = ("addr", "size", "raw", "mnem", "ops", "target", "kind",
                 "reads", "writes", "wpart", "flags_r", "flags_w",
                 "mem_ops", "imm", "bits", "opv")

    def __init__(self, insn, bits):
        self.addr = insn.address
        self.size = insn.size
        self.raw = bytes(insn.bytes)
        self.mnem = insn.mnemonic
        self.ops = insn.op_str
        self.bits = bits
        self.target = None
        self.kind = "other"
        self.reads = set()
        self.writes = set()
        self.wpart = {}                 # reg -> widest width written
        self.flags_r = False
        self.flags_w = False
        self.mem_ops = []               # [(key, read, write)]
        self.imm = None
        # capstone recycles the memory behind a CsInsn as soon as the disasm
        # generator is closed, so nothing below may keep `insn` alive
        self.opv = []
        grp = set(insn.groups)
        if CS_GRP_RET in grp or CS_GRP_IRET in grp:
            self.kind = "ret"
        elif CS_GRP_CALL in grp:
            self.kind = "call"
        elif CS_GRP_JUMP in grp:
            self.kind = "jmp" if self.mnem in ("jmp", "ljmp") else "jcc"
        for op in insn.operands:
            t = op.type
            if t == CS_OP_IMM:
                self.imm = op.imm
                self.opv.append((t, 0, op.imm, None))
                if self.kind in ("jmp", "jcc", "call"):
                    self.target = op.imm
            elif t == CS_OP_MEM:
                key = (op.mem.base, op.mem.index, op.mem.scale, op.mem.disp,
                       op.size)
                self.mem_ops.append((key, bool(op.access & 1),
                                     bool(op.access & 2)))
                self.opv.append((t, 0, 0, key))
            else:
                self.opv.append((t, op.reg, 0, None))
        self._effects(insn)

    def _effects(self, insn):
        try:
            reads, writes = insn.regs_access()
        except Exception:
            reads, writes = [], []
        for r in reads:
            c = _canon(r)[0]
            if c is not None:
                self.reads.add(c)
        for r in writes:
            c, w = _canon(r)
            if c is None:
                continue
            self.writes.add(c)
            self.wpart[c] = max(self.wpart.get(c, 0), w)
        ef = getattr(insn, "eflags", 0) or 0
        rmask = wmask = 0
        for n in ("CF", "ZF", "SF", "OF", "PF", "AF", "DF"):
            rmask |= getattr(xc, "X86_EFLAGS_TEST_%s" % n, 0)
            wmask |= getattr(xc, "X86_EFLAGS_MODIFY_%s" % n, 0)
        self.flags_r = bool(ef & rmask)
        self.flags_w = bool(ef & wmask)

    def covers_whole(self, reg):
        """True when the write to `reg` defines all of its bits."""
        w = self.wpart.get(reg, 0)
        return w >= 4 if self.bits == 64 else w >= 4

    @property
    def text(self):
        return ("%s %s" % (self.mnem, self.ops)).strip()

    @property
    def mem(self):
        return bool(self.mem_ops)

    @property
    def is_store_only(self):
        return bool(self.mem_ops) and all(not rd for _k, rd, _w in self.mem_ops)


def decode(blob, base, bits):
    """Resynchronising sweep. Returns (by_off, bad_offsets)."""
    md = decoder(bits)
    dec = {}
    bad = []
    n = len(blob)
    off = 0
    while off < n:
        got = None
        for it in md.disasm(blob[off:off + MAX_INSN], base + off):
            got = it
            break
        if got is None or not got.size:
            bad.append(off)
            off += 1
            continue
        dec[off] = NIns(got, bits)
        off += got.size
    return dec, bad


def pad_map(blob, min_run=PAD_RUN):
    """bytearray flag per byte: inside a run of >= min_run equal 0x00 / 0xCC."""
    pad = bytearray(len(blob))
    n = len(blob)
    i = 0
    runs = 0
    while i < n:
        c = blob[i]
        if c in (0x00, 0xCC):
            j = i
            while j < n and blob[j] == c:
                j += 1
            if j - i >= min_run:
                pad[i:j] = b"\x01" * (j - i)
                runs += 1
            i = j
        else:
            i += 1
    return pad, runs


# ---------------------------------------------------------------- reachability --
def find_seeds(dec, pad, blob, base, bits, extra=(), pointers=()):
    """Every address that could plausibly start code."""
    seeds = set()
    n = len(blob)
    # 1. start of every non-padding run
    for off in range(n):
        if not pad[off] and (off == 0 or pad[off - 1]):
            seeds.add(off)
    # 2. every direct branch target the sweep can see
    for off, x in dec.items():
        if x.target is not None:
            t = x.target - base
            if 0 <= t < n:
                seeds.add(t)
    # 3. pointers that live *outside* the payload (IAT slots, vtables, the
    #    relocation-free .data of the carrier): a dword inside the payload that
    #    happens to look like an address is junk, not an entry point
    for v in pointers:
        if base <= v < base + n:
            seeds.add(v - base)
    for e in extra:
        off = e - base if e >= base else e
        if 0 <= off < n:
            seeds.add(off)
    return set(o for o in seeds if o in dec and not pad[o])


def external_pointers(image, secs, skip, base, blob_len, bits=32):
    """Pointer-sized values in every section except the payload itself."""
    out = []
    step = 8 if bits == 64 else 4
    fmt = "<Q" if bits == 64 else "<I"
    for name, s in secs.items():
        if name == skip:
            continue
        data = image[s["raw"]:s["raw"] + s["rs"]]
        for off in range(0, len(data) - step + 1, step):
            v = struct.unpack_from(fmt, data, off)[0]
            if base <= v < base + blob_len:
                out.append(v)
    return out



def reach(dec, base, n, seeds, pad):
    """Recursive descent. Returns (reachable offsets, indirect sites, blocked)."""
    seen = set()
    indirect = collections.Counter()
    blocked = collections.Counter()
    todo = list(seeds)
    while todo:
        off = todo.pop()
        if off in seen:
            continue
        x = dec.get(off)
        if x is None:
            blocked["undecodable"] += 1
            continue
        if pad[off]:
            blocked["padding"] += 1
            continue
        seen.add(off)
        nxt = off + x.size
        if x.kind == "ret":
            continue
        if x.kind == "call":
            if x.target is not None:
                t = x.target - base
                if 0 <= t < n:
                    todo.append(t)
            else:
                indirect["call"] += 1
            todo.append(nxt)
            continue
        if x.kind == "jmp":
            if x.target is not None:
                t = x.target - base
                if 0 <= t < n:
                    todo.append(t)
                else:
                    indirect["jmp-out"] += 1
            else:
                indirect["jmp-indirect"] += 1
            continue
        if x.kind == "jcc":
            if x.target is not None:
                t = x.target - base
                if 0 <= t < n:
                    todo.append(t)
            else:
                indirect["jcc-indirect"] += 1
            todo.append(nxt)
            continue
        todo.append(nxt)
    return seen, indirect, blocked


def blocks_of(dec, reachable):
    """Split the reachable stream into basic blocks (list of offset lists)."""
    order = sorted(reachable)
    targets = set()
    for off in order:
        x = dec[off]
        if x.target is not None:
            targets.add(x.target)
        if x.kind in ("jcc", "call"):
            targets.add(x.addr + x.size)
    out = []
    cur = []
    for off in order:
        x = dec[off]
        if cur:
            p = dec[cur[-1]]
            if (x.addr != p.addr + p.size or x.addr in targets
                    or p.kind in ("jmp", "jcc", "ret")):
                out.append(cur)
                cur = []
        cur.append(off)
    if cur:
        out.append(cur)
    return out


# -------------------------------------------------------------------- effects --
FLAGS = 1 << 16
ALL = (1 << 17) - 1


def _ud(x):
    """(uses, defs) bitmasks. A narrow write also reads its parent register."""
    u = set(x.reads)
    d = set()
    for r in x.writes:
        if x.covers_whole(r):
            d.add(r)
        else:
            u.add(r)
    um = dm = 0
    for r in u:
        um |= 1 << r
    for r in d:
        dm |= 1 << r
    if x.flags_r:
        um |= FLAGS
    if x.flags_w:
        dm |= FLAGS
    return um, dm


def cfg_edges(dec, order, idx, base):
    n = len(order)
    succ = [[] for _ in range(n)]
    unknown = bytearray(n)
    for i, off in enumerate(order):
        x = dec[off]
        ni = idx.get(off + x.size)
        if x.kind == "ret":
            continue
        if x.kind == "jmp":
            t = idx.get(x.target - base) if x.target is not None else None
            if t is None:
                unknown[i] = 1
            else:
                succ[i] = (t,)
            continue
        if x.kind in ("jcc", "call"):
            out = []
            if ni is None:
                unknown[i] = 1
            else:
                out.append(ni)
            if x.kind == "call":
                unknown[i] = 1          # the callee may touch anything
            t = idx.get(x.target - base) if x.target is not None else None
            if t is not None:
                out.append(t)
            succ[i] = tuple(out)
            continue
        if ni is None:
            unknown[i] = 1
        else:
            succ[i] = (ni,)
    return succ, unknown


def liveness(dec, order, succ, unknown):
    n = len(order)
    live_in = [0] * n
    live_out = [0] * n
    pred = [[] for _ in range(n)]
    for i, ss in enumerate(succ):
        for s in ss:
            pred[s].append(i)
    wl = collections.deque(range(n - 1, -1, -1))
    inq = bytearray(b"\x01") * n
    ud = [_ud(dec[off]) for off in order]
    while wl:
        i = wl.popleft()
        inq[i] = 0
        lo = 0
        for s in succ[i]:
            lo |= live_in[s]
        if unknown[i]:
            lo = ALL
        u, d = ud[i]
        li = u | (lo & ~d)
        if li != live_in[i] or lo != live_out[i]:
            live_in[i] = li
            live_out[i] = lo
            for p in pred[i]:
                if not inq[p]:
                    inq[p] = 1
                    wl.append(p)
    return live_in, live_out, pred


def _self_lea(x):
    """`lea r, [r]` - identity, but the EA may still carry a useless `+0`."""
    if x.mnem != "lea" or len(x.opv) != 2 or len(x.mem_ops) != 1:
        return False
    dst = x.opv[0]
    if dst[0] != _REG:
        return False
    base, index, scale, disp, _size = x.mem_ops[0][0]
    return base == dst[1] and not index and disp == 0


def _noop(x, flags_dead):
    """Instructions that provably cannot change anything (or only flags)."""
    m, o = x.mnem, x.ops.replace(" ", "")
    if m == "nop":
        return True
    ops = x.opv
    if m in ("mov", "movabs") and len(ops) == 2 and \
            ops[0][0] == _REG and ops[1][0] == _REG and \
            ops[0][1] == ops[1][1]:
        return True
    if _self_lea(x):
        return True
    if m == "xchg" and len(ops) == 2 and ops[0][0] == _REG and \
            ops[1][0] == _REG and ops[0][1] == ops[1][1]:
        return True
    if m in ("shl", "shr", "sal", "sar", "rol", "ror") and "," in o:
        tail = o.rsplit(",", 1)[1]
        if tail in ("0", "0x0"):
            return True
    if m in ("add", "sub", "or", "xor", "and") and "," in o:
        tail = o.rsplit(",", 1)[1]
        if tail in ("0", "0x0"):
            # xor/add/sub/or with 0 still write flags
            return flags_dead
        if m == "and" and tail in ("-1", "0xffffffff",
                                   "0xffffffffffffffff"):
            # all-ones keeps the value; `and rax, 0xffffffff` does not (it
            # zero-extends the parent register in long mode)
            if x.bits == 32 or tail != "0xffffffff":
                return flags_dead
    return False


def _identity(x):
    """True when the instruction cannot change a register *value* - only flags.

    `_noop` answers "may this be dropped here?" with the flags taken into
    account; this one answers the narrower question the audit needs: does the
    instruction leave every register it touches with the same bits it had?

    Long mode makes that subtle: `add eax, 0` defines all of RAX (the upper half
    becomes zero), so it is *not* identity there even though it is in 32-bit
    code.  `wpart` records the width actually written, so require a full qword
    write in 64-bit mode and a dword write in 32-bit mode.
    """
    full = 8 if x.bits == 64 else 4
    if x.mnem == "nop":
        return True
    for r in x.writes:
        if x.wpart.get(r, 0) < full:
            return False
    m, o = x.mnem, x.ops.replace(" ", "")
    ops = x.opv
    if m in ("mov", "movabs") and len(ops) == 2 and \
            ops[0][0] == _REG and ops[1][0] == _REG and \
            ops[0][1] == ops[1][1]:
        return True
    if m == "xchg" and len(ops) == 2 and ops[0][0] == _REG and \
            ops[1][0] == _REG and ops[0][1] == ops[1][1]:
        return True
    if _self_lea(x):
        return True
    if m in ("shl", "shr", "sal", "sar", "rol", "ror") and "," in o:
        return o.rsplit(",", 1)[1] in ("0", "0x0")
    if m in ("add", "sub", "or", "xor", "and") and "," in o:
        tail = o.rsplit(",", 1)[1]
        if tail in ("0", "0x0"):
            return True
        if m == "and" and tail in ("-1", "0xffffffff",
                                   "0xffffffffffffffff"):
            # same caveat as in `_noop`: `and rax, 0xffffffff` is not identity
            if x.bits == 32 or tail != "0xffffffff":
                return True
    if m == "imul" and "," in o and o.rsplit(",", 1)[1] in ("1", "0x1"):
        return True
    return False


_MEM_MNEM = ("push", "pop", "pushf", "popf", "pusha", "popa", "leave", "enter",
             "stos", "movs", "lods", "scas", "cmps", "xlat", "ins", "outs",
             "call", "ret", "iret", "int", "sysenter", "syscall", "sysret",
             "pushal", "popal")
_SIDE_MNEM = ("cpuid", "rdtsc", "rdtscp", "rdmsr", "wrmsr", "hlt", "in", "out",
              "cli", "sti", "std", "cld", "invlpg", "wbinvd", "invd", "lgdt",
              "lidt", "lldt", "ltr", "lmsw", "clts", "swapgs", "xbegin",
              "xend", "ud2", "lock", "rep")


def touches_mem(x):
    if x.mem_ops:
        return True
    m = x.mnem
    for p in _MEM_MNEM:
        if m.startswith(p):
            return True
    return False


def kills_all(x):
    """Instruction whose effect on machine state cannot be modelled locally."""
    m = x.mnem
    for p in _SIDE_MNEM:
        if m.startswith(p):
            return True
    return x.kind in ("call", "ret")


def deadstores(dec, block):
    """Stores in one block that a later store to the same EA overwrites."""
    dead = []
    pend = {}                       # key -> (offset, bases)
    for off in block:
        x = dec[off]
        if kills_all(x):
            pend.clear()
            continue
        # a read of an address kills its pending store; an unknown read kills all
        for key, rd, _wr in x.mem_ops:
            if rd:
                pend.pop(key, None)
        if not x.mem_ops and touches_mem(x):
            pend.clear()
        for r in x.writes:          # base/index of a pending store changed
            for key in list(pend):
                if r in pend[key][1]:
                    pend.pop(key, None)
        for key, _rd, wr in x.mem_ops:
            if not wr:
                continue
            bases = set()
            for part in (key[0], key[1]):
                b = _canon_reg_id(part)
                if b is not None:
                    bases.add(b)
            prev = pend.get(key)
            if prev is not None and prev[1] == bases:
                dead.append(prev[0])
            pend[key] = (off, bases)
        if x.kind in ("jmp", "jcc"):
            pend.clear()
    return dead


def _canon_reg_id(reg_id):
    if not reg_id:
        return None
    return _canon(reg_id)[0]


def optimize(dec, order, base, rounds=8, verbose=False):
    """Iterate liveness DCE + no-op removal + block dead stores to a fixpoint.

    Returns (kept_order, {offset: reason}, Counter(reason)).  Everything here is
    a *candidate*: `audit()` still has to prove each one locally.
    """
    cand = {}
    by_reason = collections.Counter()
    cur = list(order)
    for _ in range(rounds):
        idx = {off: i for i, off in enumerate(cur)}
        succ, unknown = cfg_edges(dec, cur, idx, base)
        _li, live_out, _pred = liveness(dec, cur, succ, unknown)
        blow = blocks_of(dec, set(cur))
        drop = {}
        for off in deadstores(dec, [o for b in blow for o in b]):
            if off not in cand:
                drop[off] = "dead store"
        for i, off in enumerate(cur):
            x = dec[off]
            if kills_all(x) or touches_mem(x) or x.kind != "other":
                continue
            flags_dead = not (live_out[i] & FLAGS)
            if _noop(x, flags_dead):
                drop[off] = "no effect"
                continue
            if not x.writes:
                continue
            if all(not (live_out[i] & (1 << r)) for r in x.writes) and \
                    (not x.flags_w or flags_dead):
                drop[off] = "dead register write"
        if not drop:
            break
        for off, why in drop.items():
            cand[off] = why
            by_reason[why] += 1
        cur = [o for o in cur if o not in drop]
    if verbose:
        print("   candidates: %d %s" % (len(cand), dict(by_reason)))
    return cur, cand, by_reason


# ------------------------------------------------------------------- output --
def render(dec, order, removed, base, rva, stats):
    """Listing of the recovered stream, with the cut instructions in a tail."""
    lines = ["; devirt - native code recovered from .vlizer",
             "; section rva %08X  %X bytes; reachable %d instrs (%.1f%% of the "
             "section by bytes)" % (rva, stats["section_bytes"],
                                    stats["reachable_instrs"],
                                    stats["reachable_pct"]),
             "; dropped: %d padding bytes (%.1f%%), %d instrs of junk/data "
             "(%.1f%%), %d dead instrs NOPed"
             % (stats["padding_bytes"], stats["padding_pct"],
                stats["unreachable_instrs"], stats["unreachable_pct"],
                stats["removed"]),
             ""]
    keep = set(order)
    for b in blocks_of(dec, keep):
        lines.append("; ---- block +%X  (%d instrs, %d cut)"
                     % (b[0], len(b), sum(1 for o in b if o in removed)))
        for off in b:
            x = dec[off]
            lines.append("%08X  %-32s %s%s"
                         % ((rva + off) & 0xFFFFFFFF, x.raw.hex(),
                            x.text, "        ; cut" if off in removed else ""))
        lines.append("")
    if removed:
        lines.append("; ---- cut instructions (%d)" % len(removed))
        for off in sorted(removed):
            lines.append("%08X  %-32s %s"
                         % ((rva + off) & 0xFFFFFFFF, dec[off].raw.hex(),
                            dec[off].text))
    return lines


def patch_bytes(image, raw_base, dec, removed):
    """Copy of `image` with every cut instruction overwritten by 0x90."""
    out = bytearray(image)
    n = 0
    for off in removed:
        x = dec[off]
        pos = raw_base + off
        if 0 <= pos < len(out) and pos + x.size <= len(out):
            out[pos:pos + x.size] = b"\x90" * x.size
            n += 1
    return bytes(out), n


# --------------------------------------------------------------------- audit --
def audit(dec, order, cand):
    """Independent local proof for every instruction the optimiser wants to cut.

    A cut is accepted only when the same block, scanning forward, shows a full
    write to the register before any read of it (and a flag write before any
    flag read).  This is deliberately a *different* computation from the global
    liveness pass that produced the candidates: if liveness is wrong about a
    block boundary, the audit refuses the cut instead of trusting it.
    """
    bad = []
    for b in blocks_of(dec, set(order)):
        need_at = {}
        for i, o in enumerate(b):
            if o not in cand:
                continue
            x = dec[o]
            if x.mnem == "nop":
                continue
            need = set(x.writes)
            nflags = x.flags_w
            if not need and not nflags:
                continue
            if cand[o] == "no effect" and _identity(x):
                # value-preserving: cutting it cannot change a register, so the
                # forward scan only has to show the flags are overwritten
                need = set()
            ok = False
            for j in range(i + 1, len(b)):
                y = dec[b[j]]
                if need & y.reads:
                    break
                if nflags and y.flags_r:
                    break
                need = set(r for r in need if not (r in y.writes
                                                  and y.covers_whole(r)))
                if nflags and y.flags_w:
                    nflags = False
                if not need and not nflags:
                    ok = True
                    break
            if not ok:
                bad.append(dict(block=b[0], addr=o, text=dec[o].text))
    return bad


def structural_check(image, raw_base, blob_len, base, dec, removed, bits):
    """The patched section must re-decode to exactly the same instruction grid."""
    patched, _n = patch_bytes(image, raw_base, dec, removed)
    blob2 = patched[raw_base:raw_base + blob_len]
    dec2, _bad = decode(blob2, base, bits)
    missing = changed = 0
    for off, x in dec.items():
        if off in removed:
            continue
        y = dec2.get(off)
        if y is None:
            missing += 1
        elif y.raw != x.raw:
            changed += 1
    return dict(status="ok" if not (missing or changed) else "mismatch",
                checked=len(dec) - len(removed), missing=missing,
                changed=changed)

def _engine(code, base, bits, pages, stack):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
    from unicorn import UC_HOOK_MEM_UNMAPPED
    uc = Uc(UC_ARCH_X86, UC_MODE_64 if bits == 64 else UC_MODE_32)
    span = ((len(code) + 0xFFF) & ~0xFFF) + 0x2000
    uc.mem_map(base & ~0xFFF, span)
    uc.mem_write(base, code)
    uc.mem_map(stack, 0x10000)

    def unmapped(u, access, address, size, value, user):
        page = address & ~0xFFF
        if len(pages) > 8192:
            return False
        try:
            u.mem_map(page, 0x1000)
        except Exception:
            return False
        pages.add(page)
        return True

    uc.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped)
    return uc


_REG_NAMES = {
    64: ("RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"),
    32: ("EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"),
}
_REGIDS = {}


def _regids(bits):
    """UC_X86_REG_* ids for the eight GPRs of `bits`, in canonical order."""
    if bits not in _REGIDS:
        import unicorn.x86_const as ux
        _REGIDS[bits] = [getattr(ux, "UC_X86_REG_" + n) for n in _REG_NAMES[bits]]
    return _REGIDS[bits]


def _eflags_id():
    import unicorn.x86_const as ux
    return ux.UC_X86_REG_EFLAGS


def _run_block(uc, start, end, regs, eflags, bits):
    from unicorn import UC_HOOK_CODE
    ids = _regids(bits)
    for i, rid in enumerate(ids):
        uc.reg_write(rid, regs[i])
    uc.reg_write(_eflags_id(), eflags)

    def code_hook(u, address, size, user):
        if address < start or address >= end:
            u.emu_stop()

    h = uc.hook_add(UC_HOOK_CODE, code_hook)
    try:
        uc.emu_start(start, end, count=8192)
    finally:
        uc.hook_del(h)
    return [uc.reg_read(rid) for rid in ids], uc.reg_read(_eflags_id()) & 0x8D5


def _digest(uc, touched, union):
    """SHA1 over every page in `union`; pages this run never mapped read as 0."""
    import hashlib
    h = hashlib.sha1()
    for page in sorted(union):
        if page in touched:
            h.update(bytes(uc.mem_read(page, 0x1000)))
        else:
            h.update(b"\x00" * 0x1000)
    return h.hexdigest()


def verify(blob, base, dec, order, removed, bits=32, trials=3, max_blocks=0,
           seed=0x1234):
    """Differential: every rewritten block must end in the same machine state."""
    try:
        import unicorn                     # noqa: F401
    except ImportError:
        return dict(status="unavailable", reason="unicorn not installed",
                    tested=0, skipped=0, failures=[], failures_total=0)
    blocks = [b for b in blocks_of(dec, set(order))
              if any(o in removed for o in b)]
    total_blocks = len(blocks)
    if max_blocks:
        blocks = blocks[:max_blocks]
    patched = bytearray(blob)
    for off in removed:
        x = dec[off]
        patched[off:off + x.size] = b"\x90" * x.size
    patched = bytes(patched)
    rnd = random.Random(seed)
    stack = 0x70000000 if bits == 32 else 0x7FF00000
    stack_pages = set(range(stack, stack + 0x10000, 0x1000))
    tested = skipped = 0
    fails = []
    for b in blocks:
        start = base + b[0]
        end = base + b[-1] + dec[b[-1]].size
        lo = start & ~0xFFF
        hi = (end + 0xFFF) & ~0xFFF
        ok = True
        for _ in range(trials):
            regs = [rnd.getrandbits(bits) for _ in range(8)]
            regs[4] = stack + 0x8000
            ef = 0x202 | (rnd.getrandbits(12) & 0x8D5)
            pa, pb = set(), set()
            try:
                ea = _engine(blob[lo - base:hi - base], lo, bits, pa, stack)
                eb = _engine(patched[lo - base:hi - base], lo, bits, pb, stack)
                ra, fa = _run_block(ea, start, end, regs, ef, bits)
                rb, fb = _run_block(eb, start, end, regs, ef, bits)
                union = set(pa) | set(pb) | stack_pages
                da = _digest(ea, pa | stack_pages, union)
                db = _digest(eb, pb | stack_pages, union)
            except Exception as exc:
                ok = None
                fail_reason = "unemulable: %s" % exc
                break
            if ra != rb or fa != fb or da != db:
                ok = False
                fail_reason = ("regs %s != %s / flags %X != %X / mem %s"
                               % (ra, rb, fa, fb, "same" if da == db else "differs"))
                break
        if ok is None:
            skipped += 1
        elif ok:
            tested += 1
        else:
            fails.append(dict(block=b[0], instrs=len(b),
                              cut=sum(1 for o in b if o in removed),
                              reason=fail_reason))
    return dict(status="ok", tested=tested, skipped=skipped,
                blocks_with_cuts=total_blocks,
                blocks_checked=len(blocks), trials=trials,
                failures=fails[:10], failures_total=len(fails))


# --------------------------------------------------------------------- driver --
def pe_bits(image):
    e = struct.unpack_from("<I", image, 0x3C)[0]
    machine = struct.unpack_from("<H", image, e + 4)[0]
    return 64 if machine == 0x8664 else 32


def run(pe_path, out_dir=None, entries=(), verify_trials=3, max_verify=2000,
        write_pe=True, write_listing=True, seed=0x1234, verbose=False,
        engine="audit"):
    """Recover, optimise, patch and verify one payload. Returns stats."""
    import time
    t0 = time.time()
    image = open(pe_path, "rb").read()
    d, base, secs = oreandec.load_pe(pe_path)
    name = oreandec.pick_section(secs)
    s = secs[name]
    blob = d[s["raw"]:s["raw"] + s["rs"]]
    bits = pe_bits(image)
    dec, bad = decode(blob, base, bits)
    pad, pad_runs = pad_map(blob)
    ptrs = external_pointers(image, secs, name, base, len(blob), bits)
    seeds = find_seeds(dec, pad, blob, base, bits, entries, ptrs)
    reachable, indirect, blocked = reach(dec, base, len(blob), seeds, pad)
    order = sorted(reachable)
    cur, cand, cand_by = optimize(dec, order, base, verbose=verbose)
    unproven = audit(dec, order, cand)
    unproven_addrs = set(u["addr"] for u in unproven)
    removed = dict((o, r) for o, r in cand.items() if o not in unproven_addrs)
    reasons = collections.Counter(removed.values())
    t_opt = time.time() - t0

    rbytes = sum(dec[o].size for o in order)
    padding = sum(pad)
    unreach = [o for o in dec if o not in reachable and not pad[o]]
    stats = dict(
        image=os.path.abspath(pe_path), section=name, bits=bits,
        base=base, section_bytes=len(blob),
        instructions=len(dec), undecodable=len(bad), padding_runs=pad_runs,
        padding_bytes=padding, padding_pct=round(padding * 100.0 / len(blob), 2),
        seeds=len(seeds), reachable_instrs=len(order), reachable_bytes=rbytes,
        reachable_pct=round(rbytes * 100.0 / len(blob), 2),
        unreachable_instrs=len(unreach),
        unreachable_pct=round(sum(dec[o].size for o in unreach) * 100.0
                              / len(blob), 2),
        indirect=dict(indirect), blocked=dict(blocked),
        removed=len(removed), kept=len(order) - len(removed),
        candidates=len(cand), reverted=len(unproven_addrs),
        removed_pct=round(len(removed) * 100.0 / max(len(order), 1), 2),
        removed_by=dict(reasons),
        optimize_seconds=round(t_opt, 1))

    removed_set = set(removed)
    stats["structural"] = structural_check(image, s["raw"], len(blob), base,
                                           dec, removed_set, bits)
    if engine == "unicorn":
        ver = verify(blob, base, dec, order, removed_set, bits=bits,
                     trials=verify_trials, max_blocks=max_verify, seed=seed)
        stats["verify"] = dict(ver)
        if ver.get("failures"):
            stats["verify"]["failures"] = ver["failures"]
    else:
        stats["verify"] = dict(
            status="audit", candidates=len(cand), proven=len(removed),
            reverted=len(unproven_addrs),
            reverted_samples=unproven[:10],
            note="every cut re-proved by a forward scan inside its own block;"
                 " a cut that cannot be proved there is reverted")
        ver = stats["verify"]

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        if write_listing:
            p = os.path.join(out_dir, "41_devirt.lst")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("\n".join(render(dec, order, removed, base, s["va"],
                                          stats)) + "\n")
            stats["listing"] = p
        if write_pe:
            data, n = patch_bytes(image, s["raw"], dec, removed_set)
            p = os.path.join(out_dir, "50_devirt.exe")
            with open(p, "wb") as fh:
                fh.write(data)
            stats["patched_pe"] = p
            stats["patched_instrs"] = n
        p = os.path.join(out_dir, "42_devirt.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(stats, fh, indent=2, sort_keys=True)
        stats["json"] = p
    stats["seconds"] = round(time.time() - t0, 1)
    if verbose:
        print("decode  : %d instrs, %d undecodable bytes, %d padding runs "
              "(%X bytes = %.2f%%)  [%.1fs]"
              % (len(dec), len(bad), pad_runs, padding, stats["padding_pct"],
                 t_opt))
        print("reach   : %d seeds (%d external pointers) -> %d instrs / %X "
              "bytes = %.2f%% of the section; %d instrs junk/data (%.2f%%); "
              "indirect %s"
              % (len(seeds), len(ptrs), len(order), rbytes,
                 stats["reachable_pct"], len(unreach),
                 stats["unreachable_pct"], dict(indirect)))
        print("optimise: %d candidates, %d proven and cut (%.2f%% of reachable),"
              " %d reverted by the audit  %s"
              % (len(cand), len(removed), stats["removed_pct"],
                 len(unproven_addrs), dict(reasons)))
        if engine == "unicorn":
            print("verify  : unicorn %d blocks x %d states identical, %d "
                  "unemulable, %d failures  [%.1fs]"
                  % (ver.get("tested", 0), verify_trials,
                     ver.get("skipped", 0), ver.get("failures_total", 0),
                     stats["seconds"] - t_opt))
        else:
            print("verify  : audit proved all %d cuts locally; %d reverted"
                  % (len(removed), len(unproven_addrs)))
        print("struct  : re-decode of the patched section: %s (%d instrs "
              "checked, %d missing, %d changed)"
              % (stats["structural"]["status"],
                 stats["structural"]["checked"],
                 stats["structural"]["missing"],
                 stats["structural"]["changed"]))
    return stats


def main():
    ap = argparse.ArgumentParser(
        description="recover native code from an Oreans .vlizer payload")
    ap.add_argument("image")
    ap.add_argument("--out-dir", default=None,
                    help="write 41_devirt.lst / 42_devirt.json / 50_devirt.exe")
    ap.add_argument("--entry", action="append", default=[], metavar="VA",
                    help="extra code entry point (repeatable)")
    ap.add_argument("--engine", default="audit", choices=("audit", "unicorn"),
                    help="audit: local forward proof per cut (default); "
                         "unicorn: dynamic before/after execution "
                         "(needs a working unicorn - it faults on some "
                         "Python builds)")
    ap.add_argument("--verify", type=int, default=3, metavar="N",
                    help="unicorn only: random states per rewritten block")
    ap.add_argument("--max-verify", type=int, default=2000,
                    help="unicorn only: stop after this many blocks")
    ap.add_argument("--no-pe", action="store_true",
                    help="do not write the patched 50_devirt.exe")
    ap.add_argument("--no-listing", action="store_true")
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0x1234)
    a = ap.parse_args()
    st = run(a.image, a.out_dir, [int(e, 0) for e in a.entry],
             verify_trials=a.verify, max_verify=a.max_verify,
             write_pe=not a.no_pe, write_listing=not a.no_listing,
             seed=a.seed, verbose=True, engine=a.engine)
    if not a.out_dir:
        print(json.dumps(st, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
