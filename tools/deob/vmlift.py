#!/usr/bin/env python3
"""vmlift.py - turn a `vmtrace.py` trace into an opcode -> handler map and a
direct-threaded dispatch listing (still static from here on: only reads files).

What it recovers
  * per dispatch site: how many targets it actually used, and whether it is
    monomorphic (one handler for every opcode) or a real dispatch
  * opcode -> handler: the mapping vmfind proved is *not* in the file
  * conflicts: an opcode observed going to two handlers (polymorphic decode,
    or a second dispatcher that shares the opcode space)
  * per-handler prologue bytes seen at run time (from --follow), which is the
    only copy that exists when the handler is decrypted on the fly
  * level 2: what each opcode *does* to VM state, when the trace was taken with
    `vmtrace --until-return --snapshot N` (before/after state per opcode)

What it emits
  * a report on stdout (`--out` also writes it to a file)
  * `--emit-x86`: an assembly listing in which every dispatch becomes a direct
    jump / compare chain.  This is level 1.5 devirtualisation: the computed
    jump is gone, the handler bodies are still the original VM code.  It is
    emitted as text on purpose - patching code bytes needs slack the payload
    does not have.
  * `--semantics` / `--native-out`: level 2 - per opcode, the operation that is
    consistent with *every* observed transition (`+= k`, `^= k`, `<<= 1`,
    `= src1 + src2`, ...), the same thing as x86, and a replay oracle that
    re-applies those effects to each recorded before-state and compares the
    result with the recorded after-state byte for byte.  A candidate operation
    that does not fit all hits of an opcode is dropped, so the result is a
    claim the data supports - not a guess from disassembly.
  * `--json`: machine-readable map for further passes

Usage:
    python _analysis/vmlift.py vmtrace.jsonl
    python _analysis/vmlift.py vmtrace.jsonl --opcode-from mem --emit-x86 41_lift.asm
    python _analysis/vmlift.py vmtrace.jsonl --opcode-from reg:eax --mask 0xff
    python _analysis/vmlift.py vmtrace.jsonl --semantics --native-out 42_native.asm
    python _analysis/vmlift.py --selftest

`--opcode-from` decides how the opcode is read out of each hit:
    reg:NAME   read the register captured at the breakpoint (default reg:eax)
    mem        read --ctx-len bytes at the recorded ctx_ptr (vmtrace --ctx-ptr)
"""
import argparse
import collections
import json
import os
import sys
import tempfile

REG_ALIASES = {
    "eax": ("eax", "rax"), "ebx": ("ebx", "rbx"), "ecx": ("ecx", "rcx"),
    "edx": ("edx", "rdx"), "esi": ("esi", "rsi"), "edi": ("edi", "rdi"),
    "ebp": ("ebp", "rbp"), "esp": ("esp", "rsp"),
    "rax": ("rax", "eax"), "rbx": ("rbx", "ebx"), "rcx": ("rcx", "ecx"),
    "rdx": ("rdx", "edx"), "rsi": ("rsi", "esi"), "rdi": ("rdi", "edi"),
    "rbp": ("rbp", "ebp"), "rsp": ("rsp", "esp"),
}


def load(path):
    """(header, hits) from a vmtrace JSONL file."""
    header = None
    hits = []
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                raise SystemExit("%s:%d: not JSON" % (path, n))
            if rec.get("kind") == "header":
                header = rec
            elif rec.get("kind") == "hit":
                hits.append(rec)
    if header is None and not hits:
        raise SystemExit("%s: no header and no hits" % path)
    return header or {}, hits


def opcode_of(rec, mode, mask=0xFF, shift=0):
    """The VM opcode of one hit, per --opcode-from."""
    if mode == "mem":
        raw = rec.get("vm_bytes")
        if not raw:
            return None
        val = int.from_bytes(bytes.fromhex(raw), "little")
    else:
        name = mode.split(":", 1)[1] if ":" in mode else mode
        regs = rec.get("regs") or {}
        val = None
        for cand in REG_ALIASES.get(name.lower(), (name.lower(),)):
            if cand in regs:
                val = regs[cand]
                break
        if val is None:
            return None
    return (val >> shift) & mask


def analyse(hits, mode, mask, shift):
    """Group hits into sites and opcodes; no interpretation, just counting."""
    sites = collections.OrderedDict()
    ops = collections.OrderedDict()
    no_opcode = 0
    for rec in hits:
        site = rec.get("site_in_module")
        if site is None:
            site = rec.get("site")
        tgt = rec.get("target_in_module")
        if tgt is None:
            tgt = rec.get("target")
        s = sites.setdefault(site, {"hits": 0, "targets": collections.Counter(),
                                    "steps": collections.Counter()})
        s["hits"] += 1
        s["targets"][tgt] += 1
        steps = rec.get("steps") or []
        if steps and steps[0][1]:
            s["steps"][steps[0][1][:32]] += 1
        op = opcode_of(rec, mode, mask, shift)
        if op is None:
            no_opcode += 1
            continue
        o = ops.setdefault(op, {"hits": 0, "handlers": collections.Counter(),
                                "sites": collections.Counter(),
                                "prologues": collections.Counter()})
        o["hits"] += 1
        o["handlers"][tgt] += 1
        o["sites"][site] += 1
        if steps and steps[0][1]:
            o["prologues"][steps[0][1][:32]] += 1
    conflicts = collections.OrderedDict(
        (op, o) for op, o in ops.items() if len(o["handlers"]) > 1)
    mono = sum(1 for s in sites.values() if len(s["targets"]) == 1)
    return {"sites": sites, "ops": ops, "conflicts": conflicts,
            "no_opcode": no_opcode, "mono": mono, "hits": len(hits),
            "opcodes": len(ops), "mask": mask,
            "handlers": len({t for s in sites.values() for t in s["targets"]})}


def render(res, header, mode):
    out = []
    w = out.append
    w("trace    : %s (%s-bit)" % (header.get("target", "?"),
                                  header.get("bits", "?")))
    w("hits     : %d   sites: %d (%d monomorphic)   handlers: %d"
      % (res["hits"], len(res["sites"]), res["mono"], res["handlers"]))
    w("opcodes  : %d distinct (mask 0x%X)   conflicts: %d   no-opcode hits: %d"
      % (res["opcodes"], res["mask"], len(res["conflicts"]), res["no_opcode"]))
    w("")
    w("== dispatch sites (handler = jump destination)")
    w("   %-10s %6s %8s  %s" % ("site", "hits", "targets", "handlers"))
    for site, s in sorted(res["sites"].items(), key=lambda kv: -kv[1]["hits"]):
        tg = s["targets"]
        hs = ", ".join("%X x%d" % (t, c) for t, c in tg.most_common(4))
        if len(tg) > 4:
            hs += ", ..."
        w("   %-10s %6d %8d  %s" % ("+%X" % site if site is not None else "?",
                                    s["hits"], len(tg), hs))
    w("")
    w("== recovered opcode -> handler")
    if not res["ops"]:
        w("   none: --opcode-from %s produced no values (try reg:esi / mem)"
          % mode)
    else:
        w("   %-6s %6s %-10s %s"
          % ("op", "hits", "handler", "prologue (runtime bytes)"))
        for op in sorted(res["ops"]):
            o = res["ops"][op]
            h, _c = o["handlers"].most_common(1)[0]
            pro = o["prologues"].most_common(1)
            tag = "" if len(o["handlers"]) == 1 else "  (!%d handlers)" % len(
                o["handlers"])
            w("   0x%02X   %6d %-10s %s%s"
              % (op, o["hits"], ("+%X" % h) if h is not None else "?",
                 pro[0][0] if pro else "-", tag))
    if res["conflicts"]:
        w("")
        w("== conflicts (same opcode, different handler)")
        for op, o in sorted(res["conflicts"].items()):
            w("   0x%02X -> %s"
              % (op, ", ".join("%X x%d" % (t, c)
                               for t, c in o["handlers"].most_common())))
        w("   interpretation: either a second dispatcher sharing the opcode")
        w("   space, or opcode-dependent decode; both need a per-site map.")
    return "\n".join(out) + "\n"


def render_asm(res, bits=32):
    """Direct-threaded dispatch: every computed jump becomes a direct one."""
    out = []
    w = out.append
    ptr = 4 if bits == 32 else 8
    w("; direct-threaded VM dispatch, recovered by vmtrace.py + vmlift.py")
    w("; level 1.5: the computed jump is replaced by a direct jump; the")
    w("; handler bodies are still the original VM code (no inlining).")
    w("; %d sites, %d handlers, %d opcodes, %d monomorphic site(s)"
      % (len(res["sites"]), res["handlers"], res["opcodes"], res["mono"]))
    w("")
    for site, s in sorted(res["sites"].items(), key=lambda kv: kv[0] or 0):
        tg = s["targets"]
        w("site_%X:                     ; %d hit(s), %d target(s)"
          % (site or 0, s["hits"], len(tg)))
        if len(tg) == 1:
            t = next(iter(tg))
            w("    jmp 0x%0*X              ; was: jmp reg / jmp [mem]"
              % (ptr * 2, t or 0))
        else:
            chain = []
            covered = set()
            for op in sorted(res["ops"]):
                o = res["ops"][op]
                if len(o["handlers"]) != 1 or o["sites"].get(site, 0) == 0:
                    continue
                h = next(iter(o["handlers"]))
                chain.append((op, h))
                covered.add(h)
            for op, h in chain:
                w("    cmp opcode, 0x%02X" % op)
                w("    je  0x%0*X" % (ptr * 2, h))
            rest = [t for t in tg if t not in covered]
            if rest:
                w("    jmp [opmap_table]        ; %d target(s) not in the chain: %s"
                  % (len(rest),
                     ", ".join(("?" if t is None else "%X" % t)
                               for t in rest[:6])))
            else:
                w("    jmp [opmap_table]        ; fallback: opcodes this trace "
                  "never saw")
        w("")
    if res["ops"]:
        w("; recovered dispatch table (opcode -> handler)")
        w("opmap_table:")
        for op in sorted(res["ops"]):
            o = res["ops"][op]
            h = o["handlers"].most_common(1)[0][0]
            w("    dd 0x%0*X              ; op 0x%02X, %d hit(s)"
              % (ptr * 2, h or 0, op, o["hits"]))
    return "\n".join(out) + "\n"


def render_semantics(sem, res=None, orc=None, base="vmregs"):
    """Per-opcode native bodies derived from observed state transitions."""
    width = sem["width"]
    out = []
    w = out.append
    w("; per-opcode semantics recovered from observed VM state transitions")
    w("; input: vmtrace --until-return --snapshot N   "
      "(%d opcode(s), %d hit(s) with state)" % (len(sem["ops"]),
                                                sem["with_state"]))
    if orc is not None:
        w("; replay oracle: %d/%d hits reproduced byte-exactly (%d mismatch, "
          "%d skipped)" % (orc["ok"], orc["ok"] + orc["bad"], orc["bad"],
                           orc["skipped"]))
    if sem["ops"] and not sem.get("effect_ops"):
        w("; WARNING: no opcode changed these bytes - the snapshot base is "
          "probably wrong,")
        w(";          so every effect below is trivially 'no change'")
    w("")
    for op in sorted(sem["ops"]):
        o = sem["ops"][op]
        h = None
        if res is not None:
            hs = res["ops"].get(op, {}).get("handlers")
            h = hs.most_common(1)[0][0] if hs else None
        w("op_%02X:                          ; %d hit(s)%s"
          % (op, o["hits"], "" if h is None else ", handler +%X" % h))
        if not o["effects"]:
            w("    ; no memory effect observed for this opcode")
        for eff in o["effects"]:
            out.extend(native_lines(eff, width, base))
        w("    jmp next")
        w("")
    w("; semantic summary (what each handler does to VM state)")
    for op in sorted(sem["ops"]):
        o = sem["ops"][op]
        w("   0x%02X  %s" % (op, " ; ".join(o["text"]) or "no observable change"))
    amb = [(op, a) for op in sorted(sem["ops"])
           for a in sem["ops"][op]["ambiguous"]]
    if amb:
        w("")
        w("; ambiguity - the observations fit more than one operation")
        for op, (off, why) in amb:
            w("   0x%02X +0x%X  %s" % (op, off, why))
    churn = [(op, sem["ops"][op]["regs"]) for op in sorted(sem["ops"])
             if sem["ops"][op]["regs"]]
    if churn:
        w("")
        w("; register churn - NOT semantics: the state is sampled when the "
          "dispatcher is")
        w("; re-entered, so the VM's own bookkeeping (opcode/handler pointer) "
          "shows up here")
        for op, regs in churn:
            w("   0x%02X  %s" % (op, ", ".join("%s x%d" % (n, c)
                                              for n, c in sorted(regs.items()))))
    return "\n".join(out) + "\n"


def to_json(res):
    def key(v):
        return "?" if v is None else "%X" % v
    return {
        "sites": {key(k): {"hits": s["hits"],
                           "targets": {key(t): c for t, c in s["targets"].items()},
                           "prologues": dict(s["steps"])}
                  for k, s in res["sites"].items()},
        "opcodes": {"0x%02X" % op: {
            "hits": o["hits"],
            "handler": key(o["handlers"].most_common(1)[0][0]),
            "handlers": {key(t): c for t, c in o["handlers"].items()},
            "prologues": dict(o["prologues"])}
            for op, o in res["ops"].items()},
        "conflicts": ["0x%02X" % op for op in res["conflicts"]],
        "stats": {"hits": res["hits"], "sites": len(res["sites"]),
                  "monomorphic": res["mono"], "handlers": res["handlers"],
                  "opcodes": res["opcodes"], "no_opcode": res["no_opcode"]},
    }


# ------------------------------------------------------------- level 2 -------
# Deriving what an opcode *does*, from observation only.  A trace produced with
# `vmtrace --until-return --snapshot N` carries the VM state block before and
# after each opcode, so the effect can be read off as a constraint:
#
#     for every hit of this opcode:  after[i] == f(before[i])
#
# A candidate operation survives only if it satisfies *all* hits of that
# opcode.  That is what makes the result checkable rather than "plausible": the
# fixture in vmfix.py is built so that a wrong guess (e.g. "add k" for a
# two-slot add) cannot fit every observed transition.
WIDTH_NAME = {1: "byte", 2: "word", 4: "dword", 8: "qword"}
_WIDTH = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
# most structural first; `set` is last because it is the weakest claim
PRIORITY = ("not", "neg", "shl", "shr", "movadd", "movsub", "addmem", "submem",
            "xor", "or", "and", "add", "sub", "set")


def _ints(buf, width):
    return [int.from_bytes(buf[i:i + width], "little")
            for i in range(0, len(buf) - width + 1, width)]


def _candidates(b, a, slots, off, width):
    """Operations that map `b` to `a` in this one observation.

    name -> parameter (None for the unary ones).  A parameter is later required
    to be identical across every hit of the opcode.
    """
    m = _WIDTH[width]
    c = {"set": a, "arith": (a - b) & m, "xor": b ^ a}
    # `or` can only set bits and `and` can only clear them, so a mask exists
    # only if the observation moved in that direction.  Without the guard a
    # transition that clears bits still yields "or 0" (a no-op that cannot
    # produce `a`), which then poisons every other hit of the opcode.
    if not (b & (~a & m)):
        c["or"] = a & (~b & m)
    if not (a & (~b & m)):
        c["and"] = a | (~b & m)
    if a == (~b) & m:
        c["not"] = None
    if a == (-b) & m:
        c["neg"] = None
    if b:
        for k in range(1, width * 8):
            if a == (b << k) & m:
                c["shl"] = k
                break
        for k in range(1, width * 8):
            if a == b >> k:
                c["shr"] = k
                break
    for src, v in slots.items():
        if src == off:
            continue
        if "addmem" not in c and a == (b + v) & m:
            c["addmem"] = src
        if "submem" not in c and a == (b - v) & m:
            c["submem"] = src
    for s1, v1 in slots.items():
        if s1 == off:
            continue
        for s2, v2 in slots.items():
            if s2 in (off, s1):
                continue
            if "movadd" not in c and a == (v1 + v2) & m:
                c["movadd"] = (s1, s2)
            if "movsub" not in c and a == (v1 - v2) & m:
                c["movsub"] = (s1, s2)
    return c


def effect_text(eff, width=4):
    """Canonical text of one effect - the same format vmfix.py documents."""
    kind, off = eff[0], eff[1]
    param = eff[2] if len(eff) > 2 else None
    w = WIDTH_NAME.get(width, "dword")
    dst = "%s [vm+0x%X]" % (w, off)
    if kind == "add":
        return "%s += %d" % (dst, param)
    if kind == "sub":
        return "%s -= %d" % (dst, param)
    if kind == "xor":
        return "%s ^= 0x%X" % (dst, param)
    if kind == "or":
        return "%s |= 0x%X" % (dst, param)
    if kind == "and":
        return "%s &= 0x%X" % (dst, param)
    if kind == "shl":
        return "%s <<= %d" % (dst, param)
    if kind == "shr":
        return "%s >>= %d" % (dst, param)
    if kind == "not":
        return "%s = ~%s" % (dst, dst)
    if kind == "neg":
        return "%s = -%s" % (dst, dst)
    if kind == "set":
        return "%s = 0x%X" % (dst, param)
    if kind == "addmem":
        return "%s += %s [vm+0x%X]" % (dst, w, param)
    if kind == "submem":
        return "%s -= %s [vm+0x%X]" % (dst, w, param)
    if kind in ("movadd", "movsub"):
        return "%s = %s [vm+0x%X] %s %s [vm+0x%X]" % (
            dst, w, param[0], "+" if kind == "movadd" else "-", w, param[1])
    if kind == "nop":
        return "%s: no observable change" % dst
    return "%s = ?" % dst


def native_lines(eff, width=4, base="vmregs"):
    """The same effect as x86 a devirtualiser can emit (text, not bytes)."""
    kind, off = eff[0], eff[1]
    param = eff[2] if len(eff) > 2 else None
    w = WIDTH_NAME.get(width, "dword")
    dst = "%s ptr [%s+0x%X]" % (w, base, off)
    if kind == "add":
        return ["    add %s, %d" % (dst, param)]
    if kind == "sub":
        return ["    sub %s, %d" % (dst, param)]
    if kind == "xor":
        return ["    xor %s, 0x%X" % (dst, param)]
    if kind == "or":
        return ["    or  %s, 0x%X" % (dst, param)]
    if kind == "and":
        return ["    and %s, 0x%X" % (dst, param)]
    if kind == "shl":
        return ["    shl %s, %d" % (dst, param)]
    if kind == "shr":
        return ["    shr %s, %d" % (dst, param)]
    if kind == "not":
        return ["    not %s" % dst]
    if kind == "neg":
        return ["    neg %s" % dst]
    if kind == "set":
        return ["    mov %s, 0x%X" % (dst, param)]
    if kind in ("addmem", "submem"):
        src = "%s ptr [%s+0x%X]" % (w, base, param)
        return ["    mov eax, %s" % dst,
                "    %s eax, %s" % ("add" if kind == "addmem" else "sub", src),
                "    mov %s, eax" % dst]
    if kind in ("movadd", "movsub"):
        s1 = "%s ptr [%s+0x%X]" % (w, base, param[0])
        s2 = "%s ptr [%s+0x%X]" % (w, base, param[1])
        return ["    mov eax, %s" % s1,
                "    %s eax, %s" % ("add" if kind == "movadd" else "sub", s2),
                "    mov %s, eax" % dst]
    return ["    ; no code: %s" % effect_text(eff, width)]


def replay(effects, before, width=4):
    """Apply recovered effects to a state block - the differential oracle."""
    buf = bytearray(before)
    m = _WIDTH[width]

    def get(off):
        return int.from_bytes(buf[off:off + width], "little")

    def put(off, v):
        buf[off:off + width] = (v & m).to_bytes(width, "little")

    for eff in effects:
        kind, off = eff[0], eff[1]
        param = eff[2] if len(eff) > 2 else None
        b = get(off)
        if kind == "add":
            put(off, b + param)
        elif kind == "sub":
            put(off, b - param)
        elif kind == "xor":
            put(off, b ^ param)
        elif kind == "or":
            put(off, b | param)
        elif kind == "and":
            put(off, b & param)
        elif kind == "shl":
            put(off, b << param)
        elif kind == "shr":
            put(off, b >> param)
        elif kind == "not":
            put(off, ~b)
        elif kind == "neg":
            put(off, -b)
        elif kind == "set":
            put(off, param)
        elif kind == "addmem":
            put(off, b + get(param))
        elif kind == "submem":
            put(off, b - get(param))
        elif kind == "movadd":
            put(off, get(param[0]) + get(param[1]))
        elif kind == "movsub":
            put(off, get(param[0]) - get(param[1]))
        # "nop" / unknown: nothing to do
    return bytes(buf)


def _derive_op(rs, width):
    """(effects, ambiguous, hits, regs) for all hits of one opcode."""
    m = _WIDTH[width]
    before, after = [], []
    for rec in rs:
        before.append({i * width: v for i, v in enumerate(
            _ints(bytes.fromhex(rec["mem_before"]), width))})
        after.append({i * width: v for i, v in enumerate(
            _ints(bytes.fromhex(rec["mem_after"]), width))})
    effects, ambiguous = [], []
    for off in sorted(set().union(*before)) if before else []:
        pairs = [(b[off], a[off], b) for b, a in zip(before, after)
                 if off in a and a[off] != b.get(off)]
        if not pairs:
            continue
        cands = [_candidates(b, a, s, off, width) for b, a, s in pairs]
        params = dict(cands[0])
        keep = set(params)
        for c in cands[1:]:
            keep &= set(c)
        for name in list(keep):            # the parameter must be constant
            if any(c[name] != params[name] for c in cands[1:]):
                keep.discard(name)
        if "arith" in keep:
            # fold the constant delta into add/sub (k and -k are the same op)
            k = params.pop("arith")
            keep.discard("arith")
            if k == 0:
                keep.add("nop")
            elif k <= m >> 1:
                keep.add("add")
                params["add"] = k
            else:
                keep.add("sub")
                params["sub"] = (m + 1 - k) % (m + 1)
        pick = next((n for n in PRIORITY if n in keep), None) or \
            ("nop" if "nop" in keep else None)
        if pick is None:
            effects.append(("unknown", off, None))
            ambiguous.append((off, "unexplained (%d hit(s) fit no single "
                                   "operation - a mask needs more varied "
                                   "observations)" % len(pairs)))

            continue
        effects.append((pick, off, params.get(pick)))
        others = [n for n in PRIORITY if n in keep and n != pick]
        if others:
            ambiguous.append((off, "%s (also fits: %s)"
                              % (pick, ", ".join(others))))
    regs = {}
    for rec in rs:
        for name, after_v in (rec.get("regs_after") or {}).items():
            if (rec.get("regs") or {}).get(name) != after_v:
                regs[name] = regs.get(name, 0) + 1
    return effects, ambiguous, len(rs), regs


def derive(hits, mode, mask, shift, width=4):
    """opcode -> {effects, text, ambiguous, hits, regs} from observed deltas."""
    if width not in _WIDTH:
        raise SystemExit("--sem-width must be 1, 2, 4 or 8")
    groups = collections.OrderedDict()
    skipped = 0
    for rec in hits:
        b, a = rec.get("mem_before"), rec.get("mem_after")
        if not b or not a or len(b) != len(a) or rec.get("truncated"):
            skipped += 1
            continue
        op = opcode_of(rec, mode, mask, shift)
        if op is None:
            skipped += 1
            continue
        groups.setdefault(op, []).append(rec)
    out = collections.OrderedDict()
    for op, rs in groups.items():
        effs, amb, n, regs = _derive_op(rs, width)
        out[op] = {"effects": effs, "hits": n,
                   "text": [effect_text(e, width) for e in effs],
                   "ambiguous": amb, "regs": regs}
    return {"ops": out, "skipped": skipped, "width": width,
            "with_state": sum(o["hits"] for o in out.values()),
            "effect_ops": sum(1 for o in out.values() if o["effects"]),
            "silent": [op for op, o in out.items() if not o["effects"]]}


def verify(sem, hits, mode, mask, shift, width=4):
    """Replay every hit through the recovered effects and compare the bytes."""
    ops = sem["ops"]
    ok = bad = skipped = 0
    fails = []
    for rec in hits:
        b, a = rec.get("mem_before"), rec.get("mem_after")
        if not b or not a or rec.get("truncated"):
            skipped += 1
            continue
        op = opcode_of(rec, mode, mask, shift)
        if op not in ops:
            skipped += 1
            continue
        want = bytes.fromhex(a)
        got = replay(ops[op]["effects"], bytes.fromhex(b), width)
        if got == want:
            ok += 1
        else:
            bad += 1
            if len(fails) < 8:
                off = next((i for i in range(min(len(got), len(want)))
                            if got[i] != want[i]), 0)
                fails.append({"seq": rec.get("seq"), "opcode": op,
                              "offset": off})
    return {"ok": ok, "bad": bad, "skipped": skipped, "fails": fails}


# ------------------------------------------------------------- self test ------
def _synth():
    """A small trace with known answers: 2 monomorphic sites, 1 dispatch site,
    one opcode that resolves to two handlers."""
    hits = []

    def hit(site, target, eax, pro="558bec", vm=None):
        rec = {"kind": "hit", "seq": len(hits) + 1, "site": site,
               "site_in_module": site, "target": target,
               "target_in_module": target, "regs": {"eax": eax},
               "eflags": 0x246, "thread": 1,
               "steps": [[target, pro]]}
        if vm is not None:
            rec["vm_bytes"] = vm
            rec["ctx_ptr"] = 0x400000
        hits.append(rec)

    for _ in range(5):
        hit(0x1000, 0x2000, 0x10)
    for _ in range(3):
        hit(0x1000, 0x2010, 0x11)
    for _ in range(4):
        hit(0x1100, 0x2100, 0x12)
    for _ in range(2):
        hit(0x1200, 0x2200, 0x20)
    hit(0x1200, 0x2210, 0x20, pro="8bff55")          # the conflict
    hit(0x1200, 0x2200, 0x0C, vm="0c000000")         # for --opcode-from mem
    return hits


def _synth_state():
    """Hits carrying before/after VM state: 0x10 = inc dword[0],
    0x11 = xor dword[4],0x1234  (the level-2 analogue of _synth)."""
    hits = []

    def hit(op, before, after):
        hits.append({"kind": "hit", "seq": len(hits) + 1, "site": 0x1000,
                     "site_in_module": 0x1000, "target": 0x2000 + op,
                     "target_in_module": 0x2000 + op,
                     "regs": {"eax": op}, "thread": 1,
                     "steps": [[0x2000 + op, "41ff45"]],
                     "mem_before": bytes(before).hex(),
                     "mem_after": bytes(after).hex()})

    for i in range(4):
        before = bytearray(0x10)
        before[0:4] = (0x100 + i).to_bytes(4, "little")
        before[4:8] = (0x40 + i).to_bytes(4, "little")
        after = bytearray(before)
        after[0:4] = (0x101 + i).to_bytes(4, "little")
        hit(0x10, before, after)
        xored = bytearray(before)
        xored[4:8] = ((0x40 + i) ^ 0x1234).to_bytes(4, "little")
        hit(0x11, before, xored)
    return hits


def selftest():
    hits = _synth()
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    res = analyse(hits, "reg:eax", 0xFF, 0)
    check("sites counted", len(res["sites"]) == 3, str(len(res["sites"])))
    check("monomorphic sites", res["mono"] == 1, str(res["mono"]))
    check("distinct opcodes", res["opcodes"] == 5, str(res["opcodes"]))
    check("conflict detected", list(res["conflicts"]) == [0x20],
          str(["0x%02X" % o for o in res["conflicts"]]))
    check("handler count", res["handlers"] == 5, str(res["handlers"]))
    txt = render(res, {"target": "synthetic", "bits": 32}, "reg:eax")
    check("report has opcode table", "recovered opcode -> handler" in txt)
    check("report marks the conflict", "0x20 ->" in txt and "(!2 handlers)" in txt)
    asm = render_asm(res, 32)
    check("asm: monomorphic site becomes direct jmp",
          "site_1100:" in asm and "jmp 0x00002100" in asm)
    check("asm: dispatch site becomes a compare chain",
          "cmp opcode, 0x11" in asm and "je  0x00002010" in asm)
    check("asm: dispatch table emitted", "opmap_table:" in asm)
    mem = analyse(hits, "mem", 0xFF, 0)
    check("--opcode-from mem reads vm_bytes", 0x0C in mem["ops"],
          "ops %s" % sorted("0x%02X" % o for o in mem["ops"]))
    js = to_json(res)
    check("json has opcode 0x10 -> 2000",
          js["opcodes"]["0x10"]["handler"] == "2000",
          str(js["opcodes"].get("0x10")))

    # level 2: semantics from observed state transitions
    st = _synth_state()
    sem = derive(st, "reg:eax", 0xFF, 0, 4)
    want10, want11 = ["dword [vm+0x0] += 1"], ["dword [vm+0x4] ^= 0x1234"]
    check("semantics: 0x10 recovered as inc dword[0]",
          sem["ops"].get(0x10, {}).get("text") == want10,
          str(sem["ops"].get(0x10, {}).get("text")))
    check("semantics: 0x11 recovered as xor dword[4],0x1234",
          sem["ops"].get(0x11, {}).get("text") == want11,
          str(sem["ops"].get(0x11, {}).get("text")))
    orc = verify(sem, st, "reg:eax", 0xFF, 0, 4)
    check("replay oracle reproduces every hit",
          orc["bad"] == 0 and orc["ok"] == len(st),
          "%d/%d bad=%d" % (orc["ok"], len(st), orc["bad"]))
    tampered = {"ops": {0x10: {"effects": [("add", 0, 2)]},
                        0x11: {"effects": sem["ops"][0x11]["effects"]}},
                "width": 4}
    orc2 = verify(tampered, st, "reg:eax", 0xFF, 0, 4)
    check("oracle rejects a wrong effect (not vacuous)", orc2["bad"] > 0,
          "%d mismatch" % orc2["bad"])
    native = render_semantics(sem, None, orc)
    check("native listing has a body per opcode",
          "op_10:" in native and "op_11:" in native
          and "add dword ptr [vmregs+0x0], 1" in native)
    quiet = [dict(h, mem_after=h["mem_before"]) for h in st]
    sem0 = derive(quiet, "reg:eax", 0xFF, 0, 4)
    check("a trace whose state never changes is flagged, not believed",
          sem0["effect_ops"] == 0 and len(sem0["silent"]) == len(sem0["ops"])
          and "WARNING" in render_semantics(sem0, None, None),
          "%d/%d silent" % (len(sem0["silent"]), len(sem0["ops"])))

    # `or` can only set bits and `and` can only clear them, so a transition that
    # clears bits must never be explained as `or 0` (a no-op: it would leave the
    # value at `b`, not at `a`).  Regression for the candidate bug that
    # vminline's execute-to-prove oracle exposed.
    clr = []
    for b, a in ((0x0000FFFF, 0x000000FF), (0x1234, 0x0034)):
        clr.append({"kind": "hit", "site": 0x1000, "target": 0x3000,
                    "regs": {"eax": 0x30},
                    "mem_before": b.to_bytes(4, "little").hex(),
                    "mem_after": a.to_bytes(4, "little").hex()})
    semc = derive(clr, "reg:eax", 0xFF, 0, 4)
    ef = semc["ops"].get(0x30, {}).get("effects", [])
    check("a bit-clearing transition is never explained as `or`",
          bool(ef) and all(e[0] != "or" for e in ef), str(ef))
    check("a mask that the hits do not pin down is reported, not guessed",
          ef and ef[0][0] == "unknown" and
          "mask needs more varied observations" in
          " ".join(d for _o, d in semc["ops"].get(0x30, {}).get("ambiguous", [])),
          "%s / %s" % (ef, semc["ops"].get(0x30, {}).get("ambiguous")))


    # when every bit of the input is 1, the mask is pinned exactly and the
    # honest answer is `and`, never `or` (whose mask would have to be 0)
    clr2 = [{"kind": "hit", "site": 0x1000, "target": 0x3000,
             "regs": {"eax": 0x31},
             "mem_before": (0xFFFFFFFF).to_bytes(4, "little").hex(),
             "mem_after": (0x000000FF).to_bytes(4, "little").hex()},
            {"kind": "hit", "site": 0x1000, "target": 0x3000,
             "regs": {"eax": 0x31},
             "mem_before": (0xFFFFFF00).to_bytes(4, "little").hex(),
             "mem_after": (0x00000000).to_bytes(4, "little").hex()}]
    sem2 = derive(clr2, "reg:eax", 0xFF, 0, 4)
    ef2 = sem2["ops"].get(0x31, {}).get("effects", [])
    check("a pinned mask comes back as `and`/`xor`, never `or`",
          [e[0] for e in ef2] == ["xor"] or [e[0] for e in ef2] == ["and"], str(ef2))
    check("that effect reproduces both hits exactly (honest ambiguity)",
          verify(sem2, clr2, "reg:eax", 0xFF, 0, 4)["bad"] == 0,
          str(sem2["ops"].get(0x31, {}).get("ambiguous")))




    # round trip through a real JSONL file (the actual entry point)
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"kind": "header", "target": "synthetic",
                                "bits": 32}) + "\n")
            for r in hits:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        header, loaded = load(path)
        res2 = analyse(loaded, "reg:eax", 0xFF, 0)
        check("jsonl round trip", res2["hits"] == len(hits) and
              len(res2["sites"]) == 3 and res2["opcodes"] == 5,
              "%d hits" % res2["hits"])
        check("header parsed", header.get("bits") == 32)
    finally:
        os.unlink(path)

    bad = 0
    for name, ok, detail in checks:
        print("  [%s] %-46s %s" % ("PASS" if ok else "FAIL", name, detail))
        bad += 0 if ok else 1
    print("selftest: %s (%d/%d)" % ("PASS" if not bad else "FAIL",
                                    len(checks) - bad, len(checks)))
    return 0 if not bad else 1


# ------------------------------------------------------------------- main -----
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="opcode -> handler recovery from a vmtrace.py trace")
    ap.add_argument("trace", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--opcode-from", default="reg:eax",
                    help="reg:NAME (default reg:eax) or mem (ctx_ptr bytes)")
    ap.add_argument("--mask", type=lambda s: int(s, 0), default=0xFF)
    ap.add_argument("--shift", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--out", default=None, help="write the report here too")
    ap.add_argument("--emit-x86", default=None, metavar="ASM",
                    help="write a direct-threaded dispatch listing")
    ap.add_argument("--semantics", action="store_true",
                    help="derive what each opcode does to VM state (needs a "
                         "trace made with --until-return --snapshot N)")
    ap.add_argument("--sem-width", type=int, default=4, metavar="N",
                    help="VM state slot width for --semantics (default 4)")
    ap.add_argument("--native-out", default=None, metavar="ASM",
                    help="write per-opcode native bodies (implies --semantics)")
    ap.add_argument("--json", default=None, metavar="JSON",
                    help="write the recovered map as JSON")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not a.trace:
        raise SystemExit("need a trace file (or --selftest)")
    header, hits = load(a.trace)
    if not hits:
        print("trace has no hits - did vmtrace.py run with --exec and hit "
              "anything?")
    res = analyse(hits, a.opcode_from, a.mask, a.shift)
    txt = render(res, header, a.opcode_from)
    sys.stdout.write(txt)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(txt)
    if a.emit_x86:
        asm = render_asm(res, int(header.get("bits", 32) or 32))
        with open(a.emit_x86, "w", encoding="utf-8") as f:
            f.write(asm)
        print("\nasm      : %s (%d sites, %d handlers)"
              % (a.emit_x86, len(res["sites"]), res["handlers"]))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(to_json(res), f, indent=1, sort_keys=True)
            f.write("\n")
        print("json     : %s" % a.json)
    if a.semantics or a.native_out:
        sem = derive(hits, a.opcode_from, a.mask, a.shift, a.sem_width)
        if not sem["ops"]:
            print("\nsemantics: this trace carries no VM state snapshots - make "
                  "it with\n           --until-return --snapshot N "
                  "--snapshot-from reg:NAME")
            return 1
        orc = verify(sem, hits, a.opcode_from, a.mask, a.shift, a.sem_width)
        print("\n== level 2: semantics per opcode   (replay oracle %d/%d, "
              "%d skipped)" % (orc["ok"], orc["ok"] + orc["bad"],
                               orc["skipped"]))
        for op in sorted(sem["ops"]):
            o = sem["ops"][op]
            h = res["ops"].get(op, {}).get("handlers")
            print("   0x%02X %-10s %s" % (op, ("+%X" % h.most_common(1)[0][0])
                                          if h else "",
                                          " ; ".join(o["text"])
                                          or "no observable change"))
        if orc["bad"]:
            print("   MISMATCH: %d hit(s) not reproduced: %s"
                  % (orc["bad"], orc["fails"][:3]))
            print("   (effects that do not replay are not semantics - check "
                  "--sem-width, or the handler for that opcode)")
        if not sem["effect_ops"]:
            print("   WARNING: no opcode changed the snapshot - check "
                  "--snapshot-from/--snapshot")
        if a.native_out:
            txt2 = render_semantics(sem, res, orc)
            with open(a.native_out, "w", encoding="utf-8") as f:
                f.write(txt2)
            print("native   : %s (%d opcode(s), oracle %d/%d)"
                  % (a.native_out, len(sem["ops"]), orc["ok"],
                     orc["ok"] + orc["bad"]))
        return 0 if not orc["bad"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
