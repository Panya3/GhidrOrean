#!/usr/bin/env python3
"""vminline.py - level 2 devirtualisation: inline an observed VM program into
real x86-64, and prove the result by executing it.

`vmlift.py` answers "what does opcode 0x04 do to VM state".  This answers
"what does *this run of the VM* do", i.e. the same question as REPORT 7.6
level 2: the executed opcode stream is replaced by the native instructions of
each opcode, in order, with no dispatcher and no handlers left.

Where the two inputs come from
    semantics   a vmtrace.jsonl taken with `--until-return --snapshot N`
                (opcode -> effects, derived by vmlift.derive - same code path
                as `vmlift --semantics`, so the two never disagree)
    program     the opcode sequence of that trace, in file (= run) order, or
                --ops "1,2,3" to inline any sequence by hand

Why the result is checkable, not just plausible
    --blob-out assembles the inlined programme into real x86-64 bytes: a leaf
    function that takes the state-block pointer in RCX (Windows x64).
    --run calls it on a copy of the seed state and prints the final block, and
    --expect-from-trace compares that block against the *last* snapshot the
    debugger recorded in the real process, byte for byte.  So the claim is
    "native code that reproduces what the VM actually did", measured.

    Every emitted instruction is encoded from the effect model, never copied
    from the handler, so a wrong effect model produces wrong bytes and the
    comparison fails.  --selftest executes every encoder form for that reason.

What is NOT claimed (see REPORT 7.7)
    * straight-line only: the programme is a sequence, so VM-level branches
      (`jcc` inside the bytecode) are not reproduced - a traced run is inlined
      as the path it took
    * one state block per run: a VM that keeps state in several places needs
      one pass per base (same rule as vmlift --snapshot-from)
    * effects of one opcode are applied in slot order; a handler that writes a
      slot and then reads it again inside the same opcode would need a finer
      model (vmlift reports such an opcode as ambiguous)

Usage:
    python _analysis/vminline.py vmtrace.jsonl --asm-out 43_inline.asm
           --blob-out 43_inline.bin --expect-from-trace --run
    python _analysis/vminline.py vmtrace.jsonl --ops 1,2,3 --seed 00112233...
    python _analysis/vminline.py --selftest
"""
import argparse
import ctypes
import hashlib
import json
import struct
import sys

import vmlift

PAGE_RWX = 0x40
MEM_COMMIT_RESERVE = 0x3000
MEM_RELEASE = 0x8000


# --------------------------------------------------------------- encoder -----
# One effect -> x86-64 bytes.  The state block pointer is passed in RCX, which
# is why every memory operand below is [rcx+disp]; EAX/RAX is the scratch
# register for the two-source forms (the same shape vmlift.native_lines writes).
_ALU = {"add": 0, "or": 1, "and": 4, "sub": 5, "xor": 6}     # 81 /r id
_SHIFT = {"shl": 4, "shr": 5}                               # c1 /r ib
_UNARY = {"not": 2, "neg": 3}                               # f7 /r


class EncodeError(ValueError):
    """An effect the encoder cannot turn into bytes (never silently skipped)."""


def _rex(width):
    return b"\x48" if width == 8 else b""


def _modrm(reg, disp):
    """modrm for [rcx+disp] with an arbitrary /r field."""
    if -0x80 <= disp <= 0x7F:
        return bytes(((0x40 | (reg << 3) | 1), disp & 0xFF))
    return bytes(((0x80 | (reg << 3) | 1),)) + struct.pack("<i", disp)


def _imm32(v, width):
    """imm32 operand: zero-extended for dword slots, sign-extended for qword."""
    v = int(v)
    if width == 4:
        if not -(1 << 31) <= v < (1 << 32):
            raise EncodeError("dword immediate out of range: %d" % v)
        return struct.pack("<I", v & 0xFFFFFFFF)
    if not -(1 << 31) <= v < (1 << 31):
        raise EncodeError("qword immediate does not fit imm32: %d" % v)
    return struct.pack("<i", v)


def _mov_mem_imm(width, off, v):
    """mov dword/qword [rcx+off], imm - including the movabs fallback."""
    if width == 8 and not (-(1 << 31) <= int(v) < (1 << 31)):
        return (b"\x48\xb8" + struct.pack("<Q", int(v) & 0xFFFFFFFFFFFFFFFF)
                + b"\x48\x89" + _modrm(0, off))          # movabs rax,imm64; mov [],rax
    return _rex(width) + b"\xc7" + _modrm(0, off) + _imm32(v, width)



def encode(eff, width=4):
    """x86-64 bytes for one effect ("add", off, k) / ("movadd", off, (a, b))."""
    if width not in (4, 8):
        raise EncodeError("only dword and qword slots can be emitted (got %d)"
                          % width)
    kind = eff[0]
    off = eff[1]
    param = eff[2] if len(eff) > 2 else None
    if kind in ("nop", "unknown"):
        return b""                                        # nothing observed
    if off is None or off < 0:
        raise EncodeError("bad slot offset for %r" % (eff,))
    if kind in _ALU:
        return (_rex(width) + b"\x81" + _modrm(_ALU[kind], off)
                + _imm32(param, width))
    if kind in _SHIFT:
        if not 0 <= int(param) <= 63:
            raise EncodeError("shift count out of range: %r" % (param,))
        return (_rex(width) + b"\xc1" + _modrm(_SHIFT[kind], off)
                + bytes((int(param),)))
    if kind in _UNARY:
        return _rex(width) + b"\xf7" + _modrm(_UNARY[kind], off)
    if kind == "set":
        return _mov_mem_imm(width, off, param)
    if kind in ("addmem", "submem"):
        dst, src = off, param
        return (_rex(width) + b"\x8b" + _modrm(0, dst)     # mov acc,[rcx+dst]
                + _rex(width) + (b"\x03" if kind == "addmem" else b"\x2b")
                + _modrm(0, src)                           # add/sub acc,[rcx+src]
                + _rex(width) + b"\x89" + _modrm(0, dst))  # mov [rcx+dst],acc
    if kind in ("movadd", "movsub"):
        dst, s1, s2 = off, param[0], param[1]
        return (_rex(width) + b"\x8b" + _modrm(0, s1)
                + _rex(width) + (b"\x03" if kind == "movadd" else b"\x2b")
                + _modrm(0, s2)
                + _rex(width) + b"\x89" + _modrm(0, dst))
    raise EncodeError("no x86 form for effect %r" % (eff,))


RET = b"\xc3"


def assemble(steps, width=4, block=0):
    """(code, notes) - one native sequence per VM instruction, then `ret`.

    `block` is the size of the state block: every slot the model touches must
    fit inside it, so a bad --snapshot / --sem-width is caught before anything
    is executed rather than after.
    """
    code = bytearray()
    notes = []
    for i, (op, effs) in enumerate(steps):
        start = len(code)
        for eff in effs:
            off = eff[1]
            if block and isinstance(off, int) and off + width > block:
                raise EncodeError("op 0x%02X touches +0x%X which is outside the "
                                  "%d-byte state block" % (op or 0, off, block))
            if block and eff[0] in ("addmem", "submem") and eff[2] + width > block:
                raise EncodeError("op 0x%02X reads +0x%X outside the state block"
                                  % (op or 0, eff[2]))
            if block and eff[0] in ("movadd", "movsub") and \
                    max(eff[2]) + width > block:
                raise EncodeError("op 0x%02X reads +0x%X outside the state block"
                                  % (op or 0, max(eff[2])))
            code += encode(eff, width)
        notes.append((i, op, len(code) - start))
    code += RET
    return bytes(code), notes


def run_code(code, state, bits=64):
    """Call `code` on a copy of `state`; returns the (mutated) block.

    Only ever runs bytes this file just encoded, on a buffer we own: no target
    binary, no handler, nothing that came out of a file.  Windows x64 only,
    because the calling convention (state pointer in RCX) is written into the
    encoding.
    """
    if sys.platform != "win32":
        raise SystemExit("error: --run needs Windows (state pointer is passed "
                         "in RCX)")
    if bits != 64:
        raise SystemExit("error: --run emits x86-64 only (trace says %s-bit)"
                         % bits)
    if len(code) > 1 << 20:
        raise SystemExit("error: refusing to run %d bytes of code" % len(code))
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_uint32, ctypes.c_uint32]
    k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    addr = k32.VirtualAlloc(None, len(code) + 16, MEM_COMMIT_RESERVE, PAGE_RWX)
    if not addr:
        raise OSError("VirtualAlloc failed (0x%X)" % ctypes.get_last_error())
    buf = ctypes.create_string_buffer(bytes(state), len(state))
    try:
        ctypes.memmove(addr, code, len(code))
        fn = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(addr)
        fn(ctypes.addressof(buf))
    finally:
        k32.VirtualFree(ctypes.c_void_p(addr), 0, MEM_RELEASE)
    return buf.raw[:len(state)]



# ------------------------------------------------------------- programme -----
def program_from_trace(hits, mode, mask, shift, limit=None):
    """Opcode sequence in run order (None = a hit whose opcode was not read)."""
    out = []
    for rec in hits:
        if limit and len(out) >= limit:
            break
        out.append(vmlift.opcode_of(rec, mode, mask, shift))
    return out


def state_ends(hits):
    """(seed, expect, n) - first before-state and last after-state in the trace.

    Both are the debugger's own bytes at the VM state block: the seed is what
    the VM started with, the expectation is what it ended with, so running the
    inlined code between them is a differential test and not a re-simulation.
    """
    seed = expect = None
    n = 0
    for rec in hits:
        b, a = rec.get("mem_before"), rec.get("mem_after")
        if not b or not a or len(b) != len(a):
            continue
        n += 1
        if seed is None:
            seed = bytes.fromhex(b)
        expect = bytes.fromhex(a)
    return seed, expect, n


def unmapped_ops(program, sem):
    """Opcodes in the programme the trace gave no effect for (emitted as text)."""
    seen = []
    for op in program:
        if (op is None or op not in sem["ops"]
                or not sem["ops"][op]["effects"]):
            if op not in seen:
                seen.append(op)
    return seen


def build(trace, mode="reg:eax", mask=0xFF, shift=0, width=4, ops=None,
          limit=None, block=0):
    """Read a trace, derive semantics, inline the programme.  No execution."""
    try:
        header, hits = vmlift.load(trace)
    except OSError as exc:
        raise SystemExit("error: %s" % exc)

    sem = vmlift.derive(hits, mode, mask, shift, width)
    if ops is not None:
        program = list(ops)
    else:
        program = program_from_trace(hits, mode, mask, shift, limit)
    steps = [(op, sem["ops"].get(op, {}).get("effects", [])) for op in program]
    seed, expect, n_state = state_ends(hits)
    size = block or (len(seed) if seed else 0)
    code, notes = assemble(steps, width, size)
    return {"header": header, "hits": hits, "sem": sem, "program": program,
            "steps": steps, "code": code, "notes": notes,
            "unmapped": unmapped_ops(program, sem), "seed": seed,
            "expect": expect, "n_state": n_state, "width": width,
            "block": size, "mode": mode}


def replay_steps(steps, seed, width=4):
    """The reference model: vmlift.replay over the whole programme."""
    effs = []
    for _op, es in steps:
        effs.extend(es)
    return vmlift.replay(effs, seed, width)


def first_diff(a, b):
    """Offset of the first differing byte, or None when the blocks are equal."""
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i
    return None if len(a) == len(b) else min(len(a), len(b))


# ---------------------------------------------------------------- output -----
def render(b, base="vmregs", orc=None, run=None):
    """The inlined programme as an assembly listing (one block per VM step)."""
    width = b["width"]
    hdr = b["header"] or {}
    out = []
    w = out.append
    w("; inline of the executed VM programme - level 2 devirtualisation")
    w("; (vminline.py; semantics from vmlift.derive, programme = the traced run)")
    w("; trace     : %s (%s-bit), %d hit(s), %d with state"
      % (hdr.get("target", "?"), hdr.get("bits", "?"), len(b["hits"]),
         b["n_state"]))
    w("; programme : %d step(s), %d opcode(s) with effects, unmapped: %s"
      % (len(b["program"]), len(b["sem"]["ops"]) - len(
          [o for o in b["sem"]["ops"] if not b["sem"]["ops"][o]["effects"]]),
         ", ".join(("?" if o is None else "0x%02X" % o)
                   for o in b["unmapped"]) or "none"))
    w("; emitted   : %d byte(s) of x86-64 (sha256 %s) + ret"
      % (len(b["code"]), hashlib.sha256(b["code"]).hexdigest()[:16]))
    if orc is not None:
        w("; replay    : %d/%d hits reproduced byte-exactly (%d mismatch)"
          % (orc["ok"], orc["ok"] + orc["bad"], orc["bad"]))
    if run is not None:
        w("; executed  : %s" % run)
    w(";")
    w("; scope: this is the path the trace took - straight line, one state")
    w("; block, effects applied in slot order (REPORT 7.6/7.7).  VM-level")
    w("; branches are not reproduced, and handler bodies are NOT reused: every")
    w("; instruction below was encoded from the effect model.")
    w("")
    w("%s equ rcx%s" % (base, " " * 22) + "; state block pointer (leaf arg)")
    w("")
    for (i, op, size) in b["notes"]:
        effs = b["steps"][i][1]
        hs = b["sem"]["ops"].get(op, {}).get("handlers")
        h = hs.most_common(1)[0][0] if hs else None
        w("vm_%04d:                            ; op %s%s, %d instruction(s)"
          % (i, "?" if op is None else "0x%02X" % op,
             "" if h is None else " -> handler +%X" % h, size))
        if not effs:
            w("    ; no effect observed for this opcode%s"
              % ("" if op is not None else " (opcode could not be read)"))
        for eff in effs:
            out.extend(vmlift.native_lines(eff, width, base))
        w("")
    w("    ret")
    return "\n".join(out) + "\n"


def summary(b, trace, orc=None, got=None, want=None):
    """The one-screen verdict (no listing): what was inlined, and did it run.

    Returns (text, rc) with rc=1 only for a positive mismatch, so callers can
    use the exit code as a pass/fail gate (autodeob.py does).
    """
    lines = ["trace    : %s" % trace,
             "programme: %d step(s), %d opcode(s) with effects, unmapped: %s"
             % (len(b["program"]),
                sum(1 for o in b["sem"]["ops"] if b["sem"]["ops"][o]["effects"]),
                ", ".join(("?" if o is None else "0x%02X" % o)
                          for o in b["unmapped"]) or "none"),
             "code     : %d byte(s) of x86-64, sha256 %s"
             % (len(b["code"]), hashlib.sha256(b["code"]).hexdigest()[:16])]
    if orc:
        lines.append("replay   : %d/%d hit(s) byte-exact (%d mismatch)"
                     % (orc["ok"], orc["ok"] + orc["bad"], orc["bad"]))
    if got is not None:
        lines.append("run      : %d B state -> %s%s"
                     % (len(got), got.hex()[:32],
                        "..." if len(got) > 16 else ""))
    rc = 0
    if want is not None:
        if got is None:
            lines.append("expect   : %d B given but nothing was executed "
                         "(pass --run)" % len(want))
        else:
            d = first_diff(got, want)
            if d is None:
                lines.append("expect   : MATCH - the inlined x86 reproduces the "
                             "VM's own final state (%d B)" % len(want))
            else:
                lines.append("expect   : MISMATCH at +0x%X (got %02X, want %02X)"
                             % (d, got[d], want[d]))
                rc = 1
    return "\n".join(lines) + "\n", rc


def to_json(b, orc=None, run=None, expect=None):
    def key(op):
        return "?" if op is None else "0x%02X" % op
    return {
        "trace": {"target": (b["header"] or {}).get("target"),
                  "bits": (b["header"] or {}).get("bits"),
                  "hits": len(b["hits"]), "with_state": b["n_state"]},
        "width": b["width"], "block": b["block"],
        "program": {"steps": len(b["program"]),
                    "ops": [key(o) for o in b["program"]],
                    "unmapped": [key(o) for o in b["unmapped"]]},
        "semantics": {key(op): o["text"] for op, o in b["sem"]["ops"].items()},
        "code": {"bytes": len(b["code"]),
                 "sha256": hashlib.sha256(b["code"]).hexdigest()},
        "replay_oracle": orc,
        "run": run,
        "expect": None if expect is None else expect.hex(),
    }

    """Offset of the first differing byte, or None when the blocks are equal."""
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i
    return None if len(a) == len(b) else min(len(a), len(b))


# ------------------------------------------------------------- self test ------
def _check(checks, name, ok, detail=""):
    checks.append((name, bool(ok), detail))


# one effect per kind, so every encoder form is executed, not just rendered
FORMS4 = [
    ("add", 0x00, 1), ("add", 0x00, 0x12345678),
    ("sub", 0x04, 3), ("xor", 0x08, 0x1234), ("or", 0x0C, 0x1000),
    ("and", 0x10, 0xFFFF00FF), ("shl", 0x14, 1), ("shl", 0x14, 5),
    ("shr", 0x18, 2), ("not", 0x1C, None), ("neg", 0x20, None),
    ("set", 0x24, 0xDEADBEEF), ("set", 0x24, 0),
    ("addmem", 0x28, 0x00), ("submem", 0x2C, 0x00),
    ("movadd", 0x30, (0x00, 0x04)), ("movsub", 0x34, (0x00, 0x04)),
    ("add", 0x90, 7),                      # disp32 form
    ("set", 0x90, 0xCAFEBABE),             # disp32 + immediate
]

SEED4 = bytes(range(0x40)) + b"\x00" * (0xA0 - 0x40)

# the programme the synthetic trace runs: each op changes a slot that a later
# op reads, so a wrong effect model shows up in the final state and not just in
# the text.  Every op here is *identifiable* from three hits: it keeps changing
# the slot (so `or`/`and`/`shl`-to-zero style saturation never hides a hit) and
# no other operation reproduces the same transitions.  A masked op such as
# `and r, 0xFFFF00FF` is deliberately absent - with three observations the mask
# bits that never mattered are unrecoverable, so vmlift reports "unexplained"
# rather than inventing a mask (the encoder form itself is covered in FORMS4).
SYNTH_PROG = [
    (0x10, ("add", 0x00, 1)), (0x11, ("xor", 0x04, 0x1234)),
    (0x14, ("shl", 0x10, 1)), (0x13, ("movadd", 0x0C, (0x00, 0x04))),
    (0x1E, ("add", 0x08, 5)), (0x12, ("set", 0x08, 0xDEADBEEF)),
    (0x15, ("not", 0x18, None)), (0x16, ("sub", 0x1C, 3)),
    (0x17, ("addmem", 0x20, 0x00)), (0x18, ("neg", 0x24, None)),
    (0x19, ("shr", 0x28, 2)), (0x1B, ("xor", 0x2C, 0x00FF00FF)),
    (0x1F, ("movadd", 0x30, (0x00, 0x04))),
    (0x1C, ("submem", 0x34, 0x00)),
    (0x1D, ("movsub", 0x38, (0x00, 0x04))),
]


def _synth_trace(path, reps=3):
    """Write a trace whose hits carry the before/after block per opcode."""
    state = SEED4
    hits = []
    for _r in range(reps):
        for op, eff in SYNTH_PROG:
            after = vmlift.replay([eff], state, 4)
            hits.append({"kind": "hit", "seq": len(hits) + 1, "site": 0x1000,
                         "site_in_module": 0x1000, "target": 0x2000 + op,
                         "target_in_module": 0x2000 + op,
                         "regs": {"eax": op}, "eflags": 0x246, "thread": 1,
                         "steps": [[0x2000 + op, "4883c0"]],
                         "mem_before": state.hex(), "mem_after": after.hex()})
            state = after
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"kind": "header", "target": "synthetic",
                            "bits": 64}) + "\n")
        for rec in hits:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
    return hits, state



def selftest():
    import os
    import tempfile
    checks = []
    can_run = sys.platform == "win32"

    # 1. every encoder form: encode, execute, compare with the effect model
    for eff in FORMS4:
        name = "%s +0x%X" % (eff[0], eff[1])
        code, _ = assemble([(0x99, [eff])], 4, len(SEED4))
        want = vmlift.replay([eff], SEED4, 4)
        if not can_run:
            _check(checks, "encode+run " + name, True, "skipped (not Windows)")
            continue
        d = first_diff(run_code(code, SEED4, 64), want)
        _check(checks, "encode+run " + name, d is None,
               "ok" if d is None else "byte 0x%X differs" % d)

    # 2. qword slots, including the movabs immediate imm32 cannot carry
    seed8 = bytes(range(0x40)) + b"\x00" * 0x40
    for eff in [("set", 0x00, 0x123456789ABCDEF0), ("add", 0x08, 1),
                ("movadd", 0x10, (0x00, 0x08)), ("shl", 0x18, 3),
                ("not", 0x20, None)]:
        name = "qword %s +0x%X" % (eff[0], eff[1])
        code, _ = assemble([(0x99, [eff])], 8, len(seed8))
        want = vmlift.replay([eff], seed8, 8)
        if not can_run:
            _check(checks, name, True, "skipped (not Windows)")
            continue
        d = first_diff(run_code(code, seed8, 64), want)
        _check(checks, name, d is None,
               "ok" if d is None else "byte 0x%X differs" % d)

    # 3. a whole programme from a synthetic trace: derive -> inline -> execute
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    try:
        hits, final = _synth_trace(path)
        b = build(path, "reg:eax", 0xFF, 0, 4)
        orc = vmlift.verify(b["sem"], b["hits"], "reg:eax", 0xFF, 0, 4)
        _check(checks, "programme reconstructed from the trace",
               b["program"] == [h["regs"]["eax"] for h in hits],
               "%d step(s), %d opcode(s)" % (len(b["program"]),
                                            len(b["sem"]["ops"])))
        _check(checks, "seed/expect taken from the trace's snapshots",
               b["seed"] == SEED4 and b["expect"] == final,
               "%d B seed, %d B expect" % (len(b["seed"]), len(b["expect"])))
        _check(checks, "vmlift replay oracle covers every hit",
               orc["bad"] == 0 and orc["ok"] == len(hits),
               "%d/%d" % (orc["ok"], len(hits)))
        _check(checks, "no opcode silently dropped",
               not b["unmapped"],
               ", ".join("0x%02X" % o for o in b["unmapped"]) or "none")
        if can_run:
            got = run_code(b["code"], b["seed"], 64)
            d = first_diff(got, final)
            _check(checks, "inlined x86 reproduces the VM's final state",
                   d is None, "ok, %d byte(s) of code" % len(b["code"])
                   if d is None else "byte 0x%X differs" % d)
            _check(checks, "inlined x86 == reference model (replay_steps)",
                   first_diff(got, replay_steps(b["steps"], b["seed"], 4)) is None)
        else:
            _check(checks, "inlined x86 reproduces the VM's final state", True,
                   "skipped (not Windows)")
        txt = render(b, "vmregs", orc, "synthetic")
        _check(checks, "listing has one block per step",
               txt.count("\nvm_") == len(b["program"]) and "    ret" in txt,
               "%d block(s)" % txt.count("\nvm_"))
        js = to_json(b, orc)
        _check(checks, "json carries the code hash",
               js["code"]["sha256"] == hashlib.sha256(b["code"]).hexdigest())
    finally:
        os.unlink(path)

    # 4. guards: a slot outside the state block is refused before execution
    try:
        assemble([(0x10, [("add", 0x3E, 1)])], 4, 0x40)
        _check(checks, "slot outside the block is refused", False, "no error")
    except EncodeError as exc:
        _check(checks, "slot outside the block is refused", True, str(exc)[:44])

    # 5. an opcode the trace gave no effects for is reported, not invented
    one = [("add", 0, 1)]
    b2 = {"header": {"bits": 64}, "hits": [{}], "n_state": 0, "width": 4,
          "sem": {"ops": {0x10: {"effects": one, "text": ["x"]}}},
          "program": [0x10, 0x99], "unmapped": [0x99],
          "steps": [(0x10, one), (0x99, [])], "block": 0,
          "code": assemble([(0x10, one)], 4, 0)[0],
          "notes": [(0, 0x10, 3), (1, 0x99, 0)]}
    t2 = render(b2, "vmregs")
    _check(checks, "unmapped opcode emitted as a comment, not code",
           "0x99" in t2 and "no effect observed" in t2)

    bad = 0
    for name, ok, detail in checks:
        print("  [%s] %-44s %s" % ("PASS" if ok else "FAIL", name, detail))
        bad += 0 if ok else 1
    print("selftest: %s (%d/%d)" % ("PASS" if not bad else "FAIL",
                                    len(checks) - bad, len(checks)))
    return 0 if not bad else 1




# ------------------------------------------------------------------- main -----
def _hex(s, what):
    try:
        return bytes.fromhex(s.replace(" ", ""))
    except ValueError:
        raise SystemExit("error: %s is not hex" % what)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or any(x in ("-h", "--help") for x in args):
        print(__doc__.strip())
        return 0 if args else 2
    ap = argparse.ArgumentParser(add_help=False,
                                 description="inline a traced VM programme into x86-64")
    ap.add_argument("trace", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--opcode-from", default="reg:eax",
                    help="reg:NAME (default reg:eax) or mem (ctx_ptr bytes)")
    ap.add_argument("--mask", type=lambda s: int(s, 0), default=0xFF)
    ap.add_argument("--shift", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--sem-width", type=int, default=4, metavar="N",
                    help="VM state slot width, 4 or 8 (default 4)")
    ap.add_argument("--ops", default=None, metavar="LIST",
                    help="inline this opcode list (0x10,0x11,...) instead of "
                         "the trace order")
    ap.add_argument("--max-ops", type=int, default=0, metavar="N",
                    help="inline at most N steps of the traced programme")
    ap.add_argument("--block", type=lambda s: int(s, 0), default=0, metavar="B",
                    help="size of the VM state block (default: snapshot size)")
    ap.add_argument("--seed", default=None, metavar="HEX",
                    help="state block to start from (default: the trace's "
                         "first snapshot)")
    ap.add_argument("--expect", default=None, metavar="HEX",
                    help="final state to compare against")
    ap.add_argument("--expect-from-trace", action="store_true",
                    help="compare against the trace's last snapshot")
    ap.add_argument("--run", action="store_true",
                    help="execute the emitted code on a copy of the seed state")
    ap.add_argument("--base", default="vmregs", metavar="NAME",
                    help="name used for the state block in the listing")
    ap.add_argument("--asm-out", default=None, metavar="ASM")
    ap.add_argument("--blob-out", default=None, metavar="BIN")
    ap.add_argument("--json", default=None, metavar="JSON")
    ap.add_argument("--out", default=None, metavar="TXT")
    a = ap.parse_args(args)
    if a.selftest:
        return selftest()
    if not a.trace:
        print(__doc__.strip())
        return 2
    if a.sem_width not in (4, 8):
        raise SystemExit("error: --sem-width must be 4 or 8")
    ops = None
    if a.ops is not None:
        try:
            ops = [int(t, 0) for t in a.ops.replace(" ", "").split(",") if t]
        except ValueError:
            raise SystemExit("error: --ops wants a comma-separated opcode list")
    b = build(a.trace, a.opcode_from, a.mask, a.shift, a.sem_width, ops,
              a.max_ops or None, a.block)
    if not b["program"]:
        raise SystemExit("%s: no hit carried an opcode (--opcode-from %s)"
                         % (a.trace, a.opcode_from))

    seed = _hex(a.seed, "--seed") if a.seed else b["seed"]
    if a.seed and seed:                          # re-check against this block
        b["code"], b["notes"] = assemble(b["steps"], a.sem_width, len(seed))
        b["block"] = len(seed)
    want = _hex(a.expect, "--expect") if a.expect else None
    if want is None and a.expect_from_trace:
        want = b["expect"]
    got = None
    if a.run:
        if seed is None:
            raise SystemExit("%s: no state snapshots in the trace - take it with "
                             "`vmtrace --until-return --snapshot N`, or pass "
                             "--seed" % a.trace)
        if want is not None and len(want) != len(seed):
            raise SystemExit("error: seed is %d B but expectation is %d B"
                             % (len(seed), len(want)))
        got = run_code(b["code"], seed,
                       int((b["header"] or {}).get("bits", 64) or 64))
    orc = vmlift.verify(b["sem"], b["hits"], a.opcode_from, a.mask, a.shift,
                        a.sem_width)

    txt = render(b, a.base, orc,
                 None if got is None else "ran on %d B of state" % len(got))
    block, rc = summary(b, a.trace, orc, got, want)
    report = txt.rstrip() + "\n\n" + block
    sys.stdout.write(report)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(report)
    if a.asm_out:
        with open(a.asm_out, "w", encoding="utf-8") as f:
            f.write(txt)
    if a.blob_out:
        with open(a.blob_out, "wb") as f:
            f.write(b["code"])
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(to_json(b, orc, None if got is None else got.hex(), want),
                      f, indent=1, sort_keys=True)
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except EncodeError as exc:          # a slot outside the block, bad imm, ...
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)

