#!/usr/bin/env python3
"""vmfix.py - build a tiny, real x64 PE that *is* a bytecode VM, plus the
ground truth for it.  Used by `vmtrace.py --selftest-vm` as a differential
oracle: the map the debugger recovers must equal the map this file built.

Why a synthetic VM and not the sample
    The real payload has anti-debug, needs a throw-away VM, and nobody has the
    opcode map to compare against (that map *is* the thing being recovered).
    Here the opcode -> handler map is known by construction, so a mismatch is a
    bug in the tools, not in the interpretation of the sample.

What the fixture does (one .text section, no imports, never exits)
    entry:  lea rbx,[rip+bytecode] ; lea r12,[rip+table] ; lea r13,[rip+vregs]
    loop:   movzx eax, byte ptr [rbx] ; inc rbx ; test eax,eax ; jz done
            mov rdx, [r12+rax*8]
            jmp rdx                  <-- the indirect-jump site (watched)
    each handler applies one virtual-register op to [r13] and jmps back

The virtual registers are seeded (see VREG_SEED) and hit different slots, so
every handler has an observable, distinguishable effect on memory.  The trace
therefore also carries the ground truth for *semantics*, not just for the
opcode -> handler map: `sem` per handler is what `vmlift --semantics` must
recover from before/after snapshots alone.

Usage:
    python _analysis/vmfix.py --out %TEMP%\\vmfix\\fixvm.exe
    python _analysis/vmfix.py --out ... --json ground.json   # truth only
"""
import json
import os
import struct
import sys

IMAGE_BASE = 0x140000000
CODE_RVA = 0x1000
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
SIZE_OF_IMAGE = 0x2000
SIZE_OF_HEADERS = 0x400

# opcode -> (name, machine code applied to the virtual registers at [r13], sem)
# `sem` is the ground truth for the *level 2* lift (vmlift --semantics): the
# canonical text vmlift must recover from before/after memory snapshots.
# Slots are written so that every effect is observable and *distinguishable*:
#   +0x00 is incremented by op 1, read by op 4 and by op 9
#   +0x10 is shifted by op 5 and read by op 4  -> op 4's delta *varies*, so a
#     plain "add k" cannot fit all hits; only "= [0] + [0x10]" survives, which
#     is also why the model needs a two-source form and not just dst+=src
#   +0x20 is set by op 8 and then incremented from +0x00 by op 9 -> before op 8
#     the slot holds a *different* value every round, which is the only way a
#     constant store can be told apart from an xor/add that happens to fit.
HANDLERS = [
    (1, "vinc0",  b"\x41\xff\x45\x00",                     # inc dword [r13+0]
                  "dword [vm+0x0] += 1"),
    (2, "vdec4",  b"\x41\xff\x4d\x04",                     # dec dword [r13+4]
                  "dword [vm+0x4] -= 1"),
    (3, "vxor8",  b"\x41\x81\x75\x08\x34\x12\x00\x00",     # xor dword [r13+8],0x1234
                  "dword [vm+0x8] ^= 0x1234"),
    (4, "vaddc",  b"\x41\x8b\x45\x00"                      # mov eax,[r13+0]
                  b"\x41\x03\x45\x10"                      # add eax,[r13+0x10]
                  b"\x41\x89\x45\x0c",                     # mov [r13+0xC],eax
                  "dword [vm+0xC] = dword [vm+0x0] + dword [vm+0x10]"),
    (5, "vshl10", b"\x41\xd1\x65\x10",                     # shl dword [r13+0x10],1
                  "dword [vm+0x10] <<= 1"),
    (6, "vnot18", b"\x41\xf7\x55\x18",                     # not dword [r13+0x18]
                  "dword [vm+0x18] = ~dword [vm+0x18]"),
    (7, "vsub3",  b"\x41\x83\x6d\x1c\x03",                 # sub dword [r13+0x1C],3
                  "dword [vm+0x1C] -= 3"),
    (8, "vset20", b"\x41\xc7\x45\x20\xef\xbe\xad\xde",     # [r13+0x20]=0xDEADBEEF
                  "dword [vm+0x20] = 0xDEADBEEF"),
    (9, "vadd20", b"\x41\x8b\x45\x00"                      # mov eax,[r13+0]
                  b"\x41\x03\x45\x20"                      # add eax,[r13+0x20]
                  b"\x41\x89\x45\x20",                     # mov [r13+0x20],eax
                  "dword [vm+0x20] += dword [vm+0x0]"),
]

# initial virtual registers: nothing may be zero where an opcode reads it, and
# they are deliberately unequal so that "set"/"add k" cannot fake an effect.
VREG_SEED = (0x12345678, 0x0000FFFF, 0x00000000, 0x00000000, 0x00010001,
             0x00000000, 0x00000000, 0x00000010, 0x00000000)
VREG_BYTES = 0x40


class _Asm(object):
    """Enough of an assembler for the fixture: labels and relative fixups."""

    def __init__(self):
        self.buf = bytearray()
        self.labels = {}
        self.fix = []                  # (pos, size, label)

    def __len__(self):
        return len(self.buf)

    def label(self, name):
        self.labels[name] = len(self.buf)
        return self.labels[name]

    def raw(self, data):
        self.buf += data

    def rel(self, label, size):
        self.fix.append((len(self.buf), size, label))
        self.buf += b"\0" * size

    def rip(self, label, prefix):
        """lea reg,[rip+label] - prefix is the opcode up to the disp32."""
        self.raw(prefix)
        self.rel(label, 4)

    def jump(self, label):
        self.raw(b"\xe9")
        self.rel(label, 4)

    def resolve(self):
        for pos, size, label in self.fix:
            if label not in self.labels:
                raise SystemExit("vmfix: undefined label %r" % label)
            disp = self.labels[label] - (pos + size)
            self.buf[pos:pos + size] = int(disp).to_bytes(size, "little",
                                                          signed=True)
        self.fix = []


def build_code(repeat=24):
    """(.text blob, ground truth) - code, pointer table, bytecode, vregs."""
    a = _Asm()
    a.label("entry")
    a.rip("bytecode", b"\x48\x8d\x1d")        # lea rbx,[rip+bytecode]
    a.rip("table", b"\x4c\x8d\x25")           # lea r12,[rip+table]
    a.rip("vregs", b"\x4d\x8d\x2d")           # lea r13,[rip+vregs]
    a.label("loop")
    a.raw(b"\x0f\xb6\x03")                    # movzx eax, byte ptr [rbx]
    a.raw(b"\x48\xff\xc3")                    # inc rbx
    a.raw(b"\x85\xc0")                        # test eax,eax
    a.raw(b"\x0f\x84")                        # jz done
    a.rel("done", 4)
    a.raw(b"\x49\x8b\x14\xc4")                # mov rdx,[r12+rax*8]
    a.label("site")
    a.raw(b"\xff\xe2")                        # jmp rdx          <-- the site
    a.label("back")
    a.jump("loop")                            # fallback / handler return
    offs = {}
    for op, _name, code, _sem in HANDLERS:
        offs[op] = len(a)
        a.raw(code)
        a.jump("back")
    while len(a) % 8:
        a.raw(b"\x90")
    a.label("table")
    a.raw(struct.pack("<Q", 0))               # index 0 is never used (opcode 0 = halt)
    for op, _name, _code, _sem in HANDLERS:
        a.raw(struct.pack("<Q", IMAGE_BASE + CODE_RVA + offs[op]))
    a.label("bytecode")
    a.raw(bytes(op for op, _n, _c, _s in HANDLERS) * repeat)
    a.raw(b"\x00")
    while len(a) % 8:
        a.raw(b"\x00")
    a.label("vregs")
    a.raw(struct.pack("<%dI" % len(VREG_SEED), *VREG_SEED))
    a.raw(b"\x00" * (VREG_BYTES - 4 * len(VREG_SEED)))
    a.label("done")
    a.raw(b"\xeb\xfe")                        # jmp $  (never reached here)
    a.resolve()
    gt = {"image_base": IMAGE_BASE, "entry_rva": CODE_RVA,
          "site_rva": CODE_RVA + a.labels["site"],
          "bytecode_rva": CODE_RVA + a.labels["bytecode"],
          "vregs_rva": CODE_RVA + a.labels["vregs"],
          "vregs_bytes": VREG_BYTES,
          "vregs_seed": ["0x%X" % v for v in VREG_SEED],
          "opcodes": len(HANDLERS),
          "handlers": [{"opcode": op, "name": name,
                        "rva": CODE_RVA + offs[op], "sem": sem,
                        "asm": code.hex()} for op, name, code, sem in HANDLERS]}
    gt["semantics"] = {h["opcode"]: h["sem"] for h in gt["handlers"]}
    return bytes(a.buf), gt


def build_pe(blob):
    """A minimal PE32+ around one executable section (no imports needed)."""
    raw = bytearray(SIZE_OF_HEADERS)
    raw[0:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x40)
    raw[0x40:0x44] = b"PE\0\0"
    coff = 0x44
    struct.pack_into("<HHIIIHH", raw, coff,
                     0x8664, 1, 0, 0, 0, 0xF0, 0x0022)   # 1 section, exe
    opt = coff + 20                                        # 0x58
    struct.pack_into("<HBBIIIII", raw, opt, 0x20B, 1, 0, 0, 0, 0, CODE_RVA,
                     CODE_RVA)
    struct.pack_into("<Q", raw, opt + 24, IMAGE_BASE)
    struct.pack_into("<IIHHHHHHIIIIHH", raw, opt + 32,
                     SECTION_ALIGN, FILE_ALIGN,      # Section/File alignment
                     6, 0, 0, 0, 6, 0,               # OS/image/subsystem ver
                     0, SIZE_OF_IMAGE, SIZE_OF_HEADERS,
                     0,                              # CheckSum
                     3, 0)                           # CONSOLE, DllCharacteristics
    struct.pack_into("<QQQQII", raw, opt + 72, 0x100000, 0x1000,
                     0x100000, 0x1000, 0, 16)
    # data directories stay zero: no imports, no relocs -> loads at ImageBase
    sec = opt + 0xF0                                       # 0x148
    raw[sec:sec + 8] = b".text\0\0\0"
    raw_size = (len(blob) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN
    struct.pack_into("<IIIIIIHHI", raw, sec + 8,
                     len(blob), CODE_RVA, raw_size, SIZE_OF_HEADERS,
                     0, 0, 0, 0, 0xE0000020)   # code|exec|read|write (vregs)
    return bytes(raw) + bytes(blob) + b"\0" * (raw_size - len(blob))


def build(path, repeat=24):
    """Write the fixture PE and return its ground truth."""
    blob, gt = build_code(repeat)
    data = build_pe(blob)
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d)
    with open(path, "wb") as f:
        f.write(data)
    gt["path"] = os.path.abspath(path)
    gt["size"] = len(data)
    gt["expect"] = {h["opcode"]: h["rva"] for h in gt["handlers"]}
    return gt


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    out = os.path.join(os.environ.get("TEMP", "."), "vmfix", "fixvm.exe")
    js = None
    repeat = 24
    i = 0
    while i < len(argv):
        k = argv[i]
        if k in ("--out", "-o"):
            i += 1
            out = argv[i]
        elif k == "--json":
            i += 1
            js = argv[i]
        elif k == "--repeat":
            i += 1
            repeat = int(argv[i], 0)
        elif k in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            raise SystemExit("vmfix: unknown option %r" % k)
        i += 1
    gt = build(out, repeat=repeat)
    if js:
        with open(js, "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=1, sort_keys=True)
    print("fixture  : %s (%d bytes)" % (gt["path"], gt["size"]))
    print("image    : base 0x%X  entry +%X  site +%X  bytecode +%X"
          % (gt["image_base"], gt["entry_rva"], gt["site_rva"],
             gt["bytecode_rva"]))
    print("handlers : %d (opcode -> RVA)" % gt["opcodes"])
    for h in gt["handlers"]:
        print("   0x%02X -> +%-5X %-6s %-46s %s"
              % (h["opcode"], h["rva"], h["name"], h["sem"], h["asm"]))
    print("next     : python _analysis\\vmtrace.py --selftest-vm")
    return 0


if __name__ == "__main__":
    sys.exit(main())
