"""Standalone (Ghidra-free) driver for GhidrOrean's Oreans VM bytecode decoder.

GhidrOrean's xrkdsm.py decodes Oreans "RISC/CISC" VM bytecode but is written for
Ghidra's Jython. Only xrkutil.py needs the Ghidra script context (`from __main__
import *`), so with a couple of py3 shims the decoder is usable on a *dumped /
unpacked* image from plain CPython.

Usage:
    python oreandec.py <pe-image> --section .vlizer [--max 0x400] [--out list.txt]

Note: the section has to be DECRYPTED / DECOMPRESSED in memory first (dump it
from the live process). On a protected file straight from disk the bytes are
compressed+encrypted, so the listing is meaningless by construction. The tool
will report that by itself (invalid opcodes / zero continuation).
"""
import argparse
import collections
import collections.abc
import contextlib
import io
import os
import sys

# --- py3 shims for the Jython-era helper modules -----------------------------
for _n in ("Sequence", "MutableSequence", "Mapping", "MutableMapping", "Iterable"):
    if not hasattr(collections, _n):
        setattr(collections, _n, getattr(collections.abc, _n))
for _n in ("ConfigParser",):
    if _n not in sys.modules:
        try:
            import configparser
            sys.modules[_n] = configparser
        except ImportError:
            pass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def _find_ghidrorean(start):
    """Locate the GhidrOrean checkout from either layout this file lives in.

    `_analysis/oreandec.py` sits one level below it, `tools/deob/oreandec.py`
    two - and a frozen exe has no checkout at all (the modules are bundled in
    _MEIPASS instead), so the search is bounded and the last guess is the
    original `../GhidrOrean` one.
    """
    d = start
    for _ in range(4):
        if os.path.isfile(os.path.join(d, "xrkdsm.py")):
            return d
        d = os.path.dirname(d)
    return os.path.join(os.path.dirname(start), "GhidrOrean")


GHIDROREAN = _find_ghidrorean(HERE)
if GHIDROREAN not in sys.path:
    sys.path.insert(0, GHIDROREAN)

# PE layout only lives in peread.py, so a tool that just wants to unpack a file
# does not have to import this decoder (nor a GhidrOrean checkout).  The names
# are re-exported here because `oreandec` is the module the rest of the toolbox
# already asks for them.
from peread import SEC, SEC_FAMILY, load_pe, pick_section  # noqa: E402,F401

import xrkdsm  # noqa: E402

# Upstream xrkdsm.py references OP_F30F1x but xrktbl.py (before our fix) defined
# it as OP_F30f1x -> NameError on any `F3 0F 1x` byte pair. Keep a runtime alias
# so the tools work against an unpatched checkout too.
if not hasattr(xrkdsm, "OP_F30F1x") and hasattr(xrkdsm, "OP_F30f1x"):
    xrkdsm.OP_F30F1x = xrkdsm.OP_F30f1x


def decode_range(data, rva, count, out, stats=None):
    off = 0
    bad = 0
    lines = 0
    while off < count:
        # xrkdsm prints diagnostics on stdout for unknown operand encodings;
        # keep the listing clean by muting them.
        with contextlib.redirect_stdout(io.StringIO()):
            size, rki = xrkdsm.XrkDecode(data[off:off + 32] + b"\0" * 32)
            if not size or size > 15:
                bad += 1
                out.write("%08X  db %02X                 ; invalid\n" % (rva + off, data[off] & 0xFF))
                off += 1
                continue
            txt = None
            try:
                txt = xrkdsm.XrkText(rki)
            except Exception:
                txt = None
        if txt is None:
            bad += 1
            out.write("%08X  %-24s ; decode failed (ID %04X)\n"
                      % (rva + off, data[off:off + size].hex(), rki.ID))
            off += size
            continue
        if rki.ID in (xrkdsm.OP_CALL, xrkdsm.OP_JMP) and rki.operand[0].TID() == xrkdsm.TID_VAL:
            txt += "  ; -> %08X" % ((rva + off + size + rki.operand[0].value) & 0xFFFFFFFF)
        out.write("%08X  %-24s %s\n" % (rva + off, data[off:off + size].hex(), txt))
        if stats is not None:
            stats[txt.split()[0]] = stats.get(txt.split()[0], 0) + 1
        off += size
        lines += 1
    return lines, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--section", default=None,
                    help="section holding the payload "
                         "(default: first Oreans section present)")
    ap.add_argument("--raw", action="store_true",
                    help="treat image as a raw binary; --rva becomes a file offset")
    ap.add_argument("--rva", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0x200)
    ap.add_argument("--out", default=None)
    ap.add_argument("--stats", type=int, default=0,
                    help="also print a top-N mnemonic histogram")
    a = ap.parse_args()

    if a.raw:
        d = open(a.image, "rb").read()
        base, secs = 0, {"raw": dict(va=0, vs=len(d), raw=0, rs=len(d))}
        a.section = "raw"
    else:
        d, base, secs = load_pe(a.image)
        a.section = a.section or pick_section(secs)
    if a.section not in secs:
        print("sections:", ", ".join(sorted(secs)))
        raise SystemExit("%s: section %r not found" % (a.image, a.section))
    s = secs[a.section]
    rva = a.rva or s["va"]
    data = d[s["raw"] + (rva - s["va"]):]
    print("%s  base %08X  %s rva %08X  raw avail %X  requested %X"
          % (a.image, base, a.section, rva, len(data), a.size))

    fh = open(a.out, "w", encoding="utf-8") if a.out else sys.stdout
    stats = {} if a.stats else None
    try:
        lines, bad = decode_range(data, rva, min(a.size, len(data)), fh, stats)
    finally:
        if a.out:
            fh.close()
    print("decoded %d instructions, %d invalid bytes%s"
          % (lines, bad, (" -> " + a.out) if a.out else ""))
    if stats:
        total = float(sum(stats.values())) or 1.0
        print("top %d mnemonics:" % a.stats)
        for k, v in sorted(stats.items(), key=lambda kv: -kv[1])[:a.stats]:
            print("    %-10s %7d  %5.1f%%" % (k, v, v * 100.0 / total))
    if bad and lines and bad > lines:
        print("NOTE: mostly-invalid stream - the section is almost certainly still "
              "compressed/encrypted (packed on disk). Dump it from the running image.")


if __name__ == "__main__":
    main()
