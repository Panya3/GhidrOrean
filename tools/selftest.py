#!/usr/bin/env python3
"""Self checks for the offline tools in this directory.

    python tools/selftest.py

Every check builds its own inputs, so no sample file is needed:

    peread        section picking + PE header walk
    unpack_vlizer synthetic container -> LZMA_Alone round trip (its own selftest)
    xrkdsm        a fixed 17-byte vector decodes to the expected instructions
    thobfus       the dejunk engine imports on CPython 3 and exposes Defus
    OreanOffline  the drop path: synthetic container -> 10/20/30 artefacts
"""
import contextlib
import io
import lzma
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import peread  # noqa: E402

FAILS = []
TOTAL = [0]


def check(name, ok, detail=""):
    TOTAL[0] += 1
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                          ("  " + str(detail)) if detail else ""))
    if not ok:
        FAILS.append(name)
    return ok


def synth_pe():
    """Smallest PE32+ with one .vlizer section, enough for peread."""
    d = bytearray(0x200)
    struct.pack_into("<I", d, 0x3C, 0x40)              # e_lfanew
    d[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", d, 0x44, 0x8664)            # machine = x86-64
    struct.pack_into("<H", d, 0x46, 1)                 # NumberOfSections
    struct.pack_into("<H", d, 0x54, 0xF0)              # SizeOfOptionalHeader
    opt = 0x40 + 24
    struct.pack_into("<H", d, opt, 0x20B)              # PE32+
    struct.pack_into("<Q", d, opt + 24, 0x140000000)   # ImageBase
    sh = opt + 0xF0
    d[sh:sh + 8] = b".vlizer\0"
    struct.pack_into("<IIII", d, sh + 8, 0x1000, 0x1000, 0x200, 0x200)
    return bytes(d), sh


def synth_container(payload):
    """PE32+ whose .vlizer section holds [stub][LZMA_Alone(payload)].

    Same shape as a real *.xem, so the whole drop path (unpack -> decode ->
    dejunk) can be exercised without shipping a sample.
    """
    stream = lzma.compress(payload, format=lzma.FORMAT_ALONE)
    stubsz = 0x40
    body = bytearray(stubsz) + stream
    struct.pack_into("<I", body, 0, 1)                 # version
    struct.pack_into("<I", body, 8, len(stream))       # csize  (4-byte fields)
    struct.pack_into("<I", body, 0x18, stubsz)         # stub size
    raw = 0x200
    d = bytearray(raw) + bytes(body)
    struct.pack_into("<I", d, 0x3C, 0x40)              # e_lfanew
    d[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", d, 0x44, 0x8664)            # machine = x86-64
    struct.pack_into("<H", d, 0x46, 1)                 # NumberOfSections
    struct.pack_into("<H", d, 0x54, 0xF0)              # SizeOfOptionalHeader
    opt = 0x40 + 24
    struct.pack_into("<H", d, opt, 0x20B)              # PE32+
    struct.pack_into("<Q", d, opt + 24, 0x140000000)   # ImageBase
    sh = opt + 0xF0
    d[sh:sh + 8] = b".vlizer\0"
    struct.pack_into("<IIII", d, sh + 8, len(body), 0x1000, len(body), raw)
    return bytes(d)


# Bytecode taken from a real listing; every instruction is unambiguous.
VECTOR = bytes.fromhex("89fe" "be00040000" "89ef" "89ea" "81eb28000000")
EXPECT = ["MOV ESI,EDI", "MOV ESI,0x400", "MOV EDI,EBP", "MOV EDX,EBP",
          "SUB EBX,0x28"]


def main():
    print("peread")

    x = dict.fromkeys((".text", ".data"))
    check("pick_section: single family section",
          peread.pick_section(dict(x, **{".themida": 1})) == ".themida")
    check("pick_section: .vlizer preferred over .themida",
          peread.pick_section(dict(x, **{".vlizer": 1, ".themida": 2})) == ".vlizer")
    check("pick_section: no Oreans section -> prefer", peread.pick_section(x) == peread.SEC)

    blob, sh = synth_pe()
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(blob)
        path = f.name
    try:
        d, base, secs = peread.load_pe(path)
        check("load_pe: image base", base == 0x140000000, hex(base))
        check("load_pe: sections", sorted(secs) == [".vlizer"], sorted(secs))
        check("load_pe: .vlizer rva/rawsize",
              (secs[".vlizer"]["va"], secs[".vlizer"]["rs"]) == (0x1000, 0x200))
        hoff, opt, nsec = peread.section_header_offset(d, ".vlizer")
        check("section_header_offset", (hoff, nsec) == (sh, 1), (hex(hoff), nsec))
        try:
            peread.section_header_offset(d, ".nope")
            check("section_header_offset: missing section raises", False)
        except SystemExit:
            check("section_header_offset: missing section raises", True)
    finally:
        os.unlink(path)

    print("unpack_vlizer")
    import unpack_vlizer
    check("synthetic container round trip", unpack_vlizer.selftest() == 0)

    print("xrkdsm")
    import xrkdsm
    off, got = 0, []
    while off < len(VECTOR):
        size, rki = xrkdsm.XrkDecode(VECTOR[off:] + b"\0" * 32)
        if not size:
            break
        got.append(xrkdsm.XrkText(rki))
        off += size
    check("17-byte vector decodes", off == len(VECTOR), "consumed %d" % off)
    check("vector text", got == EXPECT, got)

    print("thobfus")
    import thobfus
    check("Defus importable", hasattr(thobfus, "Defus"))

    print("OreanOffline")
    import OreanOffline
    quiet = contextlib.redirect_stdout(io.StringIO())
    with quiet:
        noargs = OreanOffline._main([])
    check("no arguments -> usage, exit 2", noargs == 2, noargs)

    tmp = tempfile.mkdtemp()
    try:
        for name in ("a.xem", "notes.txt", "b.dll"):
            open(os.path.join(tmp, name), "wb").write(b"MZ")
        got = sorted(os.path.basename(p) for p in OreanOffline.expand([tmp]))
        check("dropped folder -> containers only", got == ["a.xem", "b.dll"], got)

        payload = b"\x60\x8b\x44\x24\x04\x50" * 40
        src = os.path.join(tmp, "drop.xem")
        open(src, "wb").write(synth_container(payload))
        with quiet:
            rc = OreanOffline.one(src, tmp)
        work = os.path.join(tmp, "drop")
        made = sorted(f for f in os.listdir(work)) if os.path.isdir(work) else []
        check("drop path: unpack -> decode -> dejunk", rc and made == [
            "10_unpacked.exe", "20_payload.lst", "30_dejunk.lst"], made)
        lst = os.path.join(work, "20_payload.lst")
        body = open(lst, encoding="utf-8").read() if os.path.exists(lst) else ""
        check("drop path: listing has the whole payload",
              body.count("\n") >= 120, "%d lines" % body.count("\n"))

        out2 = os.path.join(tmp, "dec.lst")
        with quiet:
            rc2 = OreanOffline._main(["decode", os.path.join(work, "10_unpacked.exe"),
                                      "--size", "0x10", "--out", out2])
        check("stage passthrough keeps the stage's own --out",
              rc2 == 0 and os.path.exists(out2) and os.path.getsize(out2) > 0,
              "rc=%s" % rc2)
    finally:
        for root_, _dirs, files in os.walk(tmp, topdown=False):
            for name in files:
                os.unlink(os.path.join(root_, name))
            os.rmdir(root_)

    print("\nselftest: %s (%d checks)"
          % ("PASS" if not FAILS else "FAIL, " + ", ".join(FAILS),
             TOTAL[0] - len(FAILS)))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
