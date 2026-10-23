#!/usr/bin/env python3
"""Statically unpack XIGNCODE *.xem: custom header | x86/x64 LZMA stub | LZMA_Alone.

Header layout is version 1 of Oreans' "vlizer" blob. Field width differs per
build (32-bit: 4-byte fields, 64-bit: 8-byte fields), so instead of hardcoding
offsets we look for two fields whose sum equals the section's SizeOfRawData:

    x3.xem      : csize=0x97773 + stubsz=0x0B46 == 0x982B9   (4-byte fields)
    x3_x64.xem  : csize=0xFDBD6 + stubsz=0x0C1F == 0xFE7F5   (8-byte fields)

The stub is a stock LZMA SDK decoder:
    prop>0xe1 -> error ; pb=prop/45 ; lp=(prop%45)/9 ; lc=prop%9
    probs = 0x300 << (lc+lp)  (+0xE6C for the state struct)
so the payload is LZMA_Alone starting right after the stub (some builds start
1 byte into it because the stub's first byte doubles as the stream's).

Output: a PE whose Oreans section holds the decompressed VM bytecode, ready for
Ghidra + GhidrOrean/Orean.py.

Usage: python unpack.py <in.xem> [out.exe] [--layout raw|head] [--section NAME]
    raw  (default) payload at <section>+0    -> bytecode addr == section RVA + off
    head           stub preserved, payload at <section>+stubsz (mirrors on-disk)
    --section      section holding the blob (default: first of .vlizer .themida
                   .winlicen .oreans .boot that the image actually has)

    python unpack.py --selftest   header + stream detection on a synthetic blob
"""
import os
import struct
import sys

import lzma

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from cli import cli, die, need  # noqa: E402

# PE layout lives in peread (no decoder, no GhidrOrean checkout needed to unpack
# a file); re-export the names so `unpack.SEC` / `unpack.pick_section` keep
# working for callers.
from peread import SEC, SEC_FAMILY, load_pe, section_header_offset  # noqa: E402,F401
from peread import pick_section  # noqa: E402,F401


def find_header(blob):
    """locate (csize, stubsz) in the first 0x40 bytes of a vlizer blob"""
    rs = len(blob)
    for width in (4, 8):
        fmt = "<Q" if width == 8 else "<I"
        vals = {}
        for off in range(0, 0x40, 4):
            if off + width > len(blob):
                break
            v, = struct.unpack_from(fmt, blob, off)
            vals[off] = v
        for a, va in vals.items():
            if not (0 < va < rs):
                continue
            for b, vb in vals.items():
                if a == b or not (0 < vb < 0x1000000):
                    continue
                if va + vb == rs:
                    return a, b, va, vb, width
    return None


def try_stream(blob, stubsz, dsize=None):
    """return (offset, payload) of the first LZMA_Alone stream that decodes"""
    cands = [stubsz + 1, stubsz, stubsz + 5, stubsz + 13]
    for extra in range(0, 0x200):
        cands.append(stubsz + extra)
    seen = set()
    best = None
    for off in cands:
        if off in seen or not (0 < off < len(blob)):
            continue
        seen.add(off)
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            out = dec.decompress(blob[off:])
        except Exception:
            continue
        if not out:
            continue
        if dsize and len(out) == dsize:
            return off, out
        if best is None or len(out) > len(best[1]):
            best = (off, out)
        if off > stubsz + 64 and best:
            break
    return best


def unpack(src, dst, layout="raw", verbose=True, section=None):
    """Unpack one .xem file. Returns a stats dict (or raises SystemExit).

    `section=None` picks the first Oreans section the image actually has
    (see SEC_FAMILY), which is what non-XIGNCODE builds need.
    """
    say = print if verbose else (lambda *a, **k: None)
    d = open(src, "rb").read()
    _, base, secs = load_pe(src)
    if section is None:
        section = pick_section(secs)
    if section not in secs:
        raise SystemExit("%s: no %s section (have: %s)"
                         % (os.path.basename(src), section,
                            ", ".join(sorted(secs)) or "none"))
    s = secs[section]
    shoff, opt, nsec = section_header_offset(d, section)

    blob = d[s["raw"]:s["raw"] + s["rs"]]

    hdr = find_header(blob)
    if not hdr:
        raise SystemExit("%s: no vlizer size-pair header in %s (rawsize %X)"
                         % (os.path.basename(src), section, len(blob)))
    c_off, s_off, csize, stubsz, width = hdr
    say("header: csize(%dB @%X)=%X stubsz(@%X)=%X  sum=%X raw=%X"
        % (width, c_off, csize, s_off, stubsz, csize + stubsz, len(blob)))

    # dsize: any other field that is a plausible decompressed size
    dsize = None
    for off in range(0, 0x40, 4):
        if off in (c_off, s_off):
            continue
        v, = struct.unpack_from("<I", blob, off)
        if v > csize and v % 0x1000 == 0:
            dsize = v
            break
    say("dsize guess: %s" % (("%X" % dsize) if dsize else "?"))

    got = try_stream(blob, stubsz, dsize)
    if not got:
        raise SystemExit("no LZMA_Alone stream found")
    used, payload = got
    say("LZMA_Alone @ %s+%X -> %X bytes (dsize match: %s)"
        % (section, used, len(payload), bool(dsize and len(payload) == dsize)))

    # ---- rebuild the section -------------------------------------------------
    file_align = struct.unpack_from("<I", d, opt + 36)[0] or 0x200
    sect_align = struct.unpack_from("<I", d, opt + 32)[0] or 0x1000
    prefix = blob[:used] if layout == "head" else b""
    new = prefix + payload
    raw_size = (len(new) + file_align - 1) // file_align * file_align
    new = new + b"\0" * (raw_size - len(new))
    vsize = (len(payload) + len(prefix) + sect_align - 1) // sect_align * sect_align

    out = bytearray(d[:s["raw"]])
    out += new
    struct.pack_into("<I", out, shoff + 8, vsize)         # VirtualSize
    struct.pack_into("<I", out, shoff + 16, raw_size)     # SizeOfRawData
    size_of_image = struct.unpack_from("<I", out, opt + 56)[0]
    struct.pack_into("<I", out, opt + 56, max(size_of_image, s["va"] + vsize))
    with open(dst, "wb") as f:
        f.write(bytes(out))
    say("wrote %s (%X bytes)  %s: rva %08X vsize %X rawsize %X"
        % (dst, len(out), section, s["va"], vsize, raw_size))

    return dict(source=src, out=dst, out_size=len(out), section=section,
                rva=s["va"], csize=csize, stubsz=stubsz, width=width,
                dsize=dsize, stream_off=used, payload=len(payload),
                dsize_match=bool(dsize and len(payload) == dsize),
                vsize=vsize, raw_size=raw_size)


def selftest():
    """Prove section picking + header/stream detection without a sample."""
    fails = []

    def check(name, ok, detail=""):
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                              ("  " + str(detail)) if detail else ""))
        if not ok:
            fails.append(name)

    x = dict.fromkeys((".text", ".data"))
    check("pick_section: single family section",
          pick_section(dict(x, **{".themida": 1})) == ".themida")
    check("pick_section: .vlizer preferred over .themida",
          pick_section(dict(x, **{".vlizer": 1, ".themida": 2})) == ".vlizer")
    check("pick_section: no Oreans section -> prefer",
          pick_section(x) == SEC)
    check("pick_section: explicit prefer wins",
          pick_section(dict(x, **{".oreans": 1}), prefer=".oreans") == ".oreans")

    payload = (b"\x60\x8b\x44\x24\x04\x50" * 40)
    stream = lzma.compress(payload, format=lzma.FORMAT_ALONE)
    for width, (c_off, s_off) in ((4, (8, 0x18)), (8, (8, 0x20))):
        stubsz = 0x40
        blob = bytearray(stubsz) + stream
        struct.pack_into("<I", blob, 0, 1)            # version
        fmt = "<Q" if width == 8 else "<I"
        struct.pack_into(fmt, blob, c_off, len(stream))
        struct.pack_into(fmt, blob, s_off, stubsz)
        hdr = find_header(bytes(blob))
        # a 64-bit field pair also matches as two low dwords, so only the
        # offsets are asserted; decoding below proves the layout works
        ok = bool(hdr) and hdr[0] == c_off and hdr[1] == s_off
        check("find_header: %dB fields at %X/%X" % (width, c_off, s_off), ok,
              "got %r" % (hdr,))
        got = try_stream(bytes(blob), stubsz, len(payload))
        check("try_stream: %dB field build decodes" % width,
              bool(got) and got[0] == stubsz and got[1] == payload,
              "off=%s len=%s" % (got[0] if got else "-",
                                 len(got[1]) if got else "-"))

    print("\nselftest: %s (%d/%d)"
          % ("PASS" if not fails else "FAIL", 8 - len(fails), 8))
    return 0 if not fails else 1


def main():
    argv = cli(1, __doc__)
    if argv[0] == "--selftest":
        return selftest()
    layout = "raw"
    section = None
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--layout" or a.startswith("--layout="):
            if "=" in a:
                layout = a.split("=", 1)[1]
            else:
                i += 1
                if i >= len(argv):
                    die("--layout needs a value (raw|head)")
                layout = argv[i]
            if layout not in ("raw", "head"):
                die("--layout must be raw or head, not %r" % layout)
        elif a == "--section" or a.startswith("--section="):
            if "=" in a:
                section = a.split("=", 1)[1]
            else:
                i += 1
                if i >= len(argv):
                    die("--section needs a value (.vlizer, .themida, ...)")
                section = argv[i]
        elif a.startswith("-"):
            die("unknown option %s" % a)
        else:
            positional.append(a)
        i += 1
    need(positional, 1, __doc__)
    src = positional[0]
    dst = positional[1] if len(positional) > 1 else os.path.splitext(src)[0] + "_unpacked.exe"
    unpack(src, dst, layout, section=section)


if __name__ == "__main__":
    sys.exit(main())
