#!/usr/bin/env python3
"""One entry point for the offline tools - and a drag & drop target.

The three tools in this directory are the implementation; this file only
decides what to run, so a frozen .exe (see build_exe.ps1) has a single entry
point that accepts a dropped file:

    OreanOffline.exe sample.xem            unpack + decode + dejunk
    OreanOffline.exe a.xem b.dll           one output directory per input
    OreanOffline.exe some-folder           every *.xem/*.dll/*.exe inside
    OreanOffline.exe sample.xem --out DIR  artefacts somewhere else
    OreanOffline.exe sample.xem --full     dejunk the whole payload (slow)

Each stage is still available on its own, with its own options:

    OreanOffline.exe unpack sample.xem out.exe [--layout raw|head]
    OreanOffline.exe decode out.exe --size 0x400 [--stats 10]
    OreanOffline.exe dejunk out.exe --rva 0x2FC000 --size 0x2000

Exit code 0 only when every input produced every artefact.  Nothing is
executed: this is the static half of the pipeline (see tools/README.md).
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import defus_offline  # noqa: E402
import unpack_vlizer  # noqa: E402
import xrkdecode  # noqa: E402
from peread import load_pe, pick_section  # noqa: E402

FROZEN = bool(getattr(sys, "frozen", False))
INPUT_EXT = (".xem", ".dll", ".exe", ".tmp", ".bin")
STAGES = ("unpack", "decode", "dejunk")
# The dejunk sweep re-decodes and re-walks everything it covers and is ~6 s per
# 8 KB of bytecode, so a 1.8 MB payload would take hours.  Cover the front of
# the stream by default (same window autodeob.py uses) and let --full opt in.
DEJUNK_WINDOW = 0x2000
SIMPLE = "D"          # Defus.Simple rule set (A..D); matches the other tools
DEADSTORE = True      # also drop MOVs provably overwritten before any read


def run(mod, argv):
    """Call another tool's main() with `argv`, whoever owns sys.argv."""
    old = sys.argv
    sys.argv = [old[0]] + list(argv)
    try:
        rc = mod.main()
    except SystemExit as e:                      # cli.die() / argparse / errors
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    finally:
        sys.argv = old
    return rc or 0


def expand(paths):
    """Files from the command line: drop a folder and get its containers."""
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.lower().endswith(INPUT_EXT):
                    yield os.path.join(p, name)
        else:
            yield p


def dejunk(pe, rva, size, window, out_path):
    """sweep_iter over the first `window` bytes of the payload -> listing.

    defus_offline --sweep only prints totals (its --out is ignored there), so
    the listing is written here, the same way autodeob.py does it.
    """
    data, _base, secs = load_pe(pe)
    s = secs[pick_section(secs)]
    blob = data[s["raw"] + (rva - s["va"]):][:window]
    st = dict(blocks=0, n0=0, kept_total=0)
    t0 = time.time()
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("; dejunk sweep - Defus.Simple(D)%s\n"
                 % (" + deadstore" if DEADSTORE else ""))
        fh.write("; window %X of %X bytes; addresses are RVAs\n"
                 % (len(blob), size))
        for r in defus_offline.sweep_iter(blob, SIMPLE, DEADSTORE, 0):
            st = r
            fh.write("; block +%X   %d -> %d instrs\n"
                     % (r["off"], r["before"], r["kept"]))
            d = r["entry"]
            for i in range(d.count):
                try:
                    txt = defus_offline.xrkdsm.XrkText(d.heap[i].instr)
                except Exception:
                    txt = "; <undecodable>"
                fh.write("%08X\t%s\n" % ((rva + d.heap[i].addr) & 0xFFFFFFFF, txt))
    n0 = st["n0"] or 1
    print("   dejunk: %s - %d blocks, %d -> %d instrs (-%.1f%%), "
          "window %X of %X (%.1fs)"
          % (os.path.basename(out_path), st["blocks"], n0, st["kept_total"],
             (n0 - st["kept_total"]) * 100.0 / n0, len(blob), size,
             time.time() - t0))
    return True


def one(src, outroot, window=DEJUNK_WINDOW):
    """unpack -> decode -> dejunk for a single input.  Returns True on success."""
    stem = os.path.splitext(os.path.basename(src))[0]
    work = os.path.join(outroot or os.path.dirname(os.path.abspath(src)), stem)
    if not os.path.isdir(work):
        os.makedirs(work)
    pe = os.path.join(work, "10_unpacked.exe")
    print("== %s -> %s" % (src, work))

    try:
        st = unpack_vlizer.unpack(src, pe)
    except SystemExit as e:
        print("   unpack: %s" % (e.code if isinstance(e.code, str) else "failed"))
        return False
    rva, size = st["rva"], st["payload"]
    print("   unpack: %s rva %08X, %X bytes of bytecode"
          % (st["section"], rva, size))

    t0 = time.time()
    ok = run(xrkdecode, [pe, "--rva", "0x%X" % rva, "--size", "0x%X" % size,
                         "--out", os.path.join(work, "20_payload.lst")]) == 0
    print("   decode: %s (%.1fs)"
          % ("20_payload.lst" if ok else "failed", time.time() - t0))

    w = size if window is None else min(window, size)
    ok2 = dejunk(pe, rva, size, w, os.path.join(work, "30_dejunk.lst"))
    if w < size:
        print("   (rerun with --full to dejunk the whole payload)")
    return ok and ok2


def main():
    argv = sys.argv[1:]
    pause = FROZEN
    if "--no-pause" in argv:
        pause = False
        argv.remove("--no-pause")
    elif "--pause" in argv:
        pause = True
        argv.remove("--pause")
    try:
        return _main(argv)
    finally:
        if pause and sys.stdin and sys.stdin.isatty():
            try:
                input("\npress Enter to close ...")
            except EOFError:
                pass


def _main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0 if argv else 2

    out, window = None, DEJUNK_WINDOW
    if "--full" in argv:
        window = None
        argv.remove("--full")
    if "--out" in argv:
        i = argv.index("--out")
        if i + 1 >= len(argv):
            print("error: --out needs a directory")
            return 2
        out = argv[i + 1]
        del argv[i:i + 2]

    if argv[0] in STAGES:                        # single stage, own options
        stage, rest = argv[0], argv[1:]
        mod = {"unpack": unpack_vlizer, "decode": xrkdecode,
               "dejunk": defus_offline}[stage]
        return run(mod, rest)

    inputs = list(expand(argv))
    if not inputs:
        print("error: nothing to do")
        return 2
    bad = [p for p in inputs if not os.path.isfile(p)]
    if bad:
        print("error: not a file: %s" % ", ".join(bad))
        return 2
    failed = [p for p in inputs if not one(p, out, window)]
    print("\n%d file(s), %d failed" % (len(inputs), len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
