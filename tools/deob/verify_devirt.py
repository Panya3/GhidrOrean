#!/usr/bin/env python3
"""verify_devirt.py - re-check the invariants of an existing devirt run.

Reads the artifacts a previous `devirt.py` run already wrote
(`42_devirt.json` + `50_devirt.exe`) and proves the numbers are self-consistent
and that the patched image was only ever *filled* - nothing in it moved.  Cheap
by design: it never re-decodes the section (that is `structural_check()` inside
devirt.py itself).

    python verify_devirt.py out/corpus        # every build below a root
    python verify_devirt.py out/corpus/x3 -v  # one build, line by line

Exit code 0 = every check passed.  The `-v` lines are what VERIFY.md quotes.
"""
import glob
import json
import os
import sys

import oreandec

TOL = 0.011          # slack for the 2-dp percentages on a ~4 MB section


def _pct(part, whole):
    return 100.0 * part / whole if whole else 0.0


def section_range(pe_path, name):
    """Raw file span of one section, straight from the PE headers."""
    _d, _base, secs = oreandec.load_pe(pe_path)
    s = secs[name]
    return s["raw"], s["raw"] + s["rs"]


def _same_headers(a, b):
    """Headers and section table identical, blob bytes ignored."""
    try:
        _da, ba, sa = oreandec.load_pe(a)
        _db, bb, sb = oreandec.load_pe(b)
    except Exception:
        return False
    return ba == bb and sa == sb


def check_build(build, out):
    with open(os.path.join(build, "42_devirt.json"), encoding="utf-8") as fh:
        st = json.load(fh)
    patched = os.path.join(build, "50_devirt.exe")
    n_ok = [0, 0]                      # [passed, failed]

    def chk(name, ok, detail=""):
        n_ok[0 if ok else 1] += 1
        out.append(("PASS" if ok else "FAIL", build, name, detail))

    # -- the accounting the report quotes -----------------------------------
    by = st.get("removed_by", {})
    ver = st.get("verify", {})
    sec = st["section_bytes"]
    chk("candidates split into cut + reverted",
        st["candidates"] == st["removed"] + st["reverted"],
        "%d = %d + %d" % (st["candidates"], st["removed"], st["reverted"]))
    chk("removed_by sums to removed", sum(by.values()) == st["removed"],
        "%s = %d" % (dict(by), st["removed"]))
    chk("audit proved every cut",
        ver.get("status") == "audit" and ver.get("proven") == st["removed"]
        and ver.get("reverted") == st["reverted"],
        "%s proven=%s reverted=%s" % (ver.get("status"), ver.get("proven"),
                                      ver.get("reverted")))
    chk("kept + removed == reachable",
        st["kept"] + st["removed"] == st["reachable_instrs"],
        "%d + %d = %d" % (st["kept"], st["removed"], st["reachable_instrs"]))
    chk("removed_pct matches",
        abs(st["removed_pct"]
            - _pct(st["removed"], st["reachable_instrs"])) < TOL,
        "%.2f%% of %d reachable" % (st["removed_pct"], st["reachable_instrs"]))
    chk("padding_pct matches",
        abs(st["padding_pct"] - _pct(st["padding_bytes"], sec)) < TOL,
        "%.2f%% = %d bytes" % (st["padding_pct"], st["padding_bytes"]))
    chk("reachable_pct matches",
        abs(st["reachable_pct"] - _pct(st["reachable_bytes"], sec)) < TOL,
        "%.2f%% = %d bytes" % (st["reachable_pct"], st["reachable_bytes"]))
    resid = sec - st["reachable_bytes"] - st["padding_bytes"] - st["undecodable"]
    want = st["unreachable_pct"] * sec / 100.0
    chk("byte partition adds up", abs(resid - want) < TOL * sec,
        "residual %d vs %.0f junk bytes (%.2f%%)"
        % (resid, want, st["unreachable_pct"]))
    chk("structural re-decode ok",
        st["structural"]["status"] == "ok"
        and not st["structural"]["missing"] and not st["structural"]["changed"],
        "%d instrs re-checked" % st["structural"]["checked"])

    # -- the patched image --------------------------------------------------
    if not os.path.exists(patched):
        chk("patched image exists", False, patched)
        return n_ok
    a = open(st["image"], "rb").read()
    b = open(patched, "rb").read()
    lo, hi = section_range(st["image"], st["section"])
    diffs = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    chk("patched image exists", True,
        "%s (%d bytes)" % (os.path.basename(patched), len(b)))
    chk("patched image keeps its size", len(a) == len(b), "%d bytes" % len(a))
    chk("every changed byte is inside %s" % st["section"],
        all(lo <= i < hi for i in diffs),
        "%d changed bytes, section %08X-%08X" % (len(diffs), lo, hi))
    chk("PE headers byte-identical", a[:lo] == b[:lo],
        "all %d bytes before %s unchanged" % (lo, st["section"]))
    chk("every changed byte became 0x90", all(b[i] == 0x90 for i in diffs),
        "%d bytes zeroed out" % len(diffs))
    chk("patched image keeps its PE headers", _same_headers(st["image"], patched),
        "machine/entry/section table unchanged")
    return n_ok


def main(argv):
    roots = [a for a in argv[1:] if not a.startswith("-")] or ["out/corpus"]
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0
    found = []
    for r in roots:
        found.extend(glob.glob(os.path.join(r, "42_devirt.json")))
        found.extend(glob.glob(os.path.join(r, "*", "42_devirt.json")))
    builds = sorted(set(os.path.dirname(p) for p in found))
    if not builds:
        print("no 42_devirt.json under %s - run devirt.py first" % roots)
        return 2
    out = []
    ok = bad = 0
    for b in builds:
        n = check_build(b, out)
        ok += n[0]
        bad += n[1]
        print("%-14s %d/%d checks"
              % (os.path.basename(os.path.abspath(b)), n[0], n[0] + n[1]))
    if "-v" in argv or "--verbose" in argv:
        for status, build, name, detail in out:
            print("%s  %-12s %-42s %s"
                  % (status, os.path.basename(os.path.abspath(build)), name,
                     detail))
    print("total: %d checks, %d failed" % (ok + bad, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
