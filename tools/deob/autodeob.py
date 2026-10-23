#!/usr/bin/env python3
"""autodeob.py - one-shot ("drop it in and walk away") deobfuscator for the
Oreans / XIGNCODE *.xem family handled by this repo.

Runs every stage we have, in order, and writes a machine-readable + human
readable report next to the artifacts:

    1. sniff     PE? which scheme? entropy, sections, imagebase
    2. unpack    .vlizer header -> LZMA_Alone -> rebuilt PE (unpack.py)
    3. decode    Oreans instruction stream -> listing + mnemonic histogram
    4. dejunk    Defus.Simple + deadstore sweep -> dejunked listing + stats
    5. cfg       whole-payload CFG + liveness DCE -> 40_cfg.lst (cfgpass.py)
    5b. devirt   whole-section native recovery -> 41_devirt.lst + 42_devirt.json
                 + 50_devirt.exe (devirt.py): padding/data split, CFG from real
                 entry points, proof-checked cuts NOPped in place, re-decode check
    6. trace     optional: fold a vmtrace.jsonl (from vmtrace.py) into
                 41_vm.txt + 41_lift.asm (vmlift.py) - the dynamic half,
                 42_native.asm and 43_inline.asm/43_inline.txt
                 (vminline.py: the observed programme as real x86-64,
                 assembled from the effect model and executed)
    6b. run      optional (--run HOST.EXE): take that trace yourself - the
                 bundled tracer starts HOST.EXE under the debugger, so the
                 whole chain lives in one process (and in the .exe) with no
                 Ghidra and no second interpreter.  This is the only path that
                 executes anything, and it is never taken unless asked for.
    7. report    <out>/<stem>/result.json  and  <out>/SUMMARY.md

Nothing is executed by default: no sample is run, no Ghidra/Jython is required -
the whole chain is pure CPython 3 (see REPORT.md sections 1-3 and 7).  `--trace`
folds a file produced earlier; `--run` drives the same tracer in-process.
`--selftest-vm` proves that half on a synthetic VM, which is the only binary it
will ever launch on its own.

Usage (from this file's directory, or give it the full path):
    python autodeob.py XIGNCODE                    # whole directory
    python autodeob.py XIGNCODE/x3.xem             # single file
    python autodeob.py "XIGNCODE/*.xem" --out out2
    python autodeob.py XIGNCODE/x3.xem --dejunk-size 0   # full payload
    python autodeob.py sample.xem --run Host.exe    # + live trace
    python autodeob.py --selftest-vm                # dynamic half, no sample

Drag & drop: use deob.cmd in the repo root (accepts files and folders).
"""
import argparse
import glob
import hashlib
import json
import math
import os
import struct
import sys
import time

FROZEN = bool(getattr(sys, "frozen", False))
# PyInstaller onefile runs from a temp dir: anchor outputs next to the .exe,
# not inside _MEIPASS (which is deleted on exit).
HERE = os.path.dirname(os.path.abspath(sys.executable if FROZEN else __file__))
if not FROZEN and HERE not in sys.path:
    sys.path.insert(0, HERE)

import defus as dz          # noqa: E402  (puts GhidrOrean on sys.path)
import oreandec            # noqa: E402
import cfgpass as dz_cfg   # noqa: E402  (CFG + liveness DCE; reuses defus shims)
import unpack as unpackmod  # noqa: E402

SEC = unpackmod.SEC
DEFAULT_OUT = os.path.join(HERE, "out", "auto")


def entropy(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = float(len(b))
    h = 0.0
    for v in c:
        if v:
            p = v / n
            h -= p * math.log(p, 2)
    return h


def pe_machine(d):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    m = struct.unpack_from("<H", d, e + 4)[0]
    return {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(m, "0x%04X" % m)


def sniff(path):
    """Cheap, non-fatal description of an input file."""
    b = open(path, "rb").read()
    info = dict(file=path, size=len(b),
                sha256=hashlib.sha256(b).hexdigest()[:16],
                entropy=round(entropy(b), 3))
    if b[:2] != b"MZ":
        info["kind"] = "not-pe"
        if b"stPust" in b[:0x40]:
            off = b[:0x40].index(b"stPust")
            info["container"] = ("Oreans container (xmag/xnina, 'stPust' "
                                 "@0x%X) - no PE image inside" % off)
        return info
    try:
        _, base, secs = oreandec.load_pe(path)
    except SystemExit as e:
        info["kind"] = "bad-pe"
        info["error"] = str(e)
        return info
    info["kind"] = "pe"
    info["machine"] = pe_machine(b)
    info["imagebase"] = base
    info["sections"] = {n: dict(rva=v["va"], vsize=v["vs"],
                                raw=v["raw"], rawsize=v["rs"])
                        for n, v in secs.items()}
    sec = unpackmod.pick_section(secs)
    info["section"] = sec if sec in secs else None
    if info["section"]:
        s = secs[sec]
        blob = b[s["raw"]:s["raw"] + s["rs"]]
        if unpackmod.find_header(blob):
            info["scheme"] = "vlizer"
        elif ".boot" in secs or ".themida" in secs:
            info["scheme"] = "themida-boot"
        else:
            info["scheme"] = "vlizer-no-header"
    elif info["entropy"] > 7.5:
        info["scheme"] = "packed-unknown"
    else:
        info["scheme"] = "plain-pe"
    return info


def quick_decode_rate(data, limit=0x400):
    """Fraction of bytes that decode as Oreans instructions (0..1)."""
    off = 0
    n = min(len(data), limit)
    good = bad = 0
    while off < n:
        size, _ = dz.decode_at(data, off)
        if not size or size > 15:
            bad += 1
            off += 1
        else:
            good += 1
            off += size
    return good / float(good + bad) if (good + bad) else 0.0


def payload_of(pe_path):
    """(data, rva, count) of the Oreans payload inside a PE image."""
    d, _base, secs = oreandec.load_pe(pe_path)
    s = secs[unpackmod.pick_section(secs)]
    data = d[s["raw"]:s["raw"] + s["rs"]]
    return data, s["va"], min(s["vs"], len(data))


# ----------------------------------------------------------------- stages ----
def stage_unpack(path, info, workdir, res):
    """Decompress the Oreans section into <workdir>/10_unpacked.exe."""
    if info.get("scheme") not in ("vlizer", "vlizer-no-header"):
        res["unpack"] = dict(status="skipped",
                             reason="scheme=%s (not handled by this pipeline)"
                                    % info.get("scheme"))
        return None

    dst = os.path.join(workdir, "10_unpacked.exe")
    if info["scheme"] == "vlizer":
        try:
            st = unpackmod.unpack(path, dst, "raw", verbose=False,
                                  section=info.get("section"))
        except SystemExit as e:
            res["unpack"] = dict(status="failed", reason=str(e))
            return None
        st["status"] = "ok"
        st.pop("source", None)
        res["unpack"] = st
        return dst

    # the Oreans section exists but the size-pair header is gone -> probably
    # already unpacked. Trust that only if the stream actually decodes.
    data, _rva, _n = payload_of(path)
    rate = quick_decode_rate(data)
    res["unpack"] = dict(status="already-unpacked", decode_rate=round(rate, 4))
    return path if rate > 0.5 else None


def stage_decode(pe_path, workdir, res, opts):
    """Full Oreans listing + histogram. Returns (data, rva, count) or None."""
    import io
    data, rva, count = payload_of(pe_path)
    res["payload"] = dict(rva=rva, bytes=count)
    stats = {}
    lst = os.path.join(workdir, "20_payload.lst")
    t0 = time.time()
    if opts.no_listing:
        lines, bad = oreandec.decode_range(data, rva, count, io.StringIO(), stats)
    else:
        with open(lst, "w", encoding="utf-8") as fh:
            lines, bad = oreandec.decode_range(data, rva, count, fh, stats)
    total = float(lines) or 1.0
    top = sorted(stats.items(), key=lambda kv: -kv[1])[:12]
    res["decode"] = dict(instructions=lines, invalid_bytes=bad,
                         invalid_pct=round(bad * 100.0 / total, 4),
                         seconds=round(time.time() - t0, 1),
                         top=[dict(mnemonic=k, count=v,
                                   pct=round(v * 100.0 / total, 2))
                              for k, v in top])
    if not opts.no_listing:
        res["decode"]["listing"] = lst
        res["decode"]["listing_bytes"] = os.path.getsize(lst)
    elif os.path.exists(lst):
        # --no-listing means "do not write", not "pretend it does not exist":
        # a listing from an earlier run is still the same input (dir is reused
        # only when sha256 matches), so record it instead of leaving a hole.
        res["decode"]["listing"] = lst
        res["decode"]["listing_bytes"] = os.path.getsize(lst)
        res["decode"]["listing_reused"] = True
    return data, rva, count


def stage_cfg(data, rva, workdir, res, opts):
    """Whole-payload CFG + liveness DCE -> 40_cfg.lst."""
    window = opts.cfg_size or len(data)
    window = min(window, len(data))
    lst = os.path.join(workdir, "40_cfg.lst")
    got = dz_cfg.run(data, rva, limit=window, rounds=opts.cfg_rounds,
                     verify_trials=opts.cfg_verify)
    st = got["stats"]
    lines = ["; cfgpass - CFG + liveness + dead-code elimination",
             "; window %X of %X bytes; Simple(%s) peephole is a separate stage"
             % (window, len(data), opts.simple),
             "; %d instrs in, %d out (-%.2f%%), %d blocks, %d unknown edges"
             % (st["instructions"],
                st["instructions"] - st["removed"], st["removed_pct"],
                st["blocks"], st["unknown_edges"]),
             "; addresses are RVAs"]
    if st.get("verify"):
        v = st["verify"]
        lines.insert(3, "; oracle: %d blocks x %d random states, %d failures "
                        "(%d skipped)" % (v["tested"], v["trials"],
                                          v["failures"], v["skipped"]))
    body = dz_cfg.render(got["kept"], set(), rva, lines)
    with open(lst, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body) + "\n")
    st = dict(st)
    st.update(simple=opts.simple, window=window,
              window_pct=round(window * 100.0 / len(data), 2),
              listing=lst, listing_lines=len(body))
    res["cfg"] = st


def stage_devirt(pe_path, workdir, res, opts):
    """Native recovery on the whole section -> 41_devirt.lst / 50_devirt.exe.

    Unlike the two stages above this one works on the *image*, not on a decoded
    window: it re-synchronises a decoder over the whole section, separates
    padding/data from code, walks the CFG from real entry points, and NOPs only
    what a local proof allows - then re-decodes the patched section to show the
    instruction grid is untouched.
    """
    t0 = time.time()
    try:
        import devirt
    except Exception as e:                  # no capstone / no wheel: stay useful
        res["devirt"] = dict(status="unavailable",
                             reason="%s: %s" % (type(e).__name__, e))
        return res["devirt"]
    try:
        st = devirt.run(pe_path, workdir, write_pe=not opts.devirt_no_pe,
                        write_listing=True, verbose=False)
    except Exception as e:
        res["devirt"] = dict(status="failed",
                             reason="%s: %s" % (type(e).__name__, e),
                             seconds=round(time.time() - t0, 1))
        return res["devirt"]
    res["devirt"] = dict(
        status="ok",
        section=st["section"], section_bytes=st["section_bytes"],
        instructions=st["instructions"], undecodable=st["undecodable"],
        padding_pct=st["padding_pct"], padding_runs=st["padding_runs"],
        seeds=st["seeds"], reachable_instrs=st["reachable_instrs"],
        reachable_pct=st["reachable_pct"],
        unreachable_pct=st["unreachable_pct"],
        candidates=st["candidates"], removed=st["removed"],
        removed_pct=st["removed_pct"], reverted=st["reverted"],
        removed_by=st["removed_by"], kept=st["kept"],
        indirect=st["indirect"], structural=st["structural"],
        listing=st.get("listing"), patched_pe=st.get("patched_pe"),
        seconds=round(time.time() - t0, 1))
    return res["devirt"]


def stage_trace(workdir, res, opts):
    """Fold a vmtrace.jsonl into 41_vm.txt + 41_lift.asm (no execution)."""
    import vmlift                       # stdlib-only; lazy = optional in .exe
    header, hits = vmlift.load(opts.trace)
    got = vmlift.analyse(hits, opts.trace_opcode_from, opts.trace_mask, 0)
    txt = vmlift.render(got, header, opts.trace_opcode_from)
    rep = os.path.join(workdir, "41_vm.txt")
    with open(rep, "w", encoding="utf-8") as fh:
        fh.write(txt)
    asm = os.path.join(workdir, "41_lift.asm")
    with open(asm, "w", encoding="utf-8") as fh:
        fh.write(vmlift.render_asm(got, int(header.get("bits", 32) or 32)))
    # update, not replace: with --run the keys from the tracing stage stay
    res.setdefault("vm", {})
    res["vm"].update({"trace": opts.trace, "bits": header.get("bits"),
                      "hits": got["hits"], "sites": len(got["sites"]),
                      "monomorphic": got["mono"], "handlers": got["handlers"],
                      "opcodes": got["opcodes"], "conflicts": len(got["conflicts"]),
                      "report": rep, "asm": asm})
    # level 2: what each opcode does to VM state - only possible when the trace
    # was taken with --until-return --snapshot N (vmtrace.py); otherwise the
    # trace has no before/after state and this stage quietly stays at level 1.5
    sem = vmlift.derive(hits, opts.trace_opcode_from, opts.trace_mask, 0, 4)
    if not sem["ops"]:
        return
    orc = vmlift.verify(sem, hits, opts.trace_opcode_from, opts.trace_mask, 0, 4)
    nat = os.path.join(workdir, "42_native.asm")
    with open(nat, "w", encoding="utf-8") as fh:
        fh.write(vmlift.render_semantics(sem, got, orc))
    res["vm"].update({
        "native": nat,
        "sem_effects": sem["effect_ops"],
        "semantics": {("0x%02X" % op): " ; ".join(o["text"])
                      for op, o in sem["ops"].items()},
        "sem_oracle": {"ok": orc["ok"], "bad": orc["bad"],
                       "skipped": orc["skipped"], "fails": orc["fails"]}})
    # level 2 devirtualisation: inline the *observed* programme into real x86-64
    # The seed is the trace's first snapshot and the expectation is its last, so
    # this is a differential test against the VM itself, not a re-simulation.
    try:
        import vminline                 # stdlib-only; lazy = optional in .exe
        inl = vminline.build(opts.trace, opts.trace_opcode_from,
                             opts.trace_mask, 0, 4)
    except Exception as exc:            # noqa: BLE001 - optional stage
        res["vm"]["inline_error"] = str(exc)   # recorded, not silent
        return
    if not inl["program"] or not inl["seed"]:
        return
    iorc = vmlift.verify(inl["sem"], inl["hits"], opts.trace_opcode_from,
                         opts.trace_mask, 0, 4)
    got = None
    try:
        got = vminline.run_code(inl["code"], inl["seed"],
                                int((inl["header"] or {}).get("bits", 64) or 64))
    except Exception:                   # noqa: BLE001 - not Windows / no exec
        got = None
    body, irc = vminline.summary(inl, opts.trace, iorc, got, inl["expect"])
    asm3 = os.path.join(workdir, "43_inline.asm")
    with open(asm3, "w", encoding="utf-8") as fh:
        fh.write(vminline.render(inl, "vmregs", iorc))
    rep3 = os.path.join(workdir, "43_inline.txt")
    with open(rep3, "w", encoding="utf-8") as fh:
        fh.write(body)
    res["vm"].update({
        "inline": asm3, "inline_report": rep3,
        "inline_steps": len(inl["program"]), "inline_bytes": len(inl["code"]),
        "inline_sha256": hashlib.sha256(inl["code"]).hexdigest(),
        "inline_ran": got is not None,
        "inline_ok": None if got is None else (irc == 0)})


def stage_run(workdir, res, opts, payload_pe):
    """Run the bundled tracer on a host process and return its jsonl path.

    This is the only place in autodeob that starts anything, and it is reached
    only through --run: the static half stays static unless the caller says
    otherwise.  vmtrace.py is shipped inside the .exe, so recovering the
    opcode -> handler map needs neither Ghidra nor a second interpreter - but
    it does need the *host* binary that executes the VM (the product's own
    .exe), because the dispatch table only exists while that process runs.

    A bitness mismatch is reported, never papered over: a debugger cannot cross
    WOW64, and a 64-bit .exe cannot debug a 32-bit target (build the 32-bit
    one with `build_exe.ps1 -Python py -3.11-32`).
    """
    import shlex
    import vmtrace

    target = opts.run
    out = os.path.join(workdir, "vmtrace.jsonl")
    res.setdefault("vm", {}).update({"run": target, "run_trace": out,
                                     "run_status": "pending"})
    if not os.path.isfile(target):
        why = "%s: no such file" % target
        res["vm"].update(run_status="failed", run_reason=why)
        print("   trace: failed (%s)" % why)
        return None
    try:
        bits = vmtrace._pe_bits(target)
    except (SystemExit, OSError) as exc:
        res["vm"].update(run_status="failed", run_reason=str(exc))
        print("   trace: failed (%s)" % exc)
        return None
    host = struct.calcsize("P") * 8
    if bits != host:
        why = ("target is %d-bit, this build is %d-bit - a debugger cannot "
               "cross WOW64; use %s" % (bits, host, vmtrace._other_python(bits)))
        res["vm"].update(run_status="skipped", run_reason=why)
        print("   trace: skipped (%s)" % why)
        return None

    argv = ["--exec", target, "--out", out,
            "--max-hits", str(opts.run_hits), "--timeout", str(opts.run_timeout),
            # one whole opcode per breakpoint: level 1.5 (the handler map) always,
            # level 2 only when the VM state base is known - vmtrace refuses to
            # guess it, and so do we
            "--until-return"]
    if opts.run_snapshot:
        argv += ["--snapshot", str(opts.run_snapshot),
                 "--snapshot-from", opts.run_state]
    if payload_pe:
        argv += ["--auto-from", payload_pe]      # sites come from the static half
    for extra in list(opts.run_opt or []):
        argv += shlex.split(extra)
    print("   trace: %s (%d-bit) %s" % (os.path.basename(target), bits,
                                        " ".join(argv[1:])))
    try:
        vmtrace.main(argv)
    except KeyboardInterrupt:
        res["vm"].update(run_status="interrupted")
        return None
    except SystemExit as exc:                    # no sites / no such file / ...
        res["vm"].update(run_status="failed", run_reason=str(exc))
        print("   trace: failed (%s)" % (exc or "vmtrace refused"))
        return None
    if not (os.path.exists(out) and os.path.getsize(out)):
        res["vm"].update(run_status="failed", run_reason="trace file is empty")
        print("   trace: failed (trace file is empty)")
        return None
    res["vm"].update(run_status="ok", run_bytes=os.path.getsize(out))
    return out


def stage_dejunk(data, rva, workdir, res, opts):
    """Sweep through Defus.Simple (+deadstore) and list what survives."""
    window = opts.dejunk_size or len(data)
    window = min(window, len(data))
    sub = data[:window]
    lst = os.path.join(workdir, "30_dejunk.lst")
    st = dict(blocks=0, n0=0, dead_total=0, kept_total=0, covered=0)
    t0 = time.time()
    with open(lst, "w", encoding="utf-8") as fh:
        fh.write("; Oreans dejunk sweep - Simple(%s)%s\n"
                 "; window %X of %X bytes; addresses are RVAs\n"
                 % (opts.simple,
                    " + deadstore" if not opts.no_deadstore else "",
                    window, len(data)))
        for r in dz.sweep_iter(sub, opts.simple, not opts.no_deadstore, opts.max):
            st = r
            d = r["entry"]
            fh.write("; block +%X   %d -> %d instrs\n"
                     % (r["off"], r["before"], r["kept"]))
            for i in range(d.count):
                ent = d.heap[i]
                try:
                    txt = dz.xrkdsm.XrkText(ent.instr)
                except Exception:
                    txt = "; <undecodable>"
                fh.write("%08X\t%s\n" % ((rva + ent.addr) & 0xFFFFFFFF, txt))
    n0 = st["n0"] or 1
    res["dejunk"] = dict(simple=opts.simple, deadstore=not opts.no_deadstore,
                         window=window,
                         window_pct=round(window * 100.0 / len(data), 2),
                         blocks=st["blocks"], instructions=st["n0"],
                         bytes_covered=st["covered"],
                         deadstore_pct=round(st["dead_total"] * 100.0 / n0, 2),
                         simple_pct=round((st["n0"] - st["dead_total"]
                                           - st["kept_total"]) * 100.0 / n0, 2),
                         total_removed_pct=round((st["n0"] - st["kept_total"])
                                                 * 100.0 / n0, 2),
                         seconds=round(time.time() - t0, 1),
                         listing=lst)


# ----------------------------------------------------------------- driver ----
def verdict(info, res):
    """One sentence a human can act on."""
    up = res.get("unpack", {})
    de = res.get("decode", {})
    dj = res.get("dejunk", {})
    vm = res.get("vm") or {}
    vm_text = ""
    if vm.get("opcodes"):
        vm_text = ("trace folded: %d opcode(s) -> %d handler(s)%s"
                   % (vm.get("opcodes", 0), vm.get("handlers", 0),
                      "" if not vm.get("inline_steps") else
                      (", %d step(s) inlined to native x86-64%s"
                       % (vm["inline_steps"],
                          " (executed: match)" if vm.get("inline_ok") else ""))))
    if info.get("kind") != "pe":
        return "not a PE (%s) - nothing to unpack with this pipeline" % (
            info.get("container") or info.get("kind"))
    if up.get("status") == "skipped":
        if vm_text:
            return "static half: scheme=%s not handled; %s" % (info.get("scheme"), vm_text)
        return "PE with scheme=%s - different protection scheme, not handled" % info.get("scheme")
    if up.get("status") == "failed":
        if vm_text:
            return "static half: unpack failed (%s); %s" % (up.get("reason"), vm_text)
        return "unpack failed: %s" % up.get("reason")
    if not de:
        return "payload could not be decoded"
    bad = de.get("invalid_pct", 100.0)
    if bad > 5.0:
        return "decoded %.2f%% invalid - stream looks still packed/encrypted" % bad
    if dj:
        if vm_text:
            tail = vm_text
        elif vm.get("run_status") in ("skipped", "failed", "interrupted"):
            tail = ("runtime trace %s: %s"
                    % (vm["run_status"], vm.get("run_reason", "")))
        elif vm.get("run_status") == "ok":
            tail = ("runtime trace taken but no dispatch site was hit - the host "
                    "never reached the VM (wrong host, or the VM starts later)")
        else:
            tail = ("level 2 needs a runtime trace: --run <host.exe> (built in) "
                    "or --trace <vmtrace.jsonl>")
        dv = res.get("devirt") or {}
        dv_text = ""
        if dv.get("status") == "ok":
            dv_text = (", native recovery -%d instrs (%.1f%% of reachable, "
                       "%d padding runs / %.1f%%)"
                       % (dv["removed"], dv["removed_pct"], dv["padding_runs"],
                          dv["padding_pct"]))
        return ("unpacked, %.3f%% decodable (%d instrs); peephole dejunk -%.1f%%, "
                "CFG+DCE -%.1f%%%s - %s"
                % (100.0 - bad, de["instructions"], dj["total_removed_pct"],
                   (res.get("cfg") or {}).get("removed_pct", 0.0), dv_text,
                   tail))
    return ("unpacked, %.3f%% decodable (%d instrs); dejunk skipped"
            % (100.0 - bad, de["instructions"]))


def suffix_dir(root, stem, sha):
    """Reuse <root>/<stem> when it already holds this exact file, else pick a
    free name (so re-running does not pile up _2/_3 directories)."""
    d = os.path.join(root, stem)
    base = d
    i = 1
    while os.path.exists(d):
        rj = os.path.join(d, "result.json")
        try:
            with open(rj, "r", encoding="utf-8") as fh:
                if json.load(fh).get("sniff", {}).get("sha256") == sha:
                    return d
        except Exception:
            pass
        i += 1
        d = "%s_%d" % (base, i)
    return d


def process(path, outroot, opts):
    name = os.path.basename(path)
    t0 = time.time()
    print("\n== %s" % name)
    info = sniff(path)

    workdir = suffix_dir(outroot, os.path.splitext(name)[0],
                         info.get("sha256", ""))
    os.makedirs(workdir, exist_ok=True)
    res = dict(file=path, workdir=workdir)
    res["sniff"] = info
    print("   kind=%s scheme=%s size=%X entropy=%.2f"
          % (info.get("kind"), info.get("scheme", "-"),
             info["size"], info["entropy"]))

    pe = stage_unpack(path, info, workdir, res)
    up = res.get("unpack", {})
    if up.get("status") == "ok":
        print("   unpack: payload %X bytes @ %s+%X -> %s"
              % (up["payload"], up.get("section", SEC), up["stream_off"],
                 os.path.basename(up["out"])))
    elif up:
        print("   unpack: %s%s" % (up.get("status"),
                                   (" (" + up["reason"] + ")")
                                   if up.get("reason") else ""))

    if pe:
        got = stage_decode(pe, workdir, res, opts)
        if got:
            de = res["decode"]
            print("   decode: %d instrs, %d invalid bytes (%.3f%%), %.1fs"
                  % (de["instructions"], de["invalid_bytes"],
                     de["invalid_pct"], de["seconds"]))
            if not opts.no_dejunk:
                stage_dejunk(got[0], got[1], workdir, res, opts)
                dj = res["dejunk"]
                print("   dejunk: %d blocks / %d instrs, deadstore %.1f%% + "
                      "Simple(%s) %.1f%% => -%.1f%%  (%.1fs)"
                      % (dj["blocks"], dj["instructions"], dj["deadstore_pct"],
                         dj["simple"], dj["simple_pct"],
                         dj["total_removed_pct"], dj["seconds"]))
            if not opts.no_cfg:
                stage_cfg(got[0], got[1], workdir, res, opts)
                cg = res["cfg"]
                print("   cfg: %d blocks, %d unknown edges, -%d instrs (%.2f%%) "
                      "in %d round(s)  (%.1fs)"
                      % (cg["blocks"], cg["unknown_edges"], cg["removed"],
                         cg["removed_pct"], len(cg["rounds"]), cg["seconds"]))
                if cg.get("verify"):
                    v = cg["verify"]
                    print("   oracle: %d blocks x %d random states, %d failure(s), "
                          "%d block(s) not modelled"
                          % (v["tested"], v["trials"], v["failures"],
                             v["skipped"]))

            if not getattr(opts, "no_devirt", False):
                dv = stage_devirt(pe, workdir, res, opts)
                if dv.get("status") == "ok":
                    print("   devirt: %d instrs in %s (%X bytes), padding %.1f%%, "
                          "reachable %.1f%% (%d), cut %d (%.2f%%), %d reverted, "
                          "struct %s  (%.1fs)"
                          % (dv["instructions"], dv["section"],
                             dv["section_bytes"], dv["padding_pct"],
                             dv["reachable_pct"], dv["reachable_instrs"],
                             dv["removed"], dv["removed_pct"], dv["reverted"],
                             dv["structural"]["status"], dv["seconds"]))
                else:
                    print("   devirt: %s (%s)" % (dv.get("status"),
                                                  dv.get("reason", "")))

    if opts.run:
        # pe is the *unpacked* payload; without it vmtrace has no sites to break
        # on (it scans a .vlizer-style section) - so --run needs the static half
        # to have produced one, i.e. a genuinely protected host, not plain-pe
        got = stage_run(workdir, res, opts, pe)
        if got:
            opts.trace = got                # fold it right below, same report
            vm = res["vm"]
            print("   trace: %d bytes -> %s"
                  % (vm["run_bytes"], os.path.basename(vm["run_trace"])))

    if opts.trace:
        stage_trace(workdir, res, opts)
        vm = res["vm"]
        print("   trace: %d hit(s), %d site(s) (%d monomorphic), %d handler(s), "
              "%d opcode(s), %d conflict(s)"
              % (vm["hits"], vm["sites"], vm["monomorphic"], vm["handlers"],
                 vm["opcodes"], vm["conflicts"]))
        if vm.get("native"):
            o = vm["sem_oracle"]
            print("   level 2: %d opcode semantic(s), replay oracle %d/%d "
                  "byte-exact -> %s"
                  % (len(vm["semantics"]), o["ok"], o["ok"] + o["bad"],
                     os.path.basename(vm["native"])))
        if vm.get("inline"):
            ok = vm.get("inline_ok")
            print("   inline : %d step(s) -> %d byte(s) of x86-64, %s "
                  "-> %s"
                  % (vm["inline_steps"], vm["inline_bytes"],
                     "executed: MATCH" if ok else
                     ("MISMATCH" if ok is False else "not executed"),
                     os.path.basename(vm["inline"])))

    res["verdict"] = verdict(info, res)
    res["seconds"] = round(time.time() - t0, 1)
    with open(os.path.join(workdir, "result.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    print("   -> %s  (%ss)" % (res["verdict"], res["seconds"]))
    return res


def collect_inputs(args):
    EXTS = (".xem", ".exe", ".dll", ".bin", ".dat", ".sys")
    found = []
    for a in args:
        if os.path.isdir(a):
            for f in sorted(os.listdir(a)):
                p = os.path.join(a, f)
                if os.path.isfile(p) and p.lower().endswith(EXTS):
                    found.append(p)
        elif any(c in a for c in "*?["):
            found.extend(sorted(glob.glob(a)))
        elif os.path.isfile(a):
            found.append(a)
        else:
            print("skip (not found): %s" % a)
    out, seen = [], set()
    for p in found:
        k = os.path.abspath(p).lower()
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


# ----------------------------------------------------------------- report ----
def write_summary(results, outroot):
    """Render every result found under <outroot> (this run + earlier runs), so
    batch-by-batch operation still ends with one coherent SUMMARY.md."""
    rows = {}

    def add(r):
        if not r.get("file"):
            return
        k = (os.path.basename(r["file"]), (r.get("sniff") or {}).get("sha256", ""))
        rows.setdefault(k, r)

    for r in results:
        add(r)
    for p in sorted(glob.glob(os.path.join(outroot, "*", "result.json"))):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                add(json.load(fh))
        except Exception:
            continue

    tool = os.path.basename(sys.executable) if FROZEN else "autodeob.py"
    lines = [
        "# autodeob summary",
        "",
        "Generated %s by `%s` (static only, nothing executed)."
        % (time.strftime("%Y-%m-%d %H:%M:%S"), tool),
        "",
        "| file | kind | scheme | payload | instrs | invalid | dejunk (-%) | cfg (-%) | devirt (-%) | verdict |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(rows.values(),
                    key=lambda r: os.path.basename(r["file"]).lower()):
        i = r["sniff"]
        de = r.get("decode") or {}
        dj = r.get("dejunk") or {}
        cg = r.get("cfg") or {}
        dvt = r.get("devirt") or {}
        lines.append("| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            os.path.basename(r["file"]),
            i.get("kind", "-"),
            i.get("scheme", "-"),
            ("%X" % r["payload"]["bytes"]) if r.get("payload") else "-",
            ("%d" % de["instructions"]) if de else "-",
            ("%.3f%%" % de["invalid_pct"]) if de else "-",
            ("%.1f%%" % dj["total_removed_pct"]) if dj else "-",
            ("%.1f%%" % cg["removed_pct"]) if cg else "-",
            ("%.1f%%" % dvt["removed_pct"]) if dvt.get("status") == "ok" else "-",
            r["verdict"],
        ))
    if any(r.get("vm") for r in results):
        lines += [
            "",
            "## Dynamic trace (`--trace`)",
            "",
            "| file | meaning |",
            "|---|---|",
            "| `41_vm.txt` | recovered `opcode -> handler` map, per-site targets, conflicts |",
            "| `41_lift.asm` | direct-threaded dispatch: computed jump -> direct jump |",
        ]
        if any((r.get("vm") or {}).get("native") for r in results):
            lines.append(
                "| `42_native.asm` | *level 2*: what each opcode does to VM "
                "state + native code per opcode, with the replay oracle |")
        if any((r.get("vm") or {}).get("inline") for r in results):
            lines.append(
                "| `43_inline.asm` | *level 2, devirtualised*: the observed programme inlined "
                "as real x86-64 (43_inline.txt = executed verdict) |")
    lines += [
        "",
        "## Artifacts per input",
        "",
        "| file | meaning |",
        "|---|---|",
        "| `10_unpacked.exe` | PE whose Oreans section holds the decompressed bytecode |",
        "| `20_payload.lst` | full decode (`addr  bytes  mnemonic`) - ground truth stream |",
        "| `30_dejunk.lst` | same stream after `Defus.Simple` + deadstore, per block |",
        "| `40_cfg.lst` | whole-payload CFG + liveness DCE (`cfgpass.py`), block headers |",
        "| `41_devirt.lst` | native-recovery listing (`devirt.py`): every instruction with its reachability and cut/proof verdict |",
        "| `50_devirt.exe` | same PE with the proven-dead instructions replaced by `0x90` in place (no byte ever moves) |",
        "| `result.json` | all numbers above, machine-readable (sections, header, histogram) |",
        "",
        "## Limits (by construction)",
        "",
        "- the peephole stage is *local*: it removes junk provably dead inside one",
        "  block, ~6% on this family (REPORT.md section 7).",
        "- the CFG stage is global but still a *removal* pass: it only deletes",
        "  instructions whose registers/flags are dead on every path, ~9% (measured;",
        "  no cancelling `ADD`/`SUB` chains exist to fold, see REPORT.md section 7).",
        "- the devirt stage works on the image instead of a window. Measured on the",
        "  four corpus builds: 17-21% of `.vlizer` is zero/`0xCC` padding, 7-9% is",
        "  never reached from any real entry point, and only 11-15% of the *reachable*",
        "  instructions can be cut with a local proof (the audit demands a redefinition",
        "  *inside* the same block, so long mode - 16 GPRs spreading the junk out -",
        "  keeps fewer cuts than 32-bit). Reachability is deliberately",
        "  high (~75% of the section) because the mutation junk is interleaved with",
        "  the real code and falls through into it - it is live, just useless, so",
        "  removing it needs value propagation (rewriting operands), not DCE.",
        "- devirtualisation is impossible statically: handlers are generated at runtime,",
        "  so the file contains no handler table to lift (REPORT.md section 3.4).",
        "  The dynamic pair `vmtrace.py` + `vmlift.py` closes that gap: it recovers",
        "  `opcode -> handler` from a live process and emits a direct-threaded",
        "  dispatch listing (REPORT.md section 7.7).",
        "- the original source is not recoverable; the output is a semantically",
        "  equivalent instruction stream, not C.",
        "",
    ]
    p = os.path.join(outroot, "SUMMARY.md")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return p


def selftest_run():
    """--selftest-vm: prove the dynamic half works inside *this* process.

    vmfix.py builds a real PE that *is* a bytecode VM (`jmp rdx`, 9 handlers)
    whose opcode -> handler map and per-opcode semantics are known by
    construction.  The bundled tracer is pointed at it with the same options
    `--run` uses, vmlift re-derives the semantics from before/after snapshots
    alone, and vminline emits native x86-64 that is executed and compared.  So
    a PASS here means the .exe really does the whole chain by itself - and the
    only thing it ever launched is our own fixture.
    """
    import tempfile

    import vmfix

    d = tempfile.mkdtemp(prefix="deob_vmfix_")
    exe = os.path.join(d, "fixvm.exe")
    gt = vmfix.build(exe)
    host = struct.calcsize("P") * 8
    print("\nselftest-vm: fixture %s" % exe)
    print("selftest-vm: %d bytes, %d-bit host, site +%X, %d handlers"
          % (gt["size"], host, gt["site_rva"], gt["opcodes"]))

    opts = argparse.Namespace(
        run=exe, run_hits=64, run_timeout=30.0,
        run_opt=["--bp-rva 0x%X" % gt["site_rva"], "--follow", "2"],
        run_snapshot=gt["vregs_bytes"], run_state="reg:r13",
        trace=None, trace_opcode_from="reg:eax", trace_mask=0xFF)
    res = {}
    trace = stage_run(d, res, opts, None)

    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    vm = res.get("vm", {})
    if vm.get("run_status") == "skipped":        # 32-bit build: x64 fixture
        print("selftest-vm: SKIP (%s)" % vm.get("run_reason"))
        return 0
    check("trace taken from a live process", bool(trace),
          str(vm.get("run_reason") or ("%d bytes" % vm.get("run_bytes", 0))))
    if not trace:
        for i, (name, ok, detail) in enumerate(checks, 1):
            print("FAIL %2d. %s  (%s)" % (i, name, detail))
        return 1

    opts.trace = trace
    stage_trace(d, res, opts)
    vm = res["vm"]

    import vmlift
    _hdr, recs = vmlift.load(trace)
    an = vmlift.analyse(recs, "reg:eax", 0xFF, 0)
    got = {op: o["handlers"].most_common(1)[0][0] for op, o in an["ops"].items()}
    base = gt["image_base"]
    bad = {op: (got.get(op), want) for op, want in gt["expect"].items()
           if got.get(op) != want}

    check("dispatch site reached %d time(s)" % vm.get("hits", 0),
          vm.get("hits", 0) >= gt["opcodes"], "%d hit(s)" % vm.get("hits", 0))
    check("opcode -> handler map has %d entries" % gt["opcodes"],
          set(got) == set(gt["expect"]),
          " ".join("%X" % op for op in sorted(got)))
    check("every opcode lands on the handler built for it", not bad,
          ", ".join("%X: +%X != +%X" % (op, ((g or base) - base), w)
                    for op, (g, w) in sorted(bad.items())))
    check("no opcode conflicts", not vm.get("conflicts"),
          "%d" % vm.get("conflicts", 0))

    mine = {}
    for k, v in (vm.get("semantics") or {}).items():
        mine[int(k, 16)] = v
    want = gt["semantics"]
    bad_sem = {op: (mine.get(op), want[op]) for op in want
               if mine.get(op) != want[op]}
    check("semantics of all %d opcodes equal the ground truth" % len(want),
          not bad_sem,
          "; ".join("%X: %r != %r" % (op, g, w)
                    for op, (g, w) in sorted(bad_sem.items())))
    orc = vm.get("sem_oracle") or {}
    check("replay oracle reproduces every hit", orc.get("bad") == 0 and
          (orc.get("ok", 0) + orc.get("bad", 0)) == vm.get("hits", 0),
          "%d ok, %d bad" % (orc.get("ok", 0), orc.get("bad", 0)))
    check("inline: %d opcode(s) -> %d byte(s) of x86-64, executed"
          % (vm.get("inline_steps", 0), vm.get("inline_bytes", 0)),
          vm.get("inline_ran") and vm.get("inline_ok") is True,
          "ran=%s ok=%s" % (vm.get("inline_ran"), vm.get("inline_ok")))

    for i, (name, ok, detail) in enumerate(checks, 1):
        print("%s %2d. %s%s" % ("PASS" if ok else "FAIL", i, name,
                                ("  (%s)" % detail) if detail else ""))
    passed = sum(1 for _n, ok, _d in checks if ok)
    print("\nselftest-vm: %s (%d/%d)   artifacts: %s"
          % ("PASS" if passed == len(checks) else "FAIL", passed, len(checks), d))
    return 0 if passed == len(checks) else 1


def main():
    ap = argparse.ArgumentParser(
        description="Drop-in static deobfuscator: "
                    "sniff -> unpack -> decode -> dejunk -> cfg -> report")
    ap.add_argument("inputs", nargs="*", help="files, directories or globs")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="output root (default %s)" % DEFAULT_OUT)
    ap.add_argument("--simple", default="D", choices=list("ABCD"),
                    help="Defus.Simple variant (default D)")
    ap.add_argument("--dejunk-size", type=lambda s: int(s, 0), default=0x10000,
                    help="bytes of payload to sweep, 0 = whole payload "
                         "(default 0x10000)")
    ap.add_argument("--max", type=int, default=0,
                    help="cap instructions per sweep")
    ap.add_argument("--no-dejunk", action="store_true")
    ap.add_argument("--no-deadstore", action="store_true")
    ap.add_argument("--no-cfg", action="store_true",
                    help="skip the CFG + liveness DCE stage (40_cfg.lst)")
    ap.add_argument("--cfg-size", type=lambda s: int(s, 0), default=0,
                    help="bytes of payload for the CFG stage, 0 = whole payload")
    ap.add_argument("--cfg-rounds", type=int, default=8,
                    help="max DCE iterations (default 8)")
    ap.add_argument("--no-devirt", action="store_true",
                    help="skip the native-recovery stage (41_devirt.lst / "
                         "50_devirt.exe); it decodes the whole section and "
                         "takes ~1 min per MB")
    ap.add_argument("--devirt-no-pe", action="store_true",
                    help="write the devirt listing but not the patched "
                         "50_devirt.exe")
    ap.add_argument("--cfg-verify", type=int, default=8, metavar="N",
                    help="differential-oracle trials per block (0 = off, default 8)")
    ap.add_argument("--no-listing", action="store_true",
                    help="do not write 20_payload.lst (still counts instrs)")
    ap.add_argument("--trace", default=None, metavar="JSONL",
                    help="fold a vmtrace.py trace into 41_vm.txt + "
                         "41_lift.asm, and when the trace has state snapshots "
                         "42_native.asm + 43_inline.asm and execute it")
    ap.add_argument("--trace-opcode-from", default="reg:eax",
                    help="opcode source for --trace: reg:NAME or mem "
                         "(default reg:eax)")
    ap.add_argument("--trace-mask", type=lambda s: int(s, 0), default=0xFF,
                    help="mask applied to the opcode value (default 0xFF)")
    ap.add_argument("--run", default=None, metavar="HOST.EXE",
                    help="ALSO EXECUTE: start HOST.EXE under the bundled "
                         "debugger, trace the dispatch sites found in the "
                         "payload, then fold the trace (level 1.5 + 2). Untrusted "
                         "samples belong in a throw-away VM")
    ap.add_argument("--run-opt", action="append", default=[], metavar="ARGS",
                    help="extra vmtrace.py options (repeatable, quoted), e.g. "
                         "\"--follow 12\" or \"--bp-rva 0x2010 --ctx-ptr esi\"")
    ap.add_argument("--run-snapshot", type=int, default=0, metavar="BYTES",
                    help="also record BYTES of VM state per opcode, which is "
                         "what level 2 (semantics + native inline) needs; 0 = "
                         "level 1.5 only (default 0)")
    ap.add_argument("--run-state", default="ctx", metavar="SPEC",
                    help="snapshot base for --run-snapshot: reg:NAME or ctx "
                         "(with --ctx-ptr in --run-opt); default ctx")
    ap.add_argument("--run-hits", type=int, default=500,
                    help="max breakpoint hits to record (default 500)")
    ap.add_argument("--run-timeout", type=float, default=180.0,
                    help="seconds before the traced target is terminated "
                         "(default 180)")
    ap.add_argument("--selftest-vm", action="store_true",
                    help="build the synthetic VM (vmfix.py) and prove the whole "
                         "chain - trace, lift, inline, execute - against its "
                         "ground truth; nothing else is ever launched")
    ap.add_argument("--no-pause", action="store_true",
                    help="frozen .exe: do not wait for Enter before closing")
    a = ap.parse_args()

    if a.selftest_vm:
        rc = selftest_run()
        if FROZEN and not a.no_pause and sys.stdout.isatty():
            try:
                input("\npress Enter to close . . .")
            except EOFError:
                pass
        raise SystemExit(rc)

    files = collect_inputs(a.inputs)
    if not files:
        raise SystemExit("no input files matched")
    os.makedirs(a.out, exist_ok=True)
    print("autodeob: %d file(s) -> %s" % (len(files), a.out))

    t0 = time.time()
    results = []
    for f in files:
        try:
            results.append(process(f, a.out, a))
        except Exception as e:            # one bad file must not stop the run
            print("   !! %s: %s: %s"
                  % (os.path.basename(f), type(e).__name__, e))
            results.append(dict(file=f, workdir="",
                                sniff=dict(kind="error", size=0),
                                verdict="crashed: %s" % e))
    p = write_summary(results, a.out)
    print("\n%d file(s) in %.1fs\nsummary -> %s"
          % (len(results), time.time() - t0, p))
    # drag & drop: the console would vanish before the numbers can be read
    if FROZEN and not a.no_pause and sys.stdout.isatty():
        try:
            input("\npress Enter to close . . .")
        except EOFError:
            pass


if __name__ == "__main__":
    main()
