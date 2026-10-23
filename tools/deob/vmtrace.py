#!/usr/bin/env python3
"""vmtrace.py - runtime trace of an Oreans VM dispatcher (THIS ONE EXECUTES code).

Why this file exists: the static pass (`cfgpass.py`, `vmfind.py`) can cut code,
but it cannot recover `opcode -> handler`.  vmfind measured 1,282 `jmp reg`
sites and no handler table, i.e. the mapping is assembled while the process
runs.  Recovering it therefore needs a live process - so the dynamic half of
the pipeline is here, and it is deliberately a *separate* tool: the static
pipeline (`autodeob.py`) still never executes anything.

How it works (no instruction decoding needed for the dispatch itself):

    set a breakpoint on every indirect-jump site
    the jump destination IS the handler
    optionally single-step N instructions of the handler      (--follow N)
    optionally step until the handler jumps back to the site  (--until-return)

`--follow` matters because the handler prologue is frequently (re)decrypted at
run time: the bytes only exist in memory *after* the dispatcher jumped there.
`--until-return` goes one step further and captures *one whole opcode*, which is
what makes level 2 possible: with `--snapshot N --snapshot-from reg:NAME` the VM
state block is read before and after each opcode, so `vmlift.py` can derive what
the opcode does from the observed transition instead of disassembling it.

Output is JSONL (`vmtrace.jsonl`), consumed by `vmlift.py`:

    {"kind":"header", "target":"...", "bits":32, "module_base":4194304, ...}
    {"kind":"hit", "site":8256, "target":4100624, "seq":1,
     "regs":{"eax":...}, "ctx_ptr":..., "steps":[[4100624,"56 8b f1 ..."]],
     "snap_addr":..., "mem_before":"...", "mem_after":"...",   # --snapshot
     "returned":true, "steps_taken":9, "regs_after":{...}}     # --until-return

SAFETY - read this before running anything
  * Nothing is launched unless you pass --exec (or --selftest / --selftest-vm).
    The default is a dry run: it prints the breakpoint plan and exits.
  * --selftest runs a *benign* system binary and kills it at its entry point.
    That is how the debugger machinery is validated without touching a sample:
        python _analysis/vmtrace.py --selftest
  * --selftest-vm goes further and proves the *recovery*: vmfix.py builds a real
    PE that is a bytecode VM (9 handlers, `jmp rdx`) with a known opcode ->
    handler map *and* known per-opcode semantics, this tool traces it with
    --until-return --snapshot, and vmlift.py's map + semantics + replay oracle
    are compared against that ground truth (PASS 16/16).  Nothing but our own
    fixture is executed.
  * Running the actual sample is your call, in a throw-away VM, with --exec.

Architecture note (WOW64): a 64-bit Python cannot debug a 32-bit process and
vice versa.  The target's PE header decides; on a mismatch the tool refuses
instead of silently tracing nothing.  For the 32-bit x3 payload use:
    py -3.11-32 _analysis/vmtrace.py --exec target.exe --auto-from ...

Usage:
    python _analysis/vmtrace.py --selftest-vm        # differential test (fixture VM)
    python _analysis/vmtrace.py --selftest           # benign system binary
    python _analysis/vmtrace.py --dry-run target.exe --auto-from out\\auto\\x3\\10_unpacked.exe
    py -3.11-32 _analysis/vmtrace.py --exec target.exe --auto-from ... --follow 12 --max-hits 500
    py -3.11-32 _analysis/vmtrace.py --exec target.exe --auto-from ... \\
           --until-return --snapshot 64 --snapshot-from reg:esi --max-hits 500
"""
import argparse
import ctypes
import ctypes.wintypes as w
import json
import os
import shlex
import struct
import sys
import tempfile
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
EXCEPTION_PRIV_INSTRUCTION = 0xC0000096

DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NEW_CONSOLE = 0x00000010
PAGE_EXECUTE_READWRITE = 0x40
TF = 0x00000100

k32.CreateProcessW.argtypes = [w.LPCWSTR, w.LPWSTR, ctypes.c_void_p,
                               ctypes.c_void_p, w.BOOL, w.DWORD, ctypes.c_void_p,
                               w.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p]
k32.CreateProcessW.restype = w.BOOL
k32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, w.DWORD]
k32.WaitForDebugEvent.restype = w.BOOL
k32.ContinueDebugEvent.argtypes = [w.DWORD, w.DWORD, w.DWORD]
k32.ContinueDebugEvent.restype = w.BOOL
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = w.BOOL
k32.WriteProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = w.BOOL
k32.VirtualProtectEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                 w.DWORD, ctypes.POINTER(w.DWORD)]
k32.VirtualProtectEx.restype = w.BOOL
k32.GetThreadContext.argtypes = [w.HANDLE, ctypes.c_void_p]
k32.GetThreadContext.restype = w.BOOL
k32.SetThreadContext.argtypes = [w.HANDLE, ctypes.c_void_p]
k32.SetThreadContext.restype = w.BOOL
k32.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
k32.TerminateProcess.restype = w.BOOL
k32.DebugActiveProcessStop.argtypes = [w.DWORD]
k32.DebugActiveProcessStop.restype = w.BOOL
k32.CloseHandle.argtypes = [w.HANDLE]
k32.FlushInstructionCache.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
k32.IsWow64Process.argtypes = [w.HANDLE, ctypes.POINTER(w.BOOL)]
k32.IsWow64Process.restype = w.BOOL


class _Arch(object):
    """CONTEXT / DEBUG_EVENT offsets, per-architecture (no ctypes struct zoo)."""

    def __init__(self, bits):
        self.bits = bits
        if bits == 32:
            self.ptr = 4
            self.ctx_size = 0x2CC
            self.ctx_flags = 0x00010007          # i386|CONTROL|INTEGER|SEGMENTS
            self.ctxflags_off = 0
            self.reg_off = {"edi": 0x9C, "esi": 0xA0, "ebx": 0xA4, "edx": 0xA8,
                            "ecx": 0xAC, "eax": 0xB0, "ebp": 0xB4, "eip": 0xB8,
                            "eflags": 0xC0, "esp": 0xC4}
            self.union_off = 12                  # DEBUG_EVENT.u
            self.cp_off = {"hfile": 0, "hproc": 4, "hthread": 8, "base": 12}
            self.exc_addr_off = 12               # inside u (EXCEPTION_RECORD)
        elif bits == 64:
            self.ptr = 8
            self.ctx_size = 0x4D0
            self.ctx_flags = 0x00100007          # amd64|CONTROL|INTEGER|SEGMENTS
            self.ctxflags_off = 0x30             # NOT 0: P1Home..P6Home come first
            self.reg_off = {"rax": 0x78, "rcx": 0x80, "rdx": 0x88, "rbx": 0x90,
                            "rsp": 0x98, "rbp": 0xA0, "rsi": 0xA8, "rdi": 0xB0,
                            "r8": 0xB8, "r9": 0xC0, "r10": 0xC8, "r11": 0xD0,
                            "r12": 0xD8, "r13": 0xE0, "r14": 0xE8, "r15": 0xF0,
                            "rip": 0xF8, "eflags": 0x44}
            self.union_off = 16
            self.cp_off = {"hfile": 0, "hproc": 8, "hthread": 16, "base": 24}
            self.exc_addr_off = 16
        else:
            raise ValueError("bits must be 32 or 64")
        self.pc = "eip" if bits == 32 else "rip"
        self.sp = "esp" if bits == 32 else "rsp"
        self.wordsize = 4 if bits == 32 else 8

    def gprs(self):
        """General purpose registers, in a stable display order."""
        if self.bits == 32:
            return ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
        return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def _other_python(bits):
    """Hint for the interpreter the caller needs (no fixed version number)."""
    return "py -3-32" if bits == 32 else "a 64-bit python"


def _pe_bits(path):
    """Machine field of a PE file -> 32/64 (raises SystemExit on non-PE)."""
    with open(path, "rb") as f:
        hdr = f.read(0x400)
    if hdr[:2] != b"MZ":
        raise SystemExit("%s: not a PE (no MZ)" % path)
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    if hdr[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("%s: not a PE (no PE signature)" % path)
    machine = struct.unpack_from("<H", hdr, e_lfanew + 4)[0]
    if machine == 0x8664:
        return 64
    if machine in (0x14C, 0x14D):
        return 32
    if machine in (0xAA64, 0xA641, 0xA64E):
        raise SystemExit("%s: ARM64 target - this harness is x86/x64 only" % path)
    raise SystemExit("%s: unknown machine 0x%X" % (path, machine))


def _pe_entry(path):
    """(entry RVA, image base) from a PE file."""
    with open(path, "rb") as f:
        hdr = f.read(0x400)
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", hdr, opt)[0]
    if magic == 0x20B:
        entry = struct.unpack_from("<I", hdr, opt + 16)[0]
        base = struct.unpack_from("<Q", hdr, opt + 24)[0]
    else:
        entry = struct.unpack_from("<I", hdr, opt + 16)[0]
        base = struct.unpack_from("<I", hdr, opt + 28)[0]
    return entry, base


def _u(buf, off, size):
    return int.from_bytes(bytes(buf[off:off + size]), "little")


# --------------------------------------------------------------- the tracer --
class Tracer(object):
    """A one-shot debugger: arm breakpoints, follow the jumps, kill the target."""

    def __init__(self, a):
        self.a = a
        self.arch = _Arch(a.bits)
        self.hproc = None
        self.pinfo = None
        self.pid = 0
        self.base = 0
        self.tids = {}                 # tid -> thread handle
        self.bps = {}                  # addr -> original byte(s)
        self.pending = None            # [site, record, steps_left]
        self.hits = []
        self.out = None
        self.deadline = 0.0
        self.records = 0
        self.sites_seen = set()
        self.targets = set()
        self.stopped = None
        self.error = None
        self.planned = 0
        self.armed_once = False

    # -- process memory ---------------------------------------------------
    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t()
        if not k32.ReadProcessMemory(self.hproc, ctypes.c_void_p(addr), buf, size,
                                     ctypes.byref(got)):
            return None
        return buf.raw[:got.value]

    def write(self, addr, data):
        n = ctypes.c_size_t()
        buf = ctypes.create_string_buffer(data, len(data))
        old = w.DWORD()
        k32.VirtualProtectEx(self.hproc, ctypes.c_void_p(addr), len(data),
                             PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        ok = k32.WriteProcessMemory(self.hproc, ctypes.c_void_p(addr), buf, len(data),
                                    ctypes.byref(n))
        k32.VirtualProtectEx(self.hproc, ctypes.c_void_p(addr), len(data), old.value,
                             ctypes.byref(old))
        return bool(ok) and n.value == len(data)

    # -- context ----------------------------------------------------------
    def get_ctx(self, tid):
        buf = ctypes.create_string_buffer(self.arch.ctx_size)
        struct.pack_into("<I", buf, self.arch.ctxflags_off, self.arch.ctx_flags)
        if not k32.GetThreadContext(self.tids[tid], buf):
            raise OSError(ctypes.get_last_error(), "GetThreadContext")
        ctx = bytearray(buf.raw)
        if not (self.reg(ctx, "eflags") & 2):
            # reserved bit 1 is always set; zero here means the offsets are wrong
            raise OSError("CONTEXT offsets are wrong for %d-bit" % self.arch.bits)
        return ctx

    def set_ctx(self, tid, buf):
        b = ctypes.create_string_buffer(bytes(buf), len(buf))
        if not k32.SetThreadContext(self.tids[tid], b):
            raise OSError(ctypes.get_last_error(), "SetThreadContext")

    def reg(self, ctx, name):
        sz = 4 if name == "eflags" else self.arch.wordsize
        return _u(ctx, self.arch.reg_off[name], sz)

    def put_reg(self, ctx, name, value):
        sz = 4 if name == "eflags" else self.arch.wordsize
        ctx[self.arch.reg_off[name]:self.arch.reg_off[name] + sz] = \
            int(value).to_bytes(sz, "little")

    # -- breakpoints ------------------------------------------------------
    def arm(self, addr):
        if addr in self.bps:
            return True
        if not addr:
            return False
        old = self.read(addr, 1)
        if old is None:
            return False
        if not self.write(addr, b"\xCC"):
            return False
        self.bps[addr] = old
        return True

    def disarm(self, addr):
        old = self.bps.pop(addr, None)
        if old is not None:
            self.write(addr, old)
        return old

    # -- helpers ----------------------------------------------------------
    def emit(self, rec):
        if self.out:
            self.out.write(json.dumps(rec, sort_keys=True) + "\n")
            self.out.flush()
        self.records += 1

    def rva(self, addr):
        return (addr - self.base) if self.base else None

    # -- events -----------------------------------------------------------
    def snap_base(self, ctx):
        """Address of the VM state block to snapshot (0 = snapshots are off)."""
        n = getattr(self.a, "snapshot", 0) or 0
        if n <= 0:
            return 0
        spec = (getattr(self.a, "snapshot_from", "") or "ctx").strip()
        if spec.lower().startswith("reg:"):
            name = spec.split(":", 1)[1].strip().lower()
            if name not in self.arch.reg_off:
                raise SystemExit("--snapshot-from: unknown register %r" % name)
            return self.reg(ctx, name)
        if not self.a.ctx_ptr:
            raise SystemExit("--snapshot: use --snapshot-from reg:NAME (or "
                             "--ctx-ptr for the default 'ctx' base)")
        return self.reg(ctx, self.a.ctx_ptr) + self.a.ctx_ptr_off

    def on_bp(self, tid, addr):
        if self.pending is not None:            # nested hit: close the outer one
            self.finish_pending()
        ctx = self.get_ctx(tid)
        rec = {"kind": "hit", "seq": self.records + 1, "site": addr,
               "site_in_module": self.rva(addr),
               "regs": {r: self.reg(ctx, r) for r in self.arch.gprs()},
               "eflags": self.reg(ctx, "eflags"), "thread": tid}
        if self.a.ctx_ptr:
            p = self.reg(ctx, self.a.ctx_ptr)
            raw = self.read(p + self.a.ctx_ptr_off, max(1, self.a.ctx_len))
            rec["ctx_ptr"] = p
            rec["vm_bytes"] = raw.hex() if raw else None
        base = self.snap_base(ctx)
        if base:
            raw = self.read(base, self.a.snapshot)
            rec["snap_addr"] = base
            rec["mem_before"] = raw.hex() if raw else None
        if self.a.verbose:
            print("  hit  0x%X  op=0x%X  target=0x%X"
                  % (addr, self.reg(ctx, "rax"), self.reg(ctx, "rdx")))
        self.disarm(addr)
        self.put_reg(ctx, self.arch.pc, addr)             # undo INT3's +1
        self.put_reg(ctx, "eflags", self.reg(ctx, "eflags") | TF)
        self.set_ctx(tid, ctx)
        budget = (max(1, int(getattr(self.a, "max_steps", 256)))
                  if getattr(self.a, "until_return", False)
                  else max(1, int(self.a.follow)))
        self.pending = [addr, rec, budget]
        return DBG_CONTINUE

    def on_single_step(self, tid):
        ctx = self.get_ctx(tid)
        pc = self.reg(ctx, self.arch.pc)
        if self.pending is None:                          # stray step: clear TF
            self.put_reg(ctx, "eflags", self.reg(ctx, "eflags") & ~TF)
            self.set_ctx(tid, ctx)
            return DBG_CONTINUE
        _site, rec, left = self.pending
        if pc in self.bps:                                # stepped onto a bpt
            rec.setdefault("target", pc)
            rec.setdefault("target_in_module", self.rva(pc))
            self.finish_pending()
            return self.on_bp(tid, pc)
        if getattr(self.a, "until_return", False) and pc == _site:
            # the handler jumped back to the dispatcher: one opcode is complete
            rec["returned"] = True
            rec["steps_taken"] = len(rec.get("steps") or [])
            self.finish_pending(ctx)
            return DBG_CONTINUE
        steps = rec.setdefault("steps", [])
        raw = self.read(pc, 16)
        steps.append([pc, raw.hex() if raw else None])
        if self.a.verbose:
            print("  step 0x%X  (left %d)" % (pc, left - 1))
        if "target" not in rec:
            rec["target"] = pc
            rec["target_in_module"] = self.rva(pc)
            self.sites_seen.add(rec["site"])
            self.targets.add(pc)
        left -= 1
        if left > 0:
            self.pending[2] = left
            # the single-step trap clears TF in the saved context: set it again
            self.put_reg(ctx, "eflags", self.reg(ctx, "eflags") | TF)
            self.set_ctx(tid, ctx)
            return DBG_CONTINUE
        rec["truncated"] = True                # --max-steps without a return
        self.finish_pending(ctx)
        return DBG_CONTINUE

    def finish_pending(self, ctx=None):
        if self.pending is None:
            return
        site, rec, _left = self.pending
        self.pending = None
        if ctx is None:
            try:
                ctx = self.get_ctx(rec["thread"])
            except Exception:
                ctx = None
        if ctx is not None:
            if rec.get("snap_addr"):
                raw = self.read(rec["snap_addr"], self.a.snapshot)
                rec["mem_after"] = raw.hex() if raw else None
            rec["regs_after"] = {r: self.reg(ctx, r) for r in self.arch.gprs()}
            self.put_reg(ctx, "eflags", self.reg(ctx, "eflags") & ~TF)
            self.set_ctx(rec["thread"], ctx)
        self.emit(rec)
        self.hits.append(rec)
        if len(self.hits) >= self.a.max_hits:
            self.stopped = "max-hits"
            return
        self.arm(site)

    # -- main loop --------------------------------------------------------
    def arm_all(self):
        """Arm one breakpoint per indirect-jump site (RVAs from vmfind)."""
        want = 0
        if self.a.bp_entry:
            ent, _ib = _pe_entry(self.a.target)
            self.arm(self.base + ent)
            want += 1
        for rva in self.a.bp_rva:
            self.arm(self.base + rva)
            want += 1
        self.planned = len(self.bps)
        if self.a.verbose:
            print("  armed %d/%d breakpoints (base 0x%X)"
                  % (self.planned, want, self.base))
        return self.planned

    def run(self):
        a = self.a
        cmdline = a.target
        if a.target_args:
            cmdline = "%s %s" % (a.target, " ".join(a.target_args))
        si = ctypes.create_string_buffer(0x68)
        struct.pack_into("<I", si, 0, 0x68)
        pi = ctypes.create_string_buffer(0x18)
        flags = DEBUG_ONLY_THIS_PROCESS
        if a.new_console:
            flags |= CREATE_NEW_CONSOLE
        if not k32.CreateProcessW(None, ctypes.c_wchar_p(cmdline), None, None, False,
                                  flags, None, a.cwd, si, pi):
            return "CreateProcess failed (%d)" % ctypes.get_last_error()
        self.pinfo = pi
        self.hproc = w.HANDLE(_u(pi, 0, self.arch.ptr))
        self.pid = _u(pi, 2 * self.arch.ptr, 4)
        self.deadline = time.time() + a.timeout
        u = self.arch.union_off
        while not self.stopped:
            if time.time() > self.deadline:
                self.stopped = "timeout"
                break
            buf = ctypes.create_string_buffer(256)
            if not k32.WaitForDebugEvent(buf, 500):
                if ctypes.get_last_error() == 121:        # ERROR_SEM_TIMEOUT
                    continue
                self.error = self.error or "WaitForDebugEvent failed (%d)" % \
                    ctypes.get_last_error()
                break
            code = _u(buf, 0, 4)
            tid = _u(buf, 8, 4)
            status = DBG_CONTINUE
            try:
                if code == CREATE_PROCESS_DEBUG_EVENT:
                    self.base = _u(buf, u + self.arch.cp_off["base"], self.arch.ptr)
                    self.tids[tid] = w.HANDLE(_u(buf, u + self.arch.cp_off["hthread"],
                                                 self.arch.ptr))
                    f = _u(buf, u + self.arch.cp_off["hfile"], self.arch.ptr)
                    if f:
                        k32.CloseHandle(w.HANDLE(f))
                    self.arm_all()
                elif code == CREATE_THREAD_DEBUG_EVENT:
                    self.tids[tid] = w.HANDLE(_u(buf, u, self.arch.ptr))
                elif code == EXIT_THREAD_DEBUG_EVENT:
                    h = self.tids.pop(tid, None)
                    if h and h.value:
                        k32.CloseHandle(h)
                elif code == LOAD_DLL_DEBUG_EVENT:
                    h = _u(buf, u, self.arch.ptr)
                    if h:
                        k32.CloseHandle(w.HANDLE(h))
                elif code == EXCEPTION_DEBUG_EVENT:
                    ecode = _u(buf, u, 4)
                    addr = _u(buf, u + self.arch.exc_addr_off, self.arch.ptr)
                    if a.verbose:
                        print("  exception 0x%08X at 0x%X" % (ecode, addr))
                    if ecode == EXCEPTION_BREAKPOINT:
                        # ours, or the loader's initial break (which we swallow)
                        if addr in self.bps:
                            status = self.on_bp(tid, addr)
                        elif not self.armed_once:
                            # nothing armed yet -> the image is fully mapped now
                            self.armed_once = True
                            self.arm_all()
                    elif ecode == EXCEPTION_SINGLE_STEP:
                        status = self.on_single_step(tid)
                    elif ecode in (EXCEPTION_ACCESS_VIOLATION,
                                   EXCEPTION_ILLEGAL_INSTRUCTION,
                                   EXCEPTION_INT_DIVIDE_BY_ZERO,
                                   EXCEPTION_PRIV_INSTRUCTION):
                        if a.verbose:
                            try:
                                c = self.get_ctx(tid)
                                print("    rax=0x%X rbx=0x%X rdx=0x%X "
                                      "r12=0x%X r13=0x%X"
                                      % (self.reg(c, "rax"), self.reg(c, "rbx"),
                                         self.reg(c, "rdx"), self.reg(c, "r12"),
                                         self.reg(c, "r13")))
                            except Exception:
                                pass
                        self.error = self.error or ("exception 0x%08X at 0x%X"
                                                    % (ecode, addr))
                        status = DBG_EXCEPTION_NOT_HANDLED
                    else:
                        status = DBG_EXCEPTION_NOT_HANDLED
                elif code == EXIT_PROCESS_DEBUG_EVENT:
                    self.stopped = "process-exit"
            except Exception as exc:
                self.error = "%s: %s" % (type(exc).__name__, exc)
                self.stopped = "internal-error"
            finally:
                k32.ContinueDebugEvent(_u(buf, 4, 4), tid, status)
        return None

    def cleanup(self, detached=False):
        try:
            if self.pending is not None:
                self.finish_pending()
        except Exception:
            self.pending = None
        for addr in list(self.bps):
            try:
                self.disarm(addr)
            except Exception:
                pass
        if self.hproc is not None:
            if detached or self.a.detach:
                k32.DebugActiveProcessStop(self.pid)
            else:
                k32.TerminateProcess(self.hproc, 0)
            k32.CloseHandle(self.hproc)
            self.hproc = None
        if self.pinfo is not None:
            for off in (self.arch.ptr, 2 * self.arch.ptr):
                h = w.HANDLE(_u(self.pinfo, off, self.arch.ptr))
                if h.value:
                    k32.CloseHandle(h)
            self.pinfo = None

# ------------------------------------------------------- site discovery ------
def sites_from_payload(path, section=None, want=32):
    """RVAs of indirect jumps in an unpacked payload (same view as vmfind)."""
    import defus as _dz            # noqa: F401  (puts GhidrOrean on sys.path)
    import cfgpass                 # noqa: E402
    import oreandec                # noqa: E402
    import xrkdsm                  # noqa: E402
    d, _base, secs = oreandec.load_pe(path)
    section = section or oreandec.pick_section(secs)
    if section not in secs:
        raise SystemExit("%s: no %s section (have: %s)"
                         % (path, section, ", ".join(sorted(secs))))
    s = secs[section]
    data = d[s["raw"]:s["raw"] + s["rs"]]
    ins, _by, _bad = cfgpass.scan(data)
    out = []
    for x in ins:
        if x.rk.ID != xrkdsm.OP_JMP:
            continue
        t = x.rk.operand[0].TID()
        if t in (xrkdsm.TID_REG, xrkdsm.TID_MEM):
            out.append(s["va"] + x.addr)
            if len(out) >= want:
                break
    return out


def selftest_vm(a):
    """Differential test: recover a *known* opcode -> handler map from a live VM.

    vmfix.build() writes a real PE whose dispatch is `jmp rdx` and whose
    opcode -> handler map is known by construction.  Everything after the
    breakpoint (site RVA, handler RVA, opcode register) is compared against it.
    """
    import vmfix
    import vmlift
    d = tempfile.mkdtemp(prefix="vmfix_")
    exe = os.path.join(d, "fixvm.exe")
    gt = vmfix.build(exe)
    a.target = exe
    a.bits = _pe_bits(exe)
    a.bp_rva = [gt["site_rva"]]
    a.bp_entry = False
    a.follow = 2
    a.until_return = True           # step each handler until it returns
    a.max_steps = 64
    a.snapshot = gt["vregs_bytes"]  # VM state before/after every opcode
    a.snapshot_from = "reg:r13"
    a.max_hits = 64
    a.timeout = 30
    a.ctx_ptr = None
    a.detach = False
    a.args = ""
    a.target_args = []
    a.new_console = False
    a.out = os.path.join(d, "fixvm.jsonl")
    print("selftest-vm: fixture %s (%d bytes, site +%X, %d handlers)"
          % (exe, gt["size"], gt["site_rva"], gt["opcodes"]))
    if a.bits != struct.calcsize("P") * 8:
        raise SystemExit("bitness mismatch - nothing to test here")

    t = Tracer(a)
    t.out = open(a.out, "w", encoding="utf-8")
    t.out.write(json.dumps({"kind": "header", "selftest": "vm", "target": exe,
                            "bits": a.bits, "sites": a.bp_rva,
                            "follow": a.follow, "time": time.time(),
                            "snapshot": a.snapshot,
                            "snapshot_from": a.snapshot_from,
                            "until_return": bool(a.until_return)},
                           sort_keys=True) + "\n")
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    err = t.run()
    t.cleanup()
    t.out.close()

    site_va = gt["image_base"] + gt["site_rva"]
    hits = [h for h in t.hits if h.get("site") == site_va]
    check("process created at the preferred base", t.base == gt["image_base"],
          "base 0x%X" % (t.base or 0))
    check("dispatch site reached", len(hits) >= gt["opcodes"],
          "%d hit(s)" % len(hits))
    check("site RVA matches the fixture",
          bool(hits) and all(h["site_in_module"] == gt["site_rva"]
                             for h in hits))
    lo = gt["image_base"] + gt["entry_rva"]
    hi = gt["image_base"] + gt["site_rva"] + 0x1000
    check("every target inside the image",
          bool(hits) and all(lo <= (h.get("target") or 0) < hi for h in hits))

    _header, recs = vmlift.load(a.out)
    res = vmlift.analyse(recs, "reg:eax", 0xFF, 0)
    got = {op: o["handlers"].most_common(1)[0][0] for op, o in res["ops"].items()}
    check("opcodes recovered: %d" % gt["opcodes"],
          set(got) == set(gt["expect"]),
          "got %s" % " ".join("%X" % o for o in sorted(got)))
    bad = {op: (got.get(op), want) for op, want in gt["expect"].items()
           if got.get(op) != want}
    check("every opcode lands on the handler built for it", not bad,
          "" if not bad else
          ", ".join("%X: +%X != +%X" % (op, (g or 0) - gt["image_base"], w)
                    for op, (g, w) in sorted(bad.items())))
    check("no opcode conflict", not res["conflicts"])
    check("no hit without an opcode", res["no_opcode"] == 0,
          "%d" % res["no_opcode"])
    check("distinct handlers: %d" % gt["opcodes"],
          res["handlers"] == gt["opcodes"], "%d" % res["handlers"])
    asm = vmlift.render_asm(res, bits=a.bits)
    check("listing names the dispatch site",
          ("site_%X" % gt["site_rva"]) in asm)
    check("listing has a direct-target chain", "cmp" in asm and "je" in asm)

    # ---- level 2: semantics, proven against the same ground truth ---------
    truncated = [h for h in hits if not h.get("returned")]
    check("every handler ran to its return jump", not truncated,
          "%d truncated" % len(truncated))
    sem = vmlift.derive(recs, "reg:eax", 0xFF, 0, 4)
    check("state snapshots cover every opcode",
          set(sem["ops"]) == set(gt["semantics"]) and sem["skipped"] == 0,
          "%d opcode(s), %d skipped" % (len(sem["ops"]), sem["skipped"]))
    mine = {op: " ; ".join(o["text"]) for op, o in sem["ops"].items()}
    bad_sem = {op: (mine.get(op),
                    gt["semantics"].get(op))
               for op in gt["semantics"] if mine.get(op) != gt["semantics"][op]}
    check("semantics equal what the handlers were built to do", not bad_sem,
          "" if not bad_sem else
          "; ".join("%X: %r != %r" % (op, g, w)
                    for op, (g, w) in sorted(bad_sem.items())))
    orc = vmlift.verify(sem, recs, "reg:eax", 0xFF, 0, 4)
    check("replay oracle reproduces every hit byte-exactly",
          orc["bad"] == 0 and orc["ok"] == len(recs),
          "%d/%d ok, %d bad" % (orc["ok"], len(recs), orc["bad"]))
    native = vmlift.render_semantics(sem, res, orc)
    check("native listing carries one body per opcode",
          all(("op_%02X:" % op) in native for op in gt["semantics"]))
    print("selftest-vm: recovered semantics")
    for op in sorted(sem["ops"]):
        print("   0x%02X  %s" % (op, mine.get(op, "?")))

    for i, (name, ok, detail) in enumerate(checks, 1):
        print("%s %2d. %s%s" % ("PASS" if ok else "FAIL", i, name,
                                ("  (%s)" % detail) if detail else ""))
    passed = sum(1 for _n, ok, _d in checks if ok)
    print("\nselftest-vm: %s (%d/%d)   trace: %s"
          % ("PASS" if passed == len(checks) else "FAIL", passed,
             len(checks), a.out))
    if err or t.error:
        print("note      : %s" % (err or t.error))
    return 0 if passed == len(checks) else 1


# ------------------------------------------------------------- self test ------
def selftest(a):
    """Prove the debugger machinery on a benign binary (entry point + 1 step)."""
    exe = a.selftest_target or os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "where.exe")
    if not os.path.exists(exe):
        raise SystemExit("selftest target not found: %s" % exe)
    a.target = exe
    a.bits = _pe_bits(exe)
    host = struct.calcsize("P") * 8
    a.bp_rva = []
    a.bp_entry = True
    a.follow = 1
    a.max_hits = 1
    a.timeout = 20
    a.ctx_ptr = None
    a.detach = False
    a.args = []
    print("selftest: %s (%d-bit target, %d-bit python)" % (exe, a.bits, host))
    if a.bits != host:
        raise SystemExit("bitness mismatch - nothing to test here")

    entry = _pe_entry(exe)[0]
    a.out = os.path.join(tempfile.gettempdir(), "vmtrace_selftest.jsonl")
    t = Tracer(a)
    t.out = open(a.out, "w", encoding="utf-8") if a.out else None
    if t.out:
        t.out.write(json.dumps({"kind": "header", "selftest": True,
                                "target": exe, "bits": a.bits},
                               sort_keys=True) + "\n")
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    err = t.run()
    base = t.base
    mz = t.read(base, 2) if base else None
    t.cleanup()                 # flushes a hit that was still in flight
    if t.out:
        t.out.close()
    hits = [h for h in t.hits if h.get("site") == base + entry]
    check("process created under debugger", t.pid > 0, "pid %d" % t.pid)
    check("module base known", base > 0, "0x%X" % base)
    check("ReadProcessMemory at base == 'MZ'", mz == b"MZ", repr(mz))
    check("entry breakpoint hit", bool(hits), "%d hit(s)" % len(hits))
    steps = (hits[0].get("steps") or []) if hits else []
    check("single-step produced code bytes", bool(steps) and bool(steps[0][1]),
          "%s" % (steps[0][:2] if steps else None))
    tgt = (hits[0].get("target") if hits else 0) or 0
    check("target inside the module", base <= tgt < base + 0x4000000,
          "0x%X" % tgt)
    check("eflags readable (bit1 set)", bool(hits) and bool(hits[0]["eflags"] & 2),
          "eflags 0x%X" % (hits[0]["eflags"] if hits else 0))
    bad = 0
    for name, ok, detail in checks:
        print("  [%s] %-42s %s" % ("PASS" if ok else "FAIL", name, detail))
        bad += 0 if ok else 1
    for note in (err, t.error):
        if note:
            print("  note: %s" % note)
    print("selftest: %s (%d/%d)" % ("PASS" if not bad else "FAIL",
                                    len(checks) - bad, len(checks)))
    return 0 if not bad else 1


# ------------------------------------------------------------------- main -----
def build_args(argv=None):
    ap = argparse.ArgumentParser(
        description="runtime trace of a VM dispatcher (executes the target!)")
    ap.add_argument("target", nargs="?")
    ap.add_argument("--args", default="",
                    help="command line passed to the target (quoted, optional)")
    ap.add_argument("--exec", action="store_true",
                    help="actually launch the target (default: dry run)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the breakpoint plan only (the default)")
    ap.add_argument("--selftest", action="store_true",
                    help="run a benign system binary to validate the harness")
    ap.add_argument("--selftest-vm", action="store_true",
                    help="build a tiny VM (vmfix.py) and compare the recovered "
                         "opcode -> handler map against its ground truth")
    ap.add_argument("--selftest-target", default=None)
    ap.add_argument("--bp-rva", action="append", type=lambda s: int(s, 0),
                    default=[], help="RVA of an indirect-jump site (repeatable)")
    ap.add_argument("--auto-from", default=None,
                    help="unpacked payload to take indirect-jump RVAs from")
    ap.add_argument("--sites", type=int, default=32,
                    help="max sites taken from --auto-from (default 32)")
    ap.add_argument("--section", default=None,
                    help="section of --auto-from (default: first Oreans one)")
    ap.add_argument("--bp-entry", action="store_true",
                    help="also break at the PE entry point")
    ap.add_argument("--ctx-ptr", default=None,
                    help="register holding the VM opcode pointer (e.g. esi)")
    ap.add_argument("--ctx-ptr-off", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--ctx-len", type=int, default=4)
    ap.add_argument("--follow", type=int, default=1,
                    help="instructions to single-step inside the handler")
    ap.add_argument("--until-return", action="store_true",
                    help="step until the handler jumps back to the dispatch "
                         "site, i.e. record the whole opcode (level 2)")
    ap.add_argument("--max-steps", type=int, default=256,
                    help="step budget per hit with --until-return")
    ap.add_argument("--snapshot", type=int, default=0, metavar="BYTES",
                    help="record BYTES of VM state before/after each opcode "
                         "(needs --snapshot-from or --ctx-ptr)")
    ap.add_argument("--snapshot-from", default="ctx", metavar="SPEC",
                    help="base of the snapshot: reg:NAME or ctx (default)")
    ap.add_argument("--max-hits", type=int, default=200)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--out", default="vmtrace.jsonl")
    ap.add_argument("--detach", action="store_true",
                    help="detach instead of terminating the target")
    ap.add_argument("--new-console", action="store_true")
    ap.add_argument("--cwd", default=None)
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every debug event (arm/exception/exit)")
    argv = list(sys.argv[1:] if argv is None else argv)
    tail = []
    if "--" in argv:                      # everything after -- goes to the target
        i = argv.index("--")
        tail = argv[i + 1:]
        argv = argv[:i]
    a = ap.parse_args(argv)
    if tail:
        a.args = " ".join(shlex.quote(x) for x in tail)
    a.target_args = shlex.split(a.args) if a.args else []
    return a


def main(argv=None):
    a = build_args(argv)
    if a.selftest:
        return selftest(a)
    if a.selftest_vm:
        return selftest_vm(a)
    if not a.target:
        raise SystemExit("need a target (or --selftest)")
    if not os.path.exists(a.target):
        raise SystemExit("%s: no such file" % a.target)
    a.bits = _pe_bits(a.target)
    host = struct.calcsize("P") * 8
    if a.bits != host and a.exec:
        raise SystemExit("%s is %d-bit but this python is %d-bit - a debugger "
                         "cannot cross WOW64; use %s"
                         % (a.target, a.bits, host, _other_python(a.bits)))
    if a.bits != host:
        print("note   : %d-bit target, %d-bit python - the plan is fine, but "
              "--exec needs %s" % (a.bits, host, _other_python(a.bits)))
    if a.auto_from:
        got = sites_from_payload(a.auto_from, section=a.section, want=a.sites)
        a.bp_rva.extend(got)
        print("sites: %d indirect jumps taken from %s" % (len(got), a.auto_from))
    if not a.bp_rva and not a.bp_entry:
        raise SystemExit("no breakpoints: pass --bp-rva/--auto-from/--bp-entry")
    if a.ctx_ptr and a.ctx_ptr not in _Arch(a.bits).reg_off:
        raise SystemExit("--ctx-ptr: unknown register %r" % a.ctx_ptr)
    if a.snapshot:
        spec = (a.snapshot_from or "ctx").strip()
        if spec.lower().startswith("reg:"):
            nm = spec.split(":", 1)[1].strip().lower()
            if nm not in _Arch(a.bits).reg_off:
                raise SystemExit("--snapshot-from: unknown register %r" % nm)
        elif not a.ctx_ptr:
            raise SystemExit("--snapshot: pass --snapshot-from reg:NAME "
                             "(or --ctx-ptr for the ctx base)")

    print("target : %s (%d-bit)" % (a.target, a.bits))
    print("sites  : %d%s" % (len(a.bp_rva),
                             "" if not a.bp_rva else
                             "  e.g. " + " ".join("+%X" % r for r in a.bp_rva[:6])))
    if a.snapshot:
        print("state  : %d bytes at %s%s" %
              (a.snapshot, a.snapshot_from or "ctx",
               ", handler stepped until it returns" if a.until_return
               else ", --follow %d" % a.follow))
    if not a.exec:
        print("\nDRY RUN - nothing was launched.  Add --exec to trace.")
        return 0

    t = Tracer(a)
    t.out = open(a.out, "w", encoding="utf-8")
    t.out.write(json.dumps({"kind": "header", "target": a.target, "bits": a.bits,
                            "target_args": a.target_args, "sites": a.bp_rva,
                            "follow": a.follow, "time": time.time(),
                            "snapshot": a.snapshot,
                            "snapshot_from": a.snapshot_from,
                            "until_return": bool(a.until_return)},
                           sort_keys=True) + "\n")
    print("tracing (Ctrl-C stops; the target is terminated afterwards)")
    print("executing: the target is launched under the debugger. Untrusted")
    print("           samples belong in a throw-away VM; --detach leaves it")
    print("           running instead of terminating it.")
    try:
        err = t.run()
    except KeyboardInterrupt:
        err = "interrupted"
        t.stopped = "interrupted"
    t.cleanup()
    t.out.close()
    print("\nhits      : %d  (%d distinct sites, %d distinct targets)"
          % (len(t.hits), len(t.sites_seen), len(t.targets)))
    print("stopped   : %s" % (t.stopped or "?"))
    if err or t.error:
        print("note      : %s" % (err or t.error))
    print("trace     : %s" % a.out)
    print("next      : python _analysis\\vmlift.py %s --opcode-from %s"
          % (a.out, "mem" if a.ctx_ptr else "reg:eax"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
