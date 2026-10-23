#!/usr/bin/env python3
"""test_devirt_identity.py - unit checks for devirt.py's effect model.

Where the audit is allowed to relax (value-preserving instructions) and where
it must not (32-bit ops in long mode zero-extend the parent register), plus the
`_noop` cases that used to be misclassified.

    python test_devirt_identity.py        # 0 = pass
"""
import sys

import devirt


def one(hexstr, bits):
    blob = bytes.fromhex(hexstr)
    dec, bad = devirt.decode(blob, 0x1000, bits)
    assert not bad, (hexstr, bits, bad)
    for off, x in dec.items():
        if 0 <= off < 0x1000:
            return x
    raise AssertionError("nothing decoded: %s" % hexstr)


CASES = [
    # (bytes, bits, text, identity?, noop-when-flags-dead?)
    ("83c000", 32, "add eax, 0", True, True),
    ("83c000", 64, "add eax, 0", False, True),      # defines all of RAX
    ("4883c000", 64, "add rax, 0", True, True),
    ("89c0", 32, "mov eax, eax", True, True),
    ("89c0", 64, "mov eax, eax", False, True),      # zero-extends
    ("4889c0", 64, "mov rax, rax", True, True),
    ("8d00", 32, "lea eax, [eax]", True, True),
    ("488d00", 64, "lea rax, [rax]", True, True),
    ("8d00", 64, "lea eax, [eax]", False, False),   # zero-extends: not identity
    ("8d4000", 32, "lea eax, [eax]", True, True),    # same, with a +0 disp
    ("83e0ff", 32, "and eax, 0xffffffff", True, True),
    ("4883e0ff", 64, "and rax, -1", True, True),
    ("83c8ff", 32, "or eax, 0xffffffff", False, False),   # constant, not noop
    ("83c801", 32, "or eax, 1", False, False),
    ("c1e000", 32, "shl eax, 0", True, True),
    ("83f800", 32, "cmp eax, 0", False, False),     # reads, writes only flags
    ("90", 32, "nop", True, True),
]

# the ledger: a value-preserving cut must keep every register it names
FLAG_ONLY = {"cmp", "test"}


def main():
    bad = 0
    for hexstr, bits, text, ident, noop in CASES:
        x = one(hexstr, bits)
        got_id = devirt._identity(x)
        got_np = devirt._noop(x, True)
        tag = "%s (%d-bit)" % (text, bits)
        if got_id != ident:
            print("FAIL identity %-22s got %s want %s" % (tag, got_id, ident))
            bad += 1
        if got_np != noop:
            print("FAIL noop     %-22s got %s want %s" % (tag, got_np, noop))
            bad += 1
        # an instruction that is identity may write no register it does not
        # also read (it keeps the value) - that is what makes the audit legal
        if ident and got_id:
            for r in x.writes:
                if r not in x.reads and x.mnem not in FLAG_ONLY:
                    print("FAIL identity %-22s writes %r without reading it"
                          % (tag, r))
                    bad += 1
    print("%d/%d case(s) ok" % (len(CASES) - bad if bad <= len(CASES) else 0,
                                len(CASES)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
