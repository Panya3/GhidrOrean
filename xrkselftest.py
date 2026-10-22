"""Self test for the xrk* modules: decode a few known x86 encodings.

Run from this directory:   python xrkselftest.py
Exits non-zero when a case does not match, so it can gate a commit.
"""
from xrkdsm import XrkDecode, XrkText

CASES = (
	# raw bytes, expected instruction text, expected length in bytes
	(b'\x55', 'PUSH EBP', 1),
	(b'\x8b\xec', 'MOV EBP,ESP', 2),
	(b'\xb8\x01\x00\x00\x00', 'MOV EAX,0x1', 5),
	(b'\x81\xec\x00\x01\x00\x00', 'SUB ESP,0x100', 6),
	(b'\x33\xc0', 'XOR EAX,EAX', 2),
	(b'\xe8\x10\x00\x00\x00', 'CALL 0x10', 5),
	(b'\x8b\x44\x24\x04', 'MOV EAX,dword ptr [ESP+0x4]', 4),
	(b'\xc3', 'RETN', 1),
)


def main():
	fail = 0
	for raw, want, want_len in CASES:
		got_len, rki = XrkDecode(raw)
		got = XrkText(rki)
		ok = got_len == want_len and got == want
		if not ok:
			fail += 1
		print("{} {:12s} len={} {!r}{}".format(
			"pass" if ok else "FAIL", raw.hex(), got_len, got,
			"" if ok else "  (want len={} {!r})".format(want_len, want)))
	print("{}/{} cases pass".format(len(CASES) - fail, len(CASES)))
	return 1 if fail else 0


if __name__ == "__main__":
	raise SystemExit(main())
