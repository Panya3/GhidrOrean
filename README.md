Reimplementation of Deathway's Orean's Unvirtualizer but as Ghidra python scripts, so you can improve it.

Also some part of code based on https://github.com/67-6f-64/AntiOreans-CodeDevirtualizer

CISC/RISC/FISH/TIGER dirs are from original 1.8 olly plugin


* CISC complete

* TIGER mostly done



Use script Orean in ghidra. All another scripts are only parts.

 ! Set correct working dir in Orean.py so scripts can open configs


## Python 3

The helper modules (`xrkutil`, `xrktbl`, `xrkopr`, `xrkdsm`, `xrkasm`,
`thcisc`, `thtiger`, `thfish`, `thrisc`, `thwild`, `thobfus`, `thvm`) import
cleanly under CPython 3: ambiguous tab/space indentation and stray line
continuations are gone, `collections.Sequence` became `collections.abc.Sequence`,
`ConfigParser` became `configparser` (`read_file`), and the `xrkopr`/`xrkdsm`
import cycle is resolved lazily.  `Orean.py` itself stays a Ghidra/Jython
script -- it needs Ghidra globals (`currentAddress`, ...) and is not importable
on its own.

Verify with:

    python xrkselftest.py


## Offline tools (no Ghidra)

`tools/` holds CPython 3 helpers for the steps that do not need Ghidra at all:
unpack an Oreans container to a PE, decode a section's bytecode to text, and run
the dejunk pass outside the IDE.

    python tools/unpack_vlizer.py sample.xem sample_unpacked.exe
    python tools/xrkdecode.py sample_unpacked.exe --size 0x400
    python tools/defus_offline.py sample_unpacked.exe --rva <rva> --size <n>

See `tools/README.md` for what is and is not covered, and run
`python tools/selftest.py` (it builds its own inputs, no sample needed).
These are plain CPython 3 scripts, not Jython: `Orean.py` never imports them.

