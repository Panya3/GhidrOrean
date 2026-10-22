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

