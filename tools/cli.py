"""Shared CLI conventions for the offline tools in this directory.

`-h` / `--help` prints the tool's own docstring and exits 0; a missing positional
argument prints the same text and exits 2. Nothing in the toolbox should ever die
with a traceback just because it was invoked without arguments.

Usage:
    from cli import cli, die
    argv = cli(1, __doc__)      # -h handled, at least one positional required
    path = argv[0]
"""
import sys


def _show(doc, code):
    text = (doc or "").strip()
    if text:
        print(text)
    raise SystemExit(code)


def cli(minimum, doc, args=None):
    """Return argv[1:] (or `args`) after honouring -h/--help and arity."""
    argv = list(sys.argv[1:] if args is None else args)
    for a in argv:
        if a in ("-h", "--help"):
            _show(doc, 0)
    if len(argv) < minimum:
        _show(doc, 2)
    return argv


def need(argv, minimum, doc):
    """Same contract as cli(), for an argument list that is already parsed."""
    if len(argv) < minimum:
        _show(doc, 2)
    return argv


def die(msg, code=1):
    """One-line error on stderr, no traceback."""
    sys.stderr.write("error: %s\n" % msg)
    raise SystemExit(code)
