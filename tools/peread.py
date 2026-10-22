"""Minimal read-only PE parser shared by the toolbox.

Nothing here knows about Oreans bytecode or about GhidrOrean: it only answers
"where does this section live in the file" so the other tools can run against a
sample without pulling in the decoder (and therefore without needing a
GhidrOrean checkout just to unpack a file).

Pure CPython 3, standard library only.
"""
import struct

SEC = ".vlizer"
# Oreans names the section holding its VM bytecode differently per product and
# per build, so nothing here is tied to XIGNCODE's spelling.
SEC_FAMILY = (".vlizer", ".themida", ".winlicen", ".oreans", ".boot")


def pick_section(secs, prefer=SEC):
    """Name of the section holding the Oreans blob in `secs` (dict name -> info).

    `prefer` when present, else the first SEC_FAMILY member that is, else
    `prefer` again (so the caller's error message can name what it wanted).
    """
    if prefer in secs:
        return prefer
    for name in SEC_FAMILY:
        if name in secs:
            return name
    return prefer


def load_pe(path):
    """Return (file bytes, image base, {section name: dict(va, vs, raw, rs)})."""
    with open(path, "rb") as f:
        d = f.read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    if d[e:e + 4] != b"PE\0\0":
        raise SystemExit("not a PE file")
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    optsz = struct.unpack_from("<H", d, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    if magic == 0x10B:
        base = struct.unpack_from("<I", d, opt + 28)[0]
    else:
        base = struct.unpack_from("<Q", d, opt + 24)[0]
    secs = {}
    for i in range(nsec):
        o = opt + optsz + i * 40
        name = d[o:o + 8].rstrip(b"\0").decode("latin1", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
        secs[name] = dict(va=va, vs=vs, raw=ra, rs=rs)
    return d, base, secs


def section_header_offset(d, name):
    """File offset of section `name`'s header, plus (optional header, nsec).

    Rewriting a section in place needs the header offset (VirtualSize /
    SizeOfRawData) and the optional header (SectionAlignment / SizeOfImage).
    """
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    optsz = struct.unpack_from("<H", d, e + 20)[0]
    opt = e + 24
    sh = opt + optsz
    for i in range(nsec):
        o = sh + i * 40
        if d[o:o + 8].rstrip(b"\0").decode("latin1") == name:
            return o, opt, nsec
    raise SystemExit("section %s not found" % name)
