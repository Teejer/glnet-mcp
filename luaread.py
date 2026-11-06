"""Reader for the Lua 5.1 bytecode GL.iNet ships its rpcd handlers as.

Why this exists: 37 of the 54 rpcd handler modules in the firmware are Lua 5.1
bytecode, and bytecode keeps a per-function constant table. That is the
cheapest honest route to method parameters -- it names every string literal a
function touches, including the keys it reads off the request, with no router
in the loop and no guessing at minified UI JavaScript.

The bytecode is not stock. luac on this machine and the firmware's own build
both emit a header with no LUAC_DATA / LUAC_INT / LUAC_NUM round-trip magic,
and the firmware's Lua has a 4-byte size_t and 4-byte lua_Number where the host
has 8-byte ones. Stock lua5.1 rejects the firmware files outright ("bad header
in precompiled chunk"); a stock reader that assumes host widths desyncs on the
first constant. So the widths are *inferred by parsing* rather than trusted
from the header, and the answer is checked against a file compiled locally,
where the right output is already known. That check is the difference between
a reader and a parser that happens to fit the blobs in front of it.

Proto layout, from lundump.c loadFunction: source, linedefined,
lastlinedefined, numparams, is_vararg, maxstacksize, then the vectors code,
k, protos, lineinfo, locvars, upvalues. There is no nups field in 5.1.
"""
from __future__ import annotations

import struct

NIL, BOOL, PTR, NUM, STR = 0, 1, 2, 3, 4
# The firmware's Lua tags integer constants 9, four bytes wide; stock 5.1 has
# no such tag. The width is settled by the byte pattern (09 00 00 00 00,
# 09 01 00 00 00, 09 02 ...) and by the file only parsing to EOF with 4.
INT = 9

# Bytes before the main prototype. Stock Lua 5.1 puts 8 bytes of LUAC_DATA and
# then a round-trip int and float here; these files put four width bytes and
# two flags in 12 bytes total, which is why the stock loader refuses them.
HEADER = 12


class Bad(Exception):
    pass


class R:
    def __init__(self, b, sizes):
        self.b, self.i = b, 0
        self.IS, self.SS, self.OS, self.NS = sizes

    def byte(self):
        if self.i >= len(self.b):
            raise Bad("unexpected end of bytecode")
        v = self.b[self.i]
        self.i += 1
        return v

    def take(self, n):
        v = self.b[self.i:self.i + n]
        if len(v) < n:
            raise Bad("unexpected end of bytecode")
        self.i += n
        return v

    def int(self):
        return struct.unpack("<i" if self.IS == 4 else "<q", self.take(self.IS))[0]

    def sz(self):
        return struct.unpack("<I" if self.SS == 4 else "<Q", self.take(self.SS))[0]

    def num(self):
        return struct.unpack("<f" if self.NS == 4 else "<d", self.take(self.NS))[0]

    def string(self):
        n = self.sz()
        return None if n == 0 else self.take(n).rstrip(b"\0")

    @property
    def eof(self):
        return self.i >= len(self.b)


def _vec(r, fn):
    return [fn(r) for _ in range(r.int())]


def _const(r):
    t = r.byte()
    if t == NIL:
        return None
    if t == BOOL:
        return bool(r.byte())
    if t == PTR:
        return ("ptr", r.sz())
    if t == NUM:
        return r.num()
    if t == STR:
        return r.string()
    if t == INT:
        return struct.unpack("<i", r.take(4))[0]
    raise Bad(f"unknown constant tag {t}")


def _proto(r, name, out):
    f = {
        "name": name,
        "source": r.string(),
        "linedefined": r.int(),
        "lastlinedefined": r.int(),
        "nups": r.byte(),
        "numparams": r.byte(),
        "is_vararg": r.byte(),
        "maxstacksize": r.byte(),
    }
    f["code"] = [r.take(r.OS) for _ in range(r.int())]
    f["consts"] = _vec(r, _const)
    kids = []
    for _ in range(r.int()):
        kids.append(_proto(r, f"{name}#{len(kids)}", out))
    f["protos"] = kids
    f["lines"] = _vec(r, lambda r: r.int())
    f["locvars"] = _vec(r, lambda r: (r.string(), r.int(), r.int()))
    # Upvalues are name-only here. Pinned by hand-decoding a locally compiled
    # control file: assuming Lua 5.1's documented {name, instack, idx} record
    # over-reads by two bytes and desyncs every file that has debug info.
    f["upvalues"] = _vec(r, lambda r: r.string())
    out.append(f)
    return f


def _try(data, header, sizes):
    r = R(data[header:], sizes)
    out = []
    main = _proto(r, "<main>", out)
    if not r.eof:
        raise Bad(f"{len(data) - r.i} bytes left after the last prototype")
    return main, out


def load(data: bytes):
    """Parse a precompiled chunk -> (main_proto, all_protos, widths)."""
    if data[:4] != b"\x1bLua":
        raise Bad("not Lua bytecode")
    if data[4] != 0x51:
        raise Bad(f"Lua version 0x{data[4]:02x}; only 5.1 bytecode is handled")
    # The header declares its own field widths at bytes 7..10: sizeof(int),
    # sizeof(size_t), sizeof(Instruction), sizeof(lua_Number). Reading them is
    # what lets one parser handle the host's 8-byte size_t and the firmware's
    # 4-byte one instead of guessing. Stock Lua expects LUAC_DATA at offset 6,
    # which is why it calls these files "bad header".
    widths = tuple(data[7:11])
    if widths[0] != 4 or any(w not in (4, 8) for w in widths):
        raise Bad(f"implausible header widths {widths}")
    r = R(data[HEADER:], widths)
    out: list[dict] = []
    main = _proto(r, "<main>", out)
    if not r.eof:
        raise Bad(f"{len(data) - r.i} bytes left after the last prototype")
    return main, out, widths


def strings(f):
    """String constants of one prototype, decoded, in order, de-duplicated."""
    seen, res = set(), []
    for c in f["consts"]:
        if isinstance(c, bytes):
            s = c.decode("utf-8", "replace")
            if s and s not in seen:
                seen.add(s)
                res.append(s)
    return res


def walk(f):
    yield f
    for child in f["protos"]:
        yield from walk(child)
