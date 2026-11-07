#!/usr/bin/env python3
"""
Recover method parameters from the firmware's own RPC handlers.

Why this exists
---------------
The catalog documents which methods exist; it has almost nothing to say about
what they accept. Until now the only sources were the UI's minified bundles
(the call-site literal, which yields about a third of the methods) and asking
the router to complain about a missing argument -- and the router's schema
layer answers "Parameter not found" without ever naming the parameter.

Both were the wrong artifact. The handlers themselves live in the firmware at
usr/lib/oui-httpd/rpc, and they are readable:

  * 18 are plain Lua source. Parameters are the keys read off the single
    argument, `params.<key>`, and 8 of the files additionally carry vendor doc
    comments -- @in / @out lines with typed field paths, plus literal
    @in-example / @out-example JSON. Those are the vendor's own documentation
    and the only source here that states intent rather than behaviour.

  * 37 are Lua 5.1 bytecode. `function M.get_config(params)` compiles to a
    CLOSURE plus a SETTABLE whose key is the *string constant* "get_config", so
    the main chunk's constant table holds the method names and each method's
    nested prototype holds the keys it actually reads. Reading a key off
    `params` is a GETTABLE/SETTABLE whose base register is the argument, so a
    few dozen lines of disassembly turn a prototype into a parameter list.

  * 10 are ELF. Not read here: their policy tables would need real reverse
    engineering, and guessing is worse than saying nothing.

What "params" means here
------------------------
Keys the handler *reads* off the request. That is behaviour, not a contract:
a key can be read and ignored, or validated inside a helper whose constants
this pass does not follow, and a method that builds a response can mention
strings that are not inputs at all. So every entry is labelled with where it
came from, and the doc-comment entries -- which do state intent -- win when
both exist. Verify against a live call before trusting a write.

    ./extract_handler_docs.py /tmp/opencode/sq            # report
    ./extract_handler_docs.py /tmp/opencode/sq --apply    # stamp into catalog
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

import luaread

HERE = Path(__file__).resolve().parent
CATALOG = HERE / "api_description.json"

# Lua 5.1 opcodes, only the ones this pass needs.
# Instruction semantics, calibrated against files compiled by this same luac
# from known source rather than read out of a spec: this build is not stock.
# GETTABLE(6) puts the *key* in B and the *base* in C, the reverse of the
# documented 5.1 layout, and the table-store opcode is 9. A B/C operand of 256
# or more is a constant index (value - 256); below that it is a register.
OP_GETTABLE, OP_SETTABLE, OP_CLOSURE, OP_GETUPVAL = 6, 9, 36, 4
K_MASK = 256


def keys_read(proto):
    """Keys read off a prototype's first argument.

    Deliberately narrow, because narrow is what proved correct: the handler's
    argument is R0, so only GETTABLE whose base register is R0 counts, and only
    when the function actually declares a parameter (a `get_config()` with no
    argument uses R0 for a uci cursor, and reading it produced phantom
    parameters). Promoting upvalue-loaded registers to "the argument" was tried
    and rejected -- it upvalues `uci` and `fs` too, and turned
    kmwan.set_sensitivity's single real key, sensitivity, into five where four
    were file and json helpers.
    """
    if proto["numparams"] < 1:
        return []
    names = [c.decode("utf-8", "replace") if isinstance(c, bytes) else None
             for c in proto["consts"]]
    out = []
    for raw in proto["code"]:
        i = struct.unpack("<I", raw)[0]
        op = i & 0x3F
        b = (i >> 14) & 0x1FF
        c = (i >> 23) & 0x1FF
        if op == OP_GETTABLE and b >= K_MASK and c == 0:
            k = names[b - K_MASK] if b - K_MASK < len(names) else None
            if k and k not in out:
                out.append(k)
    return out


def disasm(proto):
    """Parameter names for one prototype."""
    return keys_read(proto)

# Both declaration styles appear across the handlers: `function M.get_config(p)`
# and `M.get_config = function(p)`. Matching only the first silently drops whole
# modules -- wg_client is entirely the second style.
FUNC_RE = re.compile(
    r"^\s*(?:function\s+M[.:](\w+)\s*\(|M[.:](\w+)\s*=\s*function\s*\()", re.M)
PARAM_RE = re.compile(r"\bparams(?:\s*\.\s*(\w+)|\s*\[\s*[\"'](\w+)[\"']\s*\])")
DOC_FIELD = re.compile(r"^\s*@(in|out)\s+(\S+)\s+([\w.\[\]]+)\s*(.*)$")
DOC_TAG = re.compile(r"^\s*@(method-name|method-desc|in-example|out-example)\s*:?\s*(.*)$")
DOC_BLOCK = re.compile(r"--\[\[.*?--\]\]", re.S)


def bytecoded_methods(path: Path):
    """method -> parameter keys, for one compiled handler.

    `function M.get_config(params)` compiles to a CLOSURE into a register and a
    table-store whose key is the constant "get_config", so the main chunk's code
    pairs names with bodies. The body's own reads of its argument are the
    parameters.
    """
    main, allp, _ = luaread.load(path.read_bytes())
    consts = main["consts"]
    names = [c.decode("utf-8", "replace") if isinstance(c, bytes) else None
             for c in consts]
    protos = main["protos"]

    methods: dict[str, dict] = {}
    reg: dict[int, int] = {}          # register -> prototype index
    for raw in main["code"]:
        i = struct.unpack("<I", raw)[0]
        op = i & 0x3F
        a = (i >> 6) & 0xFF
        b = (i >> 14) & 0x1FF
        c = (i >> 23) & 0x1FF
        if op == OP_CLOSURE:
            idx = b                      # this build keeps the index in B
            if idx < len(protos):
                reg[a] = idx
        elif op == OP_SETTABLE and c >= K_MASK and b in reg:
            name = names[c - K_MASK]
            if name:
                methods.setdefault(name, protos[reg[b]])

    out = {}
    for name, body in methods.items():
        out[name] = sorted(disasm(body))
    return out


def source_methods(path: Path):
    """method -> parameters and vendor docs, for one plain-Lua handler."""
    text = path.read_text(encoding="utf-8", errors="replace")
    docs = parse_doc_blocks(text)
    out = {}
    ends = [m.start() for m in FUNC_RE.finditer(text)]
    for n, m in enumerate(FUNC_RE.finditer(text)):
        name = m.group(1) or m.group(2)
        stop = ends[n + 1] if n + 1 < len(ends) else len(text)
        body = text[m.end():stop]
        keys = set()
        for mm in PARAM_RE.finditer(body):
            keys.add(mm.group(1) or mm.group(2))
        entry = {"params": sorted(keys), "source": "handler source"}
        if name in docs:
            entry["docs"] = docs[name]
        out[name] = entry
    return out


def parse_doc_blocks(text: str):
    """The vendor's @in/@out/@*-example comments, keyed by method name."""
    out = {}
    for block in DOC_BLOCK.findall(text):
        rec: dict = {"in": [], "out": [], "desc": ""}
        for line in block.splitlines():
            tag = DOC_TAG.match(line)
            if tag:
                key, val = tag.group(1), tag.group(2).strip()
                if key == "method-name":
                    rec["method"] = val
                elif key == "method-desc":
                    rec["desc"] = val
                elif key == "in-example":
                    rec["in_example"] = val
                elif key == "out-example":
                    rec["out_example"] = val
                continue
            f = DOC_FIELD.match(line)
            if f:
                rec[f.group(1)].append(
                    {"where": f.group(1), "type": f.group(2),
                     "path": f.group(3), "note": f.group(4).strip()})
        name = rec.pop("method", None)
        if name:
            out[name] = rec
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("rootfs", type=Path, help="extracted firmware rootfs")
    ap.add_argument("--apply", action="store_true",
                    help="stamp findings into the catalog")
    ap.add_argument("--catalog", type=Path, default=CATALOG,
                    help=f"catalog to stamp (default {CATALOG.name}); use the "
                         "merged file so stamping cannot clobber provenance")
    ap.add_argument("--module", default="", help="only this module")
    args = ap.parse_args()
    catalog_path = args.catalog

    rpc = args.rootfs / "usr/lib/oui-httpd/rpc"
    if not rpc.is_dir():
        print(f"no handler directory at {rpc}", file=sys.stderr)
        return 1

    catalog = json.loads(catalog_path.read_text()) if catalog_path.exists() else {}
    stamped = 0
    per_module = {}

    for path in sorted(rpc.iterdir()):
        if not path.is_file():
            continue
        module = re.sub(r"\.so$|\.lua$", "", path.name)
        if args.module and module != args.module:
            continue
        head = path.read_bytes()[:4]
        if head[:4] == b"\x7fELF":
            # 10 handlers are compiled ARM code. Their blobmsg policy tables
            # would name the parameters too, but reading them means real
            # reverse engineering, and a guess there is worse than a gap.
            print(f"  {module:20s} {'ELF':8s}  -- not read (binary policy table)")
            continue
        try:
            if head == b"\x1bLua":
                found = {k: {"params": v, "source": "handler bytecode"}
                         for k, v in bytecoded_methods(path).items()}
                kind = "bytecode"
            else:
                found = source_methods(path)
                kind = "source"
        except Exception as exc:
            print(f"  ! {module}: {type(exc).__name__}: {exc}")
            continue
        per_module[module] = (kind, found)
        n_doc = sum(1 for v in found.values() if v.get("docs"))
        n_par = sum(1 for v in found.values() if v["params"])
        print(f"  {module:20s} {kind:8s} {len(found):3d} methods  "
              f"{n_par:3d} with params  {n_doc:2d} vendor-documented")

        if args.apply:
            bucket = catalog.setdefault(module, {"case_groups_data": {}})
            bucket = catalog[module].setdefault("case_groups_data", {})
            for name, info in found.items():
                entry = bucket.setdefault(name, {"data": {"desp": ""}})
                entry["params_static"] = info["params"]
                entry["params_origin"] = info["source"]
                if info.get("docs"):
                    entry["vendor_docs"] = info["docs"]
                stamped += 1

    with_params = sum(1 for _, f in per_module.values() for v in f.values() if v["params"])
    with_docs = sum(1 for _, f in per_module.values() for v in f.values() if v.get("docs"))
    total = sum(len(f) for _, f in per_module.values())
    print(f"\n{total} methods recovered from {len(per_module)} handlers: "
          f"{with_params} with parameters, {with_docs} with vendor doc comments")

    if args.apply:
        CATALOG.write_text(json.dumps(catalog, indent=1, sort_keys=True) + "\n")
        print(f"stamped {stamped} methods into {catalog_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
