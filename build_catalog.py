#!/usr/bin/env python3
"""
Rebuild the method catalog (api_description.json) from your router's firmware.

Why this exists
---------------
GL.iNet took the 4.x API documentation (dev.gl-inet.com) offline in January 2024
and has not restored it, and the API changes across releases. Firmware 4.10
deleted the entire `lan` module and moved DHCP reservations to `vlan_subnet`;
4.8 added a `hash-method` field to the login challenge. A catalog written against
one version is actively misleading on another -- it will hand you a confident
example request for a method the router no longer has.

So the catalog is not distributed with this project. It is generated from the
firmware you actually run, because that is the only firmware whose API matters.

What it does
------------
The router's own web UI ships inside the firmware image, and it is the best
available record of which methods exist. This script:

  1. finds the squashfs filesystem inside the .bin (by magic, not by a
     hard-coded offset -- offsets differ per model and version)
  2. extracts it with unsquashfs, or 7z if you do not have it
  3. greps every JavaScript bundle for the router's own call convention,
     ["sid", "<module>", "<method>"]
  4. optionally merges a pre-existing catalog for parameter documentation

Step 4 is optional: with no prior catalog you still get every method name, which
is enough for api_search and rpc_call to be useful. Methods seen in the UI are
tagged as confirmed-present; anything merged from an older catalog is tagged with
its origin, so a guess never reads like a fact.

Usage
-----
    ./build_catalog.py be9300-4.10.1_release1-1129-0918-1789732857.bin
    ./build_catalog.py /path/to/extracted/rootfs      # already unsquashed
    ./build_catalog.py firmware.bin --out ../server/api_description.json

Where to get the image: https://dl.gl-inet.com/ -- pick your model and channel.
Verify the download against the checksum the download page publishes; this script
will happily build a catalog out of a truncated or substituted file.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "api_description.json"

# ["sid","vlan_subnet","add_static_bind",t]   -- the router's own call convention.
# Minification changes the surrounding variable names but not this shape. Group 3
# captures the payload argument as written: "{}", a bare variable, or nothing at
# all when the UI calls the method with only three elements.
CALL_RE = re.compile(
    r'\[\s*"sid"\s*,\s*"([a-z0-9_-]+)"\s*,\s*"([a-z0-9_]+)"'
    r'(?:\s*,\s*([^\]\n]{0,80}))?\s*\]'
)

# The minified API wrapper that contains a call site, e.g. addPeer:function(t){...}
# When the payload is a variable rather than a literal, this name is the handle
# for finding the caller that actually constructs it.
WRAPPER_RE = re.compile(r'([A-Za-z_$][\w$]{2,40})\s*:\s*function')


def classify(arg: str | None) -> tuple[str, str]:
    """
    (arg_style, arg_expr) from how the UI writes the call.

    This matters more than it looks: "the router calls this with three elements
    and no payload" is a fact you can only get from the UI, and it is what makes
    a method safe to invoke without guessing arguments. Sending {} to something
    that validates its arguments can fail; sending nothing at all to
    get_static_bind_list on 4.10 is what the UI actually does.
    """
    if arg is None or not arg.strip():
        return "none", ""
    text = arg.strip().rstrip(",").strip()
    if text == "{}":
        return "empty_object", "{}"
    if re.fullmatch(r"[A-Za-z_$][\w$]*", text):
        return "variable", text
    return "expression", text[:80]


def ui_calls(root: Path) -> dict[str, dict[str, dict]]:
    """
    Every module.method the router's own UI invokes, with how it calls it.
    """
    found: dict[str, dict[str, dict]] = {}
    bundles = js_bundles(root)
    if not bundles:
        raise BuildError("no JavaScript bundles found -- extraction went wrong?")
    for path in bundles:
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", errors="replace") as fh:
                    text = fh.read()
            else:
                text = path.read_text(errors="replace")
        except OSError:
            continue
        for module, method, arg in CALL_RE.findall(text):
            entry = found.setdefault(module, {}).setdefault(method, {})
            style, expr = classify(arg)
            # If one bundle calls it with {} and another passes a payload, the
            # payload is the truth -- record the more informative of the two.
            rank = {"none": 0, "empty_object": 1, "variable": 2, "expression": 3}
            if rank[style] > rank.get(entry.get("arg_style", ""), -1):
                # Find the wrapper function this call sits inside.
                at = text.find(f'"{module}","{method}"')
                wrappers = WRAPPER_RE.findall(text[max(0, at - 220):at])
                entry["arg_style"] = style
                entry["arg_expr"] = expr
                entry["ui_api"] = wrappers[-1] if wrappers else ""
    if not found:
        raise BuildError(
            "bundles contained no [\"sid\", module, method] calls -- "
            "GL.iNet may have changed the call convention; extend CALL_RE"
        )
    return found

SQUASHFS_MAGIC = b"hsqs"

# Methods that appeared in 4.8-4.10 and so have no entry in any older catalog.
# Shapes below were read out of the router's own minified UI code inside the
# firmware image -- the call sites in www/views/gl-sdk4-ui-vlan.common.js -- not
# inferred from error messages. Without them the catalog confirms a method exists
# but cannot say what to send it, which forces blind trial against a live router.
# If you are here because a call is failing, this dict is the pattern to extend:
# run the UI page in a browser devtools network tab, read the real request body,
# and add it here.
KNOWN_SHAPES = {
    "vlan_subnet": {
        "get_static_bind_list": {
            "desp": "All DHCP reservations. Takes no parameters object at all: "
                    "the UI calls it as [sid, module, method]. Each entry returns "
                    "mac, name, ip and display_name (the subnet it belongs to).",
            "params": [],
        },
        "add_static_bind": {
            "desp": "Create a DHCP reservation in a subnet.",
            "params": [("name", "string", "label shown in the router UI"),
                       ("mac", "string", "colon-separated MAC address"),
                       ("ip", "string", "IPv4 address to pin"),
                       ("hostname", "string", "DHCP hostname handed to the client; "
                                              "send \"\" to omit"),
                       ("display_name", "string", "subnet, default \"main\"")],
        },
        "set_static_bind": {
            "desp": "Replace an existing reservation, matched on mac. Sends the "
                    "whole record, so omitting hostname clears it.",
            "params": [("name", "string", ""), ("mac", "string", ""),
                       ("ip", "string", ""), ("hostname", "string", ""),
                       ("display_name", "string", "subnet, default \"main\"")],
        },
        "remove_static_bind": {
            "desp": "Delete reservations. mode 0 removes the one named by mac; "
                    "mode 1 removes every reservation in display_name.",
            "params": [("mode", "number", "0 = one by mac, 1 = all in subnet"),
                       ("display_name", "string", "subnet, default \"main\""),
                       ("mac", "string", "required when mode is 0")],
        },
        "get_subnets": {
            "desp": "Every IP subnet the router serves: address, netmask, DHCP pool "
                    "start, lease time, DNS, attached interfaces, isolation flags. "
                    "Replaces lan.get_config_list from 4.7.",
            "params": [],
        },
    },
}


class BuildError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# getting at the JavaScript inside a firmware image
# --------------------------------------------------------------------------

def squashfs_offsets(image: Path, limit: int = 8) -> list[int]:
    """Every plausible squashfs start in the image, smallest offset first."""
    data = image.read_bytes()
    out, i = [], 0
    while len(out) < limit:
        i = data.find(SQUASHFS_MAGIC, i)
        if i < 0:
            break
        out.append(i)
        i += 4
    return out


def superblock_bytes_used(data: bytes, off: int) -> int | None:
    """
    Size of the squashfs starting at `off`, or None if it is a coincidental
    magic match.

    Parsing the superblock ourselves rather than asking unsquashfs to validate
    it means the offset logic does not depend on a tool flag, and the same
    numbers work for the 7z fallback on a machine without squashfs-tools.
    Layout (v4): magic[4], inode_count, mod_time, block_size, fragment_count,
    compression, block_log, flags, no_ids, s_major@28, s_minor, root_inode@32,
    bytes_used@40.
    """
    if data[off:off + 4] != SQUASHFS_MAGIC:
        return None
    if len(data) < off + 48:
        return None
    if int.from_bytes(data[off + 28:off + 30], "little") != 4:   # s_major
        return None
    used = int.from_bytes(data[off + 40:off + 48], "little")
    # A real rootfs is megabytes and must fit inside the image.
    if used < 1_000_000 or off + used > len(data):
        return None
    return used


def extract_rootfs(image: Path, dest: Path) -> Path:
    """
    Unpack the firmware image into `dest` and return the directory to scan.

    Multiple hsqs magics occur in one image -- the real rootfs plus coincidental
    byte sequences inside it -- so each candidate's superblock is parsed and the
    largest genuine filesystem wins. The carve is written to its own file first,
    because both unpackers are happier with a bare filesystem than with an image
    that starts with a device tree blob.
    """
    data = image.read_bytes()
    candidates = [
        (size, off) for off in squashfs_offsets(image)
        if (size := superblock_bytes_used(data, off)) is not None
    ]
    if not candidates:
        hits = squashfs_offsets(image)
        if not hits:
            raise BuildError("no squashfs magic in that file -- is it a firmware image?")
        raise BuildError(
            f"{len(hits)} squashfs magic hit(s) but no valid superblock among them "
            "-- the image may be truncated or use a newer squashfs format"
        )

    size, offset = max(candidates)
    print(f"squashfs at offset {offset} ({size / 1e6:.1f} MB); "
          f"{len(candidates)} valid superblock(s) of {len(squashfs_offsets(image))} "
          f"magic hit(s)")

    carve = dest / "rootfs.img"
    carve.write_bytes(data[offset:offset + size])

    out = dest / "rootfs"
    if shutil.which("unsquashfs"):
        # Extract only www/ -- that is all we read, it is far faster than the
        # whole rootfs, and it sidesteps the one thing that makes unsquashfs
        # unprivileged runs fail: it cannot mknod /dev/console and exits
        # non-zero over it even though everything else extracted fine. If the
        # path differs on this model, fall back to a full extract and judge
        # success by whether content appeared rather than by exit status.
        subprocess.run(["unsquashfs", "-no-progress", "-f", "-d", str(out),
                        str(carve), "www/*"], capture_output=True)
        if not js_bundles(out):
            subprocess.run(["unsquashfs", "-no-progress", "-f", "-d", str(out),
                            str(carve)], capture_output=True)
        if not js_bundles(out):
            raise BuildError("unsquashfs produced no JavaScript -- extraction failed")
    elif shutil.which("7z"):
        subprocess.run(["7z", "x", "-y", f"-o{out}", str(carve)],
                       capture_output=True, check=True)
    else:
        raise BuildError(
            "cannot unpack the filesystem: need unsquashfs (squashfs-tools) or 7z"
        )
    carve.unlink(missing_ok=True)
    return out


def js_bundles(root: Path) -> list[Path]:
    """
    Bundles worth scanning. www/ first because scanning a whole rootfs is slow
    and the UI is always under it; fall back to everything if that finds nothing,
    since the path is not guaranteed across models.
    """
    web = [p for p in root.rglob("*.js") if "/www/" in str(p).replace("\\", "/")]
    web += [p for p in root.rglob("*.js.gz") if "/www/" in str(p).replace("\\", "/")]
    if web:
        return web
    return list(root.rglob("*.js")) + list(root.rglob("*.js.gz"))


# --------------------------------------------------------------------------
# building the catalog
# --------------------------------------------------------------------------

def normalise(module: str) -> str:
    """The UI says `ovpn-client`; older catalogs say `ovpn_client`."""
    return module.replace("-", "_")


def load_legacy(path: Path | None) -> dict:
    """
    An existing catalog to borrow parameter documentation from. Optional.

    Never pass this script's own output back in as `legacy`: every entry would
    then match itself and claim documentation it does not have, and the totals
    would still add up, so nothing would look wrong.
    """
    if not path or not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {normalise(mod): (m.get("case_groups_data") or {})
            for mod, m in data.items()}


def build(seen: dict[str, dict[str, dict]], legacy: dict) -> tuple[dict, dict]:
    new: dict[str, dict] = {}
    stats = {"documented": 0, "ui_only": 0, "legacy_only": 0}

    for module in sorted(seen):
        entries = {}
        borrow = legacy.get(normalise(module), {})
        known = KNOWN_SHAPES.get(module, {})
        for method in sorted(seen[module]):
            callsite = seen[module][method]
            prior = borrow.get(method)
            had_docs = bool(prior and (prior.get("data") or {}).get("desp"))
            entry = dict(prior) if prior else {"data": {"desp": ""}}
            entry["source"] = ("catalog + this firmware's UI" if had_docs
                               else "this firmware's UI")
            if had_docs:
                stats["documented"] += 1
            else:
                stats["ui_only"] += 1
            if method in known:
                shape = known[method]
                entry["data"] = {"desp": shape["desp"]}
                entry["params"] = [
                    {"keyName": k, "dataType__name": t, "note": n}
                    for k, t, n in shape["params"]
                ]
                entry["in_example"] = json.dumps(
                    {"jsonrpc": "2.0", "method": "call",
                     "params": (["", module, method,
                                 {k: "..." for k, _, _ in shape["params"]}]
                                if shape["params"] else ["", module, method])},
                    separators=(",", ":"),
                )
                entry["source"] = "this firmware's UI, shape read from the UI bundle"
            # How the UI calls it. Recorded even when the parameter list is
            # unknown, because "the UI passes nothing" is itself actionable.
            if callsite.get("arg_style"):
                entry["arg_style"] = callsite["arg_style"]
                if callsite.get("arg_expr"):
                    entry["arg_expr"] = callsite["arg_expr"]
                if callsite.get("ui_api"):
                    entry["ui_api"] = callsite["ui_api"]
            entries[method] = entry
        new[module] = {"case_groups_data": entries}

    # Keep entries the UI never calls. The UI is not a complete client -- on
    # 4.10.1, network.get_arp_list is provably alive and appears nowhere in it --
    # so absence from the UI is not proof of removal. Flag them instead of
    # silently promoting or dropping them.
    for mod, methods in legacy.items():
        bucket = new.setdefault(mod, {"case_groups_data": {}})
        for method, entry in methods.items():
            if method in bucket["case_groups_data"]:
                continue
            marked = dict(entry)
            marked["source"] = "older catalog (not seen in this firmware's UI)"
            bucket["case_groups_data"][method] = marked
            stats["legacy_only"] += 1

    return new, stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("source",
                    help="firmware .bin, or a directory containing an extracted rootfs")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help=f"where to write the catalog (default {DEFAULT_OUT.name})")
    ap.add_argument("--legacy", type=Path, default=None,
                    help="an older catalog to borrow parameter docs from (optional)")
    ap.add_argument("--keep-extract", action="store_true",
                    help="leave the extracted rootfs in a temp dir and print its path")
    args = ap.parse_args()

    src = Path(args.source).expanduser()
    if not src.exists():
        print(f"no such file or directory: {src}", file=sys.stderr)
        return 1

    tmp = Path(tempfile.mkdtemp(prefix="glnet-fw."))
    try:
        if src.is_dir():
            root = src
            print(f"scanning extracted rootfs at {root}")
        else:
            print(f"unpacking {src.name} ...")
            root = extract_rootfs(src, tmp)

        seen = ui_calls(root)
        print(f"observed in the UI: {sum(len(v) for v in seen.values())} methods "
              f"across {len(seen)} modules")

        legacy = load_legacy(args.legacy)
        if legacy:
            print(f"borrowing docs from {args.legacy.name}")
        catalog, stats = build(seen, legacy)

        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(catalog, indent=1, sort_keys=True) + "\n")
        total = sum(len(m["case_groups_data"]) for m in catalog.values())
        print(f"\nwrote {args.out}")
        print(f"  {total} methods across {len(catalog)} modules")
        print(f"  {stats['documented']} with parameter docs")
        print(f"  {stats['ui_only']} confirmed present, parameters undocumented")
        if stats["legacy_only"]:
            print(f"  {stats['legacy_only']} kept from the older catalog, "
                  f"flagged not-seen-in-UI")
        if not legacy:
            print("\n  No --legacy catalog given, so most methods have no parameter "
                  "documentation.\n  That is enough for api_search to find them; "
                  "rpc_call must guess their arguments.")
        return 0
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"error: {exc.cmd[0]} failed: "
              f"{exc.stderr.decode(errors='replace')[:300] if exc.stderr else exc}",
              file=sys.stderr)
        return 1
    finally:
        if args.keep_extract:
            print(f"extracted tree left at {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
