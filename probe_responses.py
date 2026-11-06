#!/usr/bin/env python3
"""
Record what each read-only method actually returns, as a shape.

how_to_call says what to send. This says what comes back, which is the other half
of "what does this method do" and the half that cannot be recovered from the
firmware at all -- the UI bundles contain the request, not the response. It is
only obtainable by asking a live router.

Safety
------
One call per method, and only for methods that are:

  * named get_/list_/is_/has_  -- a verb that reports, and
  * not named after anything that could do work (update, sync, scan, detect,
    clean, reset, start, stop, connect, apply, add, set, remove...), and
  * probed with an empty payload only. Nothing is ever invented as a value.

Names still lie -- wan_proto_detect and clients.clean_traffic read as innocuous
and are not -- so this is a judgement, not a proof. Afterwards run
snapshot_state.py --diff and let the router confirm nothing moved.

What gets stored
----------------
A shape, never values: {"clients": [{"ip": "str", "online": "bool", ...}]}, with
list lengths and key counts recorded separately. So a passphrase or a key cannot
end up in the catalog even by accident -- the leaf is the word "str", not the
string. GlInet.call() redacts first anyway, which is a second net rather than the
reason.

Object *keys* are kept, because a shape without them is useless. That is not
neutral: some replies are maps keyed by real data -- an SSID or a MAC address
becomes a key in the shape and is therefore written out verbatim. The catalog is
gitignored for that reason. Treat a stamped api_description.json as holding your
network's inventory, the same as snapshots/ and backups/, and never commit or
attach one.

    ./probe_responses.py                      # every safe module
    ./probe_responses.py --module wifi        # one module
    ./probe_responses.py --apply              # write shapes into the catalog
    ./probe_responses.py --limit 20           # sample, for a dry run

Run with the project venv; it needs the same credentials as the server.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

try:
    import server
except ModuleNotFoundError as exc:  # pragma: no cover
    if exc.name and exc.name.startswith("mcp"):
        sys.exit("needs the MCP SDK:  .venv/bin/python probe_responses.py")
    raise

HERE = Path(__file__).resolve().parent
CATALOG = Path(server.CATALOG_PATH)

READ_VERB = re.compile(r"^(get|list|is|has|query|describe)_")
RISKY = re.compile(
    r"update|upgrade|sync|scan|detect|clean|reboot|reset|test|start|stop|"
    r"connect|disconnect|apply|install|uninstall|enable|disable|flash|recover|"
    r"factory|delete|remove|add|set|write|save|flush|kill|reload|backup"
)
MAX_DEPTH = 4        # deeper than this and the shape stops being readable
MAX_KEYS = 30        # per object; ARP tables and client lists have many keys
MAX_LIST = 2         # sample list items, so a heterogeneous list is visible

MISSING_ARGS = re.compile(r"parameter (not found|missing)", re.I)


def shape(value, depth: int = 0) -> object:
    """
    Type skeleton of a decoded reply. Leaves are type names, never values.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        if not value:
            return []
        if depth >= MAX_DEPTH:
            return ["..."]
        samples = [shape(v, depth + 1) for v in value[:MAX_LIST]]
        # A list of unlike objects is worth flagging: the first element is not a
        # representative schema and documenting it as one would mislead.
        distinct = {json.dumps(s, sort_keys=True) for s in samples}
        return samples[0] if len(distinct) == 1 else {"<heterogeneous>": samples}
    if isinstance(value, dict):
        if depth >= MAX_DEPTH:
            return "{...}"
        items = list(value.items())[:MAX_KEYS]
        out = {str(k): shape(v, depth + 1) for k, v in items}
        if len(value) > MAX_KEYS:
            out[f"<+{len(value) - MAX_KEYS} more keys>"] = "..."
        return out
    return type(value).__name__


def is_app_error(body) -> tuple[bool, str]:
    """GL.iNet reports failures as ordinary successful responses."""
    if isinstance(body, dict) and (body.get("err_code") or body.get("err_msg")):
        return True, f"{body.get('err_code')} {body.get('err_msg')}"
    return False, ""


def probe(module: str, method: str) -> tuple[str, object]:
    """
    (status, shape-or-detail). status is one of: shape, needs-params, absent,
    error. See the module docstring for why {} is the only payload ever sent.
    """
    try:
        reply = server.ROUTER.call(module, method, {})
    except server.RouterError as exc:
        if exc.code == -32601:
            return "absent", "Method not found"
        return "error", f"[{exc.code}] {exc.message[:60]}"
    except Exception as exc:  # noqa: BLE001 - one bad method must not stop a sweep
        return "error", f"{type(exc).__name__}: {exc}"[:80]

    body = reply.get("result") if isinstance(reply, dict) else reply
    body = reply if body is None else body
    failed, detail = is_app_error(body)
    if failed:
        return ("needs-params" if MISSING_ARGS.search(detail) else "refused"), detail
    return "shape", shape(body)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--module", default="")
    ap.add_argument("--limit", type=int, default=0, help="stop after N probes")
    ap.add_argument("--apply", action="store_true",
                    help="write shapes into api_description.json")
    args = ap.parse_args()

    if not CATALOG.exists():
        sys.exit(f"no catalog at {CATALOG} -- run ./build_catalog.py <firmware.bin>")
    cat = json.loads(CATALOG.read_text())
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    targets = []
    for mod in sorted(cat):
        if args.module and mod != args.module:
            continue
        for method in sorted(cat[mod]["case_groups_data"]):
            if READ_VERB.match(method) and not RISKY.search(method):
                targets.append((mod, method))

    print(f"{len(targets)} read-shaped methods to probe "
          f"({'>'.join(['all modules']) if not args.module else args.module})")
    counts: dict[str, int] = {}
    done = 0
    for mod, method in targets:
        status, detail = probe(mod, method)
        counts[status] = counts.get(status, 0) + 1
        done += 1
        entry = cat[mod]["case_groups_data"][method]
        if status == "shape":
            keys = len(detail) if isinstance(detail, dict) else "-"
            print(f"  ok    {mod}.{method}  ({keys} top-level keys)")
            if args.apply:
                entry["returns"] = detail
                entry["returns_probe"] = stamp
        else:
            print(f"  {status:13s} {mod}.{method}  {str(detail)[:52]}")
            if args.apply and status in ("absent", "needs-params"):
                entry["returns"] = status
                entry["returns_probe"] = stamp
        if args.limit and done >= args.limit:
            print(f"  (--limit {args.limit} reached)")
            break

    print("\n" + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    if args.apply:
        CATALOG.write_text(json.dumps(cat, indent=1, sort_keys=True) + "\n")
        print(f"stamped into {CATALOG.name} -- reconnect the MCP to serve it")
        print("now run:  .venv/bin/python snapshot_state.py --diff")
    else:
        print("dry run; nothing written to the catalog")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
