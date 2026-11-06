#!/usr/bin/env python3
"""
Ask the router, once per module, whether that module actually exists.

Why this exists
---------------
The catalog is assembled from two sources and both can be wrong about module
names. The firmware's UI bundles contain stale code paths -- on 4.10.1 the
bundles still call wg_client.* for ExpressVPN, a feature this firmware does not
have, and the router answers those calls with Method not found. The older
published catalog uses underscores throughout, while the wire names are mixed:
vlan_subnet and wg-client are both correct spellings of real modules.

So a catalog entry can look healthy and name a module the router will not
accept. This settles it by asking, which also makes it the thing to re-run after
a firmware upgrade: it is a fast way to find out which halves of the API moved.

How it stays safe
-----------------
It sends exactly one call per module, to a method that is:

  * named get_/list_/is_/has_ -- a verb that reports rather than changes, and
  * called by the UI with no payload or an empty one, so nothing is invented, and
  * not named after anything that could do work: no update, upgrade, sync, scan,
    detect, clean, reboot, reset, test, start, stop, connect or apply.

Names lie -- wan_proto_detect and clients.clean_traffic both read as innocuous
and are not, which is why the verb list is an exclusion list rather than a guess.
Even so, "read-only by name" is a judgement, not a proof. Run
snapshot_state.py --diff afterwards and let the router confirm nothing moved.

    ./verify_modules.py                 # report only
    ./verify_modules.py --apply         # also stamp module_status into the catalog
    ./verify_modules.py --module wifi   # one module

Needs the same credentials as the server; run it with the project venv.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import server
except ModuleNotFoundError as exc:  # pragma: no cover
    if exc.name and exc.name.startswith("mcp"):
        sys.exit("needs the MCP SDK:  .venv/bin/python verify_modules.py")
    raise

HERE = Path(__file__).resolve().parent
CATALOG = Path(server.CATALOG_PATH)

READ_VERBS = re.compile(r"^(get|list|is|has|query|describe)_")
# A method whose name contains any of these is not probeable even if it starts
# with get_. check_firmware_online reaches the internet; get_update_status may
# start a check; a "clean" or "reset" counter getter would be a write in a mask.
RISKY = re.compile(
    r"update|upgrade|sync|scan|detect|clean|reboot|reset|test|start|stop|"
    r"connect|disconnect|apply|install|uninstall|enable|disable|flash|recover|"
    r"factory|delete|remove|add|set|write|save|flush|kill|kick|reload"
)
SAFE_ARG_STYLES = ("none", "empty_object")

LIVE = "live"
# Not "not on this router". The sweep only tries getter-shaped names, so a module
# that answers solely on a non-getter is reported missing when it is present:
# ovpn_client has no live getter but set_config_name answers. The honest claim is
# about what was tried, not about what exists.
DEAD = "no live getter"
UNPROBED = "unprobed"


def pick_probe(entry: dict) -> bool:
    """Is this method safe to fire blind? See the module docstring."""
    if entry.get("arg_style") not in SAFE_ARG_STYLES:
        return False
    return True


def candidates(module: str, methods: dict) -> list[str]:
    safe = [m for m, e in methods.items()
            if READ_VERBS.match(m) and not RISKY.search(m) and pick_probe(e)]
    if safe:
        return safe
    # Nothing provably safe: fall back to read-verb names whose arg style the
    # generator never observed, but only if the module has no better option. The
    # call still sends no payload, which is the constraint that actually matters.
    return [m for m, e in sorted(methods.items())
            if READ_VERBS.match(m) and not RISKY.search(m)]


def probe(module: str, method: str) -> tuple[str, str]:
    """
    (status, detail).

    Three outcomes, and telling them apart is the whole point:
      * JSON-RPC -32601  -> this method is not on the router.
      * a payload saying {"err_msg": ..., "err_code": ...} -> the method exists
        and refused the empty arguments. Nothing was written.
      * a payload with real data -> the method ran.

    The middle case is the trap. GL.iNet returns argument errors as an ordinary
    successful RPC response, so "no exception raised" does NOT mean "nothing
    happened" -- for a write method it can mean the write succeeded. This script
    only ever selects read-verb methods with no payload, so the third case is
    benign here, but do not copy this probe into something that calls writes: an
    earlier ad-hoc probe of exactly this shape fired add_group and
    create_provider_account with {} and only a byte-identical config backup
    showed they had been rejected rather than applied.
    """
    try:
        reply = server.ROUTER.call(module, method, {})
    except server.RouterError as exc:
        if exc.code == -32601:
            return DEAD, "Method not found"
        return LIVE, f"rpc error [{exc.code}] {exc.message[:52]}"
    except Exception as exc:  # noqa: BLE001 - never abort a sweep over one module
        return "error", f"{type(exc).__name__}: {exc}"[:90]

    body = reply.get("result") if isinstance(reply, dict) else None
    body = body if body is not None else reply
    if isinstance(body, dict) and (body.get("err_code") or body.get("err_msg")):
        return LIVE, f"rejected empty args: {str(body.get('err_msg'))[:44]}"
    return LIVE, "ran and returned data"[:90]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true",
                    help="write module_status into api_description.json")
    ap.add_argument("--module", default="", help="only this module")
    ap.add_argument("--methods", action="store_true",
                    help="per-method liveness, not just per-module (needs --module)")
    args = ap.parse_args()

    if args.methods and not args.module:
        sys.exit("--methods needs --module, so it cannot sweep the whole API")

    if not CATALOG.exists():
        sys.exit(f"no catalog at {CATALOG} -- run ./build_catalog.py <firmware.bin>")
    cat = json.loads(CATALOG.read_text())

    names = [args.module] if args.module else sorted(cat)

    if args.methods:
        methods = cat[args.module].get("case_groups_data", {})
        safe = set(candidates(args.module, methods))
        print(f"{args.module}: {len(methods)} catalogued, "
              f"{len(safe)} safe to probe, {len(methods) - len(safe)} skipped")
        for m in sorted(methods):
            if m not in safe:
                print(f"  skip  {m:34s} not a provably safe read")
                continue
            status, detail = probe(args.module, m)
            mark = "live" if status == LIVE else "gone"
            print(f"  {mark:5s}  {m:34s} {detail[:46]}")
            if args.apply:
                methods[m]["method_status"] = status
        if args.apply:
            CATALOG.write_text(json.dumps(cat, indent=1, sort_keys=True) + "\n")
            print(f"stamped method_status into {CATALOG.name}")
        return 0
    results: dict[str, tuple[str, str, str]] = {}
    for module in names:
        methods = cat[module].get("case_groups_data", {})
        picks = candidates(module, methods)
        if not picks:
            results[module] = (UNPROBED, "", "no read-shaped method to probe with")
            print(f"  ?    {module:22s} unprobed (no safe getter in the catalog)")
            continue
        status, detail = "error", ""
        for method in picks[:3]:
            status, detail = probe(module, method)
            if status != DEAD:
                break
            detail = f"{method}: {detail}"
        results[module] = (status, picks[0], detail)
        flag = {"live": "OK  ", "no live getter": "MISS", "error": "ERR ",
                "unprobed": "?   "}[status]
        print(f"  {flag}  {module:22s} {status:20s} via {picks[0]}  {detail[:44]}")

    counts = {}
    for status, _, _ in results.values():
        counts[status] = counts.get(status, 0) + 1
    print(f"\n{len(results)} modules: " + ", ".join(f"{v} {k}" for k, v in
                                                    sorted(counts.items())))

    dead = sorted(m for m, (s, _, _) in results.items() if s == DEAD)
    if dead:
        print("\nno getter answered on these -- usually absent, but a module that")
        print("only exposes non-getter methods looks identical from here:")
        for m in dead:
            variants = cat[m].get("spelling_variants") or []
            note = f"   (also spelled: {', '.join(variants)})" if variants else ""
            print(f"   {m}{note}")

    if args.apply:
        for module, (status, _, _) in results.items():
            cat[module]["module_status"] = status
        CATALOG.write_text(json.dumps(cat, indent=1, sort_keys=True) + "\n")
        print(f"\nstamped module_status into {CATALOG.name}")
        print("restart the MCP server to load it (reconnect, not just reload)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
