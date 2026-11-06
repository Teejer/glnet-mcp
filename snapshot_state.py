#!/usr/bin/env python3
"""
Snapshot the router's configuration state, so a later snapshot can be diffed.

Why: the vendor API has no backup method -- not on 4.10.1 and not in the older
published catalog. The web UI clearly has a restore flow (the translations carry
a "Restoring backup takes about ..." string) but it is a plain HTTP upload, not
a JSON-RPC call, so it is not reachable from here. If you want a restorable
image, take one over SSH instead:

    ssh root@192.168.8.1 'sysupgrade -b /tmp/router.tgz'
    scp root@192.168.8.1:/tmp/router.tgz .

What this script gives you instead is a baseline you can compare against: run it
before probing the API, run it again after, and read the diff. It will not put
the router back the way it was; it will tell you, in seconds, whether anything
moved. That is the question "did my read-only probe write something?" actually
asks.

    ./snapshot_state.py                 # -> snapshots/<utc>.json, prints the path
    ./snapshot_state.py --diff          # compare against the newest previous one

Everything goes through GlInet.call(), so secret fields arrive already redacted.
The snapshots contain your SSIDs, hostnames, MACs and reservations: they are
gitignored. Do not commit them or paste them into a bug report.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

try:
    import server
except ModuleNotFoundError as exc:  # pragma: no cover - environment guidance
    if exc.name and exc.name.startswith("mcp"):
        sys.exit(
            "this script imports server.py, which needs the MCP SDK.\n"
            "Run it with the project venv:  .venv/bin/python snapshot_state.py\n"
            "(or: uv venv && uv pip install -r requirements.txt)"
        )
    raise

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "snapshots"

# (module, method, args, why it is in the baseline)
# Nothing here takes a payload except where noted, and nothing is a write: no
# set_/add_/remove_/reboot_/reset_/upgrade_/clean_/detect_ names. Probing a
# method whose name merely sounds passive is what this file exists to avoid --
# cable.wan_proto_detect and clients.clean_traffic both look read-ish and are not.
STATE = [
    ("vlan_subnet", "get_static_bind_list", None, "DHCP reservations"),
    ("vlan_subnet", "get_subnets", {}, "subnets, DHCP pools, isolation flags"),
    ("firewall", "get_port_forward_list", {}, "exposed ports"),
    ("firewall", "get_rule_list", {}, "custom firewall rules"),
    ("firewall", "get_dmz", {}, "DMZ host"),
    ("firewall", "get_zone_list", {}, "firewall zones"),
    ("wifi", "get_status", {}, "SSIDs and radio state (passphrases redacted)"),
    ("dns", "get_config", {}, "DNS override settings"),
    ("dns", "get_host", {}, "custom DNS host entries"),
    ("ddns", "get_config", {}, "dynamic DNS"),
    ("ipv6", "get_ipv6", {}, "IPv6 mode"),
    ("netmode", "get_mode", {}, "operating mode: router vs relay vs ap"),
    ("qos", "get_config", {}, "bandwidth limits"),
    ("cable", "get_config", {}, "WAN configuration"),
    ("system", "get_security_policy", {}, "router login policy"),
    ("repeater", "get_config", {}, "repeater settings"),
    ("clients", "get_list", {}, "client table: names, aliases, MACs, IPs"),
]


def grab() -> dict:
    out: dict[str, dict] = {}
    for module, method, args, why in STATE:
        try:
            value = server.ROUTER.call(module, method, args)
            out[f"{module}.{method}"] = {"ok": True, "why": why, "value": value}
        except server.RouterError as exc:
            # A method that errors is recorded as an error, not skipped: an
            # error in the baseline that becomes a value later IS the finding.
            out[f"{module}.{method}"] = {"ok": False, "why": why,
                                         "error": f"[{exc.code}] {exc.message}"}
        except Exception as exc:  # noqa: BLE001 - never lose a snapshot leg
            out[f"{module}.{method}"] = {"ok": False, "why": why,
                                         "error": f"{type(exc).__name__}: {exc}"}
    return out


def diffable(snap: dict) -> dict:
    """Drop fields that churn on their own, so the diff means something."""
    out = {}
    for key, entry in snap.items():
        if not entry.get("ok"):
            out[key] = entry.get("error")
            continue
        value = entry["value"]
        if key == "clients.get_list":
            # Traffic counters, rates and online flags move constantly; names,
            # aliases and the MAC->IP binding are the config-shaped part.
            rows = (value.get("result") or value).get("clients", []) if isinstance(value, dict) else []
            out[key] = sorted(
                f"{c.get('mac','?')} -> {c.get('ip','?')} name={c.get('name','')} "
                f"alias={c.get('alias','')} blocked={c.get('blocked')}"
                for c in rows
            )
        elif key == "wifi.get_status":
            rows = (value.get("result") or value).get("res", value)
            out[key] = rows
        else:
            out[key] = value
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--diff", action="store_true",
                    help="diff this snapshot against the most recent previous one")
    args = ap.parse_args()

    print(f"router: {server.CONFIG.url}  reading {len(STATE)} methods (read-only)")
    snap = grab()
    meta = {
        "taken": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "router": server.CONFIG.url,
        "firmware": None,
    }
    try:
        info = server.ROUTER.call("system", "get_info", {})
        meta["firmware"] = (info.get("result") or info).get("firmware_version")
    except Exception:  # noqa: BLE001
        pass

    OUT_DIR.mkdir(exist_ok=True)
    stamp = meta["taken"].replace(":", "").replace("+0000", "Z")
    path = OUT_DIR / f"{stamp}.json"
    path.write_text(json.dumps({"meta": meta, "state": snap}, indent=1, sort_keys=True))
    failed = [k for k, v in snap.items() if not v["ok"]]
    print(f"wrote {path.relative_to(HERE)}  "
          f"({len(snap) - len(failed)}/{len(STATE)} readable, firmware {meta['firmware']})")
    for k in failed:
        print(f"  unreadable: {k} -> {snap[k]['error'][:70]}")

    if args.diff:
        prev = sorted(p for p in OUT_DIR.glob("*.json") if p != path)
        if not prev:
            print("no earlier snapshot to compare against yet")
            return 0
        before = json.loads(prev[-1].read_text())
        print(f"\ncomparing against {prev[-1].name} ({before['meta']['taken']})")
        a, b = diffable(before["state"]), diffable(snap)
        changed = [k for k in set(a) | set(b) if a.get(k) != b.get(k)]
        if not changed:
            print("  no configuration differences")
        for k in sorted(changed):
            print(f"  CHANGED: {k}  ({before['state'].get(k, {}).get('why', '')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
