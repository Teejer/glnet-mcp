#!/usr/bin/env python3
"""Merge a freshly rebuilt catalog with the live one the server is using.

Why this exists: build_catalog.py derives methods from two sources -- the
firmware's own UI bundle and an older documented catalog. Neither knows about
methods that were recovered afterwards from the handler files in
usr/lib/oui-httpd/rpc, which is where most of the parameter knowledge came
from. Rebuilding straight over the top silently drops those (106 pairs on
4.10.1, of which 89 were handler-recovered and 17 were the nas_web ->
nas-web rename).

So the rebuilt file is taken as the base, because it is the only one carrying
the per-module firmware_handler cross-check, and anything the live catalog has
that the rebuild lacks is carried forward and labelled with where it actually
came from rather than quietly deleted.

Usage:
    python merge_catalog.py --rebuilt new.json --live api_description.json \
        --out merged.json
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

GROUP = "case_groups_data"


def methods(catalog: dict) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for mod, groups in catalog.items():
        if not isinstance(groups, dict):
            continue
        for name, entry in (groups.get(GROUP) or {}).items():
            if isinstance(entry, dict):
                out[(mod, name)] = entry
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rebuilt", type=Path, required=True)
    ap.add_argument("--live", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--backup", type=Path,
                    help="copy the live catalog here before writing")
    args = ap.parse_args()

    rebuilt = json.loads(args.rebuilt.read_text())
    live = json.loads(args.live.read_text())

    # modules the rebuild renamed (nas_web -> nas-web); carry entries to the
    # spelling the firmware actually ships, not the one the old docs used
    renamed: dict[str, str] = {}
    for mod, groups in rebuilt.items():
        if isinstance(groups, dict) and isinstance(groups.get("renamed_from"), str):
            renamed[groups["renamed_from"]] = mod

    new_m = methods(rebuilt)
    live_m = methods(live)

    carried: list[str] = []
    for (mod, name), entry in sorted(live_m.items()):
        target_mod = renamed.get(mod, mod)
        if (target_mod, name) in new_m:
            # the rebuild knows this one; keep any provenance it did not
            # regenerate, but never overwrite a fresh value with a stale one
            tgt = new_m[(target_mod, name)]
            for key in ("params_static", "params_origin", "vendor_docs",
                        "confirmed_on_router"):
                if key not in tgt and key in entry:
                    tgt[key] = entry[key]
            continue
        if entry.get("source"):
            # rebuild has provenance for everything it emits, so a sourced
            # entry it dropped really was removed from this firmware
            print(f"  dropped {mod}.{name} (source: {entry['source'][:40]})")
            continue
        bucket = rebuilt.setdefault(target_mod, {})
        bucket.setdefault(GROUP, {})[name] = dict(
            entry,
            source=("recovered from usr/lib/oui-httpd/rpc/" + target_mod
                    if entry.get("params_origin") == "handler bytecode"
                    else "previous catalog, no provenance recorded")
            + "; not in this firmware's UI bundle or the bundled docs")
        new_m[(target_mod, name)] = bucket[GROUP][name]
        carried.append(f"{target_mod}.{name}")

    if args.backup:
        shutil.copy2(args.live, args.backup)

    args.out.write_text(json.dumps(rebuilt, indent=1, sort_keys=True) + "\n")
    mods = sum(1 for m in rebuilt.values() if isinstance(m, dict))
    print(f"\n  {len(new_m)} methods across {mods} modules")
    print(f"  {len(carried)} carried forward from the live catalog")
    gone = [f"{m}.{n}" for (m, n) in live_m if (renamed.get(m, m), n) not in new_m]
    print(f"  {len(gone)} dropped as removed by this firmware")
    return 0


if __name__ == "__main__":
    sys.exit(main())
