#!/usr/bin/env python3
"""Poll the router's client list and record when each device was last seen.

Why this exists. The router cannot answer "when was this device last here".
Everything it stores says something else:

  * client.db `seen`, exposed over the API as the misleadingly-named
    `online_time`, is the row-creation time. Proven two ways: it did not move
    on any of 66 rows across a 3h window in which tx moved on 14, and the
    writer's single UPDATE assigns tx, rx and seen together while preserving
    the old seen.
  * there is no association history. logread holds ~5h, the hostapd log holds
    four lines since boot, /tmp/traffic_data.db is empty, and the vendor
    driver exports no station records to nl80211.

So last-seen has to be observed. This script is the observation.

What it records, and what that is worth:
  * `last_online` is the last poll at which the router itself said the device
    was online. Resolution is the poll interval; a device that connected and
    left between two polls is invisible, and a device the router wrongly marks
    offline is recorded as absent.
  * cumulative tx/rx are stored too, so the delta between two polls gives
    activity for a device the router thinks is offline. That is a proxy for
    "alive but not associated", not a substitute for association.
  * the router's own `online_time` is stored verbatim on every sample so the
    difference between it and a real last-seen stays auditable.

State lives outside the repo, on purpose: the database contains every MAC and
device name on the network.

    GLNET_SAMPLER_DB=/path/to/clients.sqlite3 ./client_sampler.py
    ./client_sampler.py --report 30        # devices offline > 30 days
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import server  # noqa: E402  GlInet owns the login handshake; not duplicating it

DEFAULT_DB = Path(os.path.expanduser("~/.local/share/glnet-sampler/clients.sqlite3"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts        INTEGER NOT NULL,
    mac       TEXT    NOT NULL,
    online    INTEGER NOT NULL,
    ip        TEXT,
    name      TEXT,
    iface     TEXT,
    total_tx  INTEGER,
    total_rx  INTEGER,
    -- the router's own field, which is first-seen, kept so the two never get
    -- confused by whoever reads this later
    vendor_online_time INTEGER,
    PRIMARY KEY (ts, mac)
);
CREATE TABLE IF NOT EXISTS devices (
    mac          TEXT PRIMARY KEY,
    name         TEXT,
    iface        TEXT,
    first_sample INTEGER,
    last_sample  INTEGER,
    last_online  INTEGER,
    last_online_ip TEXT,
    polls        INTEGER NOT NULL DEFAULT 0,
    polls_online INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS samples_mac_ts ON samples (mac, ts DESC);
"""


def connect(db: Path) -> sqlite3.Connection:
    db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db, timeout=30)
    con.executescript(SCHEMA)
    return con


def sample(con: sqlite3.Connection, router: server.GlInet, ts: int) -> int:
    reply = router.call("clients", "get_list", {})
    clients = (reply or {}).get("clients") or []
    if not clients:
        # An empty list is not "nobody is home", it is a failed or changed
        # call. Recording it as absence would make every device look stale.
        raise RuntimeError("clients.get_list returned no clients; recording nothing")

    for c in clients:
        mac = (c.get("mac") or "").upper()
        if not mac:
            continue
        online = 1 if c.get("online") else 0

        def as_int(key):
            try:
                return int(c.get(key))
            except (TypeError, ValueError):
                return None

        con.execute(
            "INSERT OR REPLACE INTO samples (ts, mac, online, ip, name, iface,"
            " total_tx, total_rx, vendor_online_time) VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, mac, online, c.get("ip"), c.get("name") or c.get("alias") or "",
             c.get("iface"), as_int("total_tx"), as_int("total_rx"),
             as_int("online_time")))
        con.execute(
            """INSERT INTO devices (mac, name, iface, first_sample, last_sample,
                                    last_online, last_online_ip, polls, polls_online)
               VALUES (?,?,?,?,?,?,?,1,?)
               ON CONFLICT(mac) DO UPDATE SET
                 name         = COALESCE(NULLIF(excluded.name,''), devices.name),
                 iface        = COALESCE(excluded.iface, devices.iface),
                 last_sample  = excluded.last_sample,
                 -- MAX(x, NULL) is NULL in SQLite, so a naive MAX here wipes
                 -- last_online the first time a device goes offline -- which is
                 -- exactly the value this whole script exists to capture.
                 last_online  = CASE WHEN excluded.last_online IS NULL
                                     THEN devices.last_online
                                     ELSE MAX(COALESCE(devices.last_online, 0),
                                              excluded.last_online) END,
                 last_online_ip = COALESCE(excluded.last_online_ip, devices.last_online_ip),
                 polls        = devices.polls + 1,
                 polls_online = devices.polls_online + excluded.polls_online""",
            (mac, c.get("name") or c.get("alias") or "", c.get("iface"), ts, ts,
             ts if online else None, c.get("ip") if online else None, online))
    con.commit()
    return len(clients)


def report(con: sqlite3.Connection, days: int, now: int) -> int:
    cutoff = now - days * 86400
    rows = con.execute(
        """SELECT mac, name, iface, polls, polls_online, last_online, first_sample
             FROM devices
            WHERE COALESCE(last_online, 0) < ?
            ORDER BY COALESCE(last_online, 0) DESC""", (cutoff,)).fetchall()
    known = con.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    samples = con.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    span = con.execute("SELECT MIN(ts), MAX(ts) FROM samples").fetchone()
    print(f"  {known} devices known, {samples} samples recorded")
    if span[0]:
        print(f"  observing since {time.strftime('%Y-%m-%d %H:%M', time.localtime(span[0]))}, "
              f"latest {time.strftime('%Y-%m-%d %H:%M', time.localtime(span[1]))}")
    if not rows:
        print(f"  no device has been unseen for {days}+ days")
        return 0
    print(f"  unseen for {days}+ days ({len(rows)}):")
    for mac, name, iface, polls, online_polls, last, first in rows:
        since = (f"{(now - last) / 86400:.0f}d ago" if last else "never seen online")
        print(f"    {mac}  {name or '-':28s} {iface or '-':10s} "
              f"last online {since:12s} ({online_polls}/{polls} polls online)")
    return len(rows)


def one_run(con: sqlite3.Connection, router: server.GlInet, prune_days: int) -> None:
    now = int(time.time())
    n = sample(con, router, now)
    dropped = con.execute("DELETE FROM samples WHERE ts < ?",
                          (now - prune_days * 86400,)).rowcount
    con.commit()
    print(f"recorded {n} clients at "
          f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}"
          + (f"; pruned {dropped} samples older than {prune_days}d" if dropped else ""),
          flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", type=Path,
                    default=Path(os.environ.get("GLNET_SAMPLER_DB", DEFAULT_DB)))
    ap.add_argument("--report", type=int, metavar="DAYS",
                    help="list devices not seen online for DAYS days and exit")
    ap.add_argument("--prune-days", type=int, default=365,
                    help="drop raw samples older than this (default 365)")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="keep running and sample every SECONDS, instead of "
                         "once. For container use, where there is no systemd "
                         "timer to do it.")
    args = ap.parse_args()

    con = connect(args.db)
    if args.report:
        report(con, args.report, int(time.time()))
        return 0

    router = server.GlInet(server.Config())
    if not args.loop:
        one_run(con, router, args.prune_days)
        return 0

    # Loop mode exists because the deployment that needs it runs in a container
    # on a box where the agent cannot get root, so there is no timer to lean on.
    # It is deliberately not clever: sleep, sample, repeat. A failed sample is
    # logged and skipped rather than fatal, because the router reboots and the
    # sampler outliving a reboot is the entire point.
    import random
    import signal
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(True))
    print(f"sampling every {args.loop}s into {args.db}", flush=True)
    while not stop:
        try:
            one_run(con, router, args.prune_days)
        except Exception as exc:
            print(f"sample failed ({type(exc).__name__}: {exc}); keeping the "
                  f"previous data and trying again", flush=True)
        nap = args.loop + random.uniform(-min(60, args.loop / 10),
                                         min(60, args.loop / 10))
        for _ in range(int(nap)):
            if stop:
                break
            time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
