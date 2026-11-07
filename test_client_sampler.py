#!/usr/bin/env python3
"""Tests for client_sampler, no router required.

The case worth pinning is a device that goes online and then offline. The
last_online column is the point of the whole sampler, and the obvious SQL for
it -- MAX(existing, new) -- silently destroys it, because SQLite's scalar MAX
returns NULL if any argument is NULL and the offline pass passes NULL.

    ./venv_or_.venv/bin/python test_client_sampler.py
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import client_sampler as cs  # noqa: E402


class FakeRouter:
    """Stands in for GlInet; yields whatever the test says the router said."""

    def __init__(self) -> None:
        self.payload: list[dict] = []

    def call(self, module: str, method: str, args: dict) -> dict:
        assert (module, method) == ("clients", "get_list")
        return {"clients": self.payload}


def client(mac: str, online: bool, name: str = "desk", tx: int = 1000) -> dict:
    return {"mac": mac, "online": online, "ip": "192.168.8.20", "name": name,
            "iface": "5G", "total_tx": tx, "total_rx": 2000,
            "online_time": 1_700_000_000}


def fresh() -> sqlite3.Connection:
    tmp = Path(tempfile.mkdtemp()) / "t.sqlite3"
    return cs.connect(tmp)


def test_survives_going_offline() -> None:
    con, router = fresh(), FakeRouter()
    router.payload = [client("AA:BB:CC:DD:EE:FF", True)]
    cs.sample(con, router, 1000)
    router.payload = [client("AA:BB:CC:DD:EE:FF", False)]
    cs.sample(con, router, 2000)

    row = con.execute(
        "SELECT last_online, last_sample, polls, polls_online FROM devices"
        " WHERE mac='AA:BB:CC:DD:EE:FF'").fetchone()
    assert row[0] == 1000, f"last_online was wiped to {row[0]}; expected 1000"
    assert row[1] == 2000, f"last_sample should advance while offline, got {row[1]}"
    assert (row[2], row[3]) == (2, 1), f"poll counters wrong: {row[2]}, {row[3]}"


def test_comeback_moves_last_online_forward() -> None:
    con, router = fresh(), FakeRouter()
    router.payload = [client("AA:BB:CC:DD:EE:FF", True)]
    cs.sample(con, router, 1000)
    router.payload = [client("AA:BB:CC:DD:EE:FF", False)]
    cs.sample(con, router, 2000)
    router.payload = [client("AA:BB:CC:DD:EE:FF", True)]
    cs.sample(con, router, 3000)

    got = con.execute(
        "SELECT last_online FROM devices WHERE mac='AA:BB:CC:DD:EE:FF'").fetchone()[0]
    assert got == 3000, f"a reconnect should move last_online, got {got}"


def test_empty_reply_records_nothing() -> None:
    # An empty client list is a failed or changed call, not an empty house.
    # Recording it would make every device look absent at that timestamp.
    con, router = fresh(), FakeRouter()
    router.payload = [client("AA:BB:CC:DD:EE:FF", True)]
    cs.sample(con, router, 1000)
    router.payload = []
    try:
        cs.sample(con, router, 2000)
    except RuntimeError:
        pass
    else:
        raise AssertionError("an empty client list should raise, not record absence")
    n = con.execute("SELECT DISTINCT ts FROM samples").fetchall()
    assert [r[0] for r in n] == [1000], f"unexpected sample times: {n}"


def test_report_separates_stale() -> None:
    con, router = fresh(), FakeRouter()
    router.payload = [client("AA:BB:CC:DD:EE:01", True),
                      client("AA:BB:CC:DD:EE:02", False, name="gone")]
    cs.sample(con, router, 1_780_000_000)
    rows = con.execute(
        "SELECT mac FROM devices WHERE COALESCE(last_online,0) < ? ORDER BY mac",
        (1_780_000_000 - 30 * 86400,)).fetchall()
    assert [r[0] for r in rows] == ["AA:BB:CC:DD:EE:02"], f"stale set wrong: {rows}"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok    {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL  {name}: {exc}")
    print("all passed" if not failures else f"{failures} failed")
    sys.exit(1 if failures else 0)
