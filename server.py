#!/usr/bin/env python3
"""
glnet-mcp -- MCP server for GL.iNet routers, over the vendor JSON-RPC API.

Speaks the same HTTPS JSON-RPC that the router's own web UI (gl-ui) speaks, at
https://<router>/rpc. No root SSH, no on-router daemon: authentication is the
router's normal challenge/login handshake and everything runs from this host.

Why this shape: GL.iNet took the 4.x API documentation offline in January 2024
and has not restored it, and they have changed the API between firmware
releases: 4.8 added a "hash-method" field to the login challenge, and 4.10
deleted the entire `lan` module and moved DHCP reservations to `vlan_subnet`.
So rather than hand-writing a tool per method and going stale, this server
carries a method catalog and exposes the surface two ways:

  * curated tools for the things you actually do every day, and
  * api_search + rpc_call, which reach the whole surface.

The catalog is deliberately NOT distributed here -- it is generated from the
firmware you actually run, by ./build_catalog.py <firmware.bin>. Shipping one
catalog would guarantee it is wrong for someone else's version. Without a
catalog every curated tool still works and rpc_call still works; only
api_search is blind. See the README.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

# mcp 2.x renamed FastMCP to MCPServer; the decorator and run() surface is
# otherwise the same. Accept either so the version pin is not brittle.
try:
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

HERE = Path(__file__).resolve().parent
CATALOG_PATH = Path(os.environ.get("GLNET_CATALOG", HERE / "api_description.json"))

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


class Config:
    """Router endpoint and credentials, from environment with sane defaults."""

    def __init__(self) -> None:
        self.host = os.environ.get("GLNET_HOST", "192.168.8.1")
        self.port = int(os.environ.get("GLNET_PORT", "443"))
        self.user = os.environ.get("GLNET_USER", "root")
        self.timeout = float(os.environ.get("GLNET_TIMEOUT", "20"))
        # The router ships a self-signed certificate, so not verifying is the
        # default. Set GLNET_VERIFY_TLS=1 and it will validate normally.
        self.verify_tls = os.environ.get("GLNET_VERIFY_TLS", "0") == "1"
        self.password_file = Path(
            os.environ.get(
                "GLNET_PASSWORD_FILE",
                Path.home() / ".config" / "opencode" / "glnet.password",
            )
        )

    @property
    def password(self) -> str | None:
        """
        Re-read on every access rather than caching at startup, so the secret
        can be rotated without restarting the server. An MCP server can sit in
        memory for days; a cached secret outliving its expiry date is a bug.
        """
        env = os.environ.get("GLNET_PASSWORD")
        if env:
            return env
        return self._read_password_file()

    def _read_password_file(self, path: Path | None = None) -> str | None:
        path = path or self.password_file
        if not path.exists():
            return None
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            # Not a hard failure: a group-readable password file is a bad idea
            # but refusing to start is a worse one at 1am.
            print(
                f"glnet-mcp: WARNING {path} is mode {mode:03o}; chmod 600 it",
                file=sys.stderr,
            )
        return path.read_text().strip() or None

    @property
    def luci_password(self) -> str | None:
        """
        Credential for LuCI on :8443, which is a separate authentication domain
        from the JSON-RPC API. Usually the same value; on some setups it is not,
        which is why it is overridable rather than assumed.
        """
        env = os.environ.get("GLNET_LUCI_PASSWORD")
        if env:
            return env
        override = os.environ.get("GLNET_LUCI_PASSWORD_FILE")
        if override:
            return self._read_password_file(Path(override))
        return self.password

    @property
    def url(self) -> str:
        port = f":{self.port}" if self.port != 443 else ""
        return f"https://{self.host}{port}/rpc"


CONFIG = Config()

# --------------------------------------------------------------------------
# JSON-RPC client with the GL.iNet challenge/login handshake
# --------------------------------------------------------------------------

# challenge returns alg as a unix crypt identifier: 1 = MD5, 5 = SHA-256,
# 6 = SHA-512. The router we talk to returns 1.
PW_CRYPT: dict[int, Any] = {
    1: lambda pw, salt: md5_crypt.hash(pw, salt=salt),
    5: lambda pw, salt: sha256_crypt.hash(pw, salt=salt, rounds=5000),
    6: lambda pw, salt: sha512_crypt.hash(pw, salt=salt, rounds=5000),
}

ACCESS_DENIED = -32000
METHOD_NOT_FOUND = -32601
WRONG_PARAMS = -32602


class RouterError(RuntimeError):
    """A JSON-RPC error from the router, with the code kept for mapping."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


class GlInet:
    """
    Minimal GL.iNet 4.x JSON-RPC client.

    Wire protocol:
      1. challenge  -> {salt, alg, nonce[, hash-method]}
      2. login      -> {sid}   hash = H("user:crypt(pw,salt,alg):nonce")
      3. call       -> params is [sid, module, method, args]

    Sessions expire. Rather than a keep-alive thread, a -32000 re-authenticates
    once and retries; that covers expiry without a background timer racing the
    stdio transport.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.sid: str | None = None
        self._id = 0
        # One router, one session. Without this, concurrent tool calls each
        # saw -32000 and re-authenticated, and every re-login invalidated the
        # session id the others were mid-flight with -- which surfaced as
        # spurious "Access denied" on perfectly valid methods. Verified: six
        # parallel calls all failed, the same six in series all succeeded.
        self._lock = threading.Lock()
        if cfg.verify_tls:
            self._ssl = ssl.create_default_context()
        else:
            self._ssl = ssl.create_default_context()
            self._ssl.check_hostname = False
            self._ssl.verify_mode = ssl.CERT_NONE

    # -- transport ---------------------------------------------------------

    def _next_id(self) -> int:
        self._id = (self._id + 1) % 9_999_999_999
        return self._id

    def _post(self, payload: dict) -> dict:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.cfg.url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout, context=self._ssl) as r:
                raw = r.read()
        except urllib.error.HTTPError as exc:
            raise RouterError(-1, f"HTTP {exc.code} from {self.cfg.url}: {exc.read()[:200]!r}") from exc
        except urllib.error.URLError as exc:
            raise RouterError(-1, f"cannot reach {self.cfg.url}: {exc.reason}") from exc

        data = json.loads(raw)
        if data.get("error"):
            err = data["error"]
            raise RouterError(err.get("code", -1), err.get("message", "unknown error"))
        return data.get("result", {})

    # -- auth --------------------------------------------------------------

    def login(self) -> str:
        password = self.cfg.password
        if not password:
            raise RouterError(
                -1,
                "no router password configured. Set GLNET_PASSWORD, or write it to "
                f"{self.cfg.password_file} (chmod 600)",
            )

        challenge = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "challenge",
                "params": {"username": self.cfg.user},
            }
        )
        crypt_id = challenge.get("alg")
        crypt_fn = PW_CRYPT.get(crypt_id)
        if crypt_fn is None:
            raise RouterError(-1, f"unsupported crypt alg from router: {crypt_id!r}")

        # Bound to the local `password` so the file cannot change mid-handshake
        # and produce a hash from two different secrets.
        pw_hash = crypt_fn(password, challenge["salt"])
        # "hash-method" only exists on firmware >= 4.8; older routers are md5.
        hash_name = challenge.get("hash-method", "md5")
        if hash_name not in ("md5", "sha256", "sha512"):
            raise RouterError(-1, f"unsupported hash-method from router: {hash_name!r}")
        digest = hashlib.new(hash_name)
        digest.update(f"{self.cfg.user}:{pw_hash}:{challenge['nonce']}".encode())

        result = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "login",
                "params": {"username": self.cfg.user, "hash": digest.hexdigest()},
            }
        )
        sid = result.get("sid")
        if not sid:
            raise RouterError(-1, f"login returned no sid: {result}")
        self.sid = sid
        return sid

    def ensure_login(self) -> str:
        return self.sid or self.login()

    # -- calls -------------------------------------------------------------

    def call(self, module: str, method: str, args: dict | None = None,
             reveal_secrets: bool = False) -> Any:
        """
        Invoke a vendor method. Re-authenticates once on a dead session.

        Results are redacted here, at the single point every reply passes
        through, so no tool can leak a secret by forgetting to scrub. Pass
        reveal_secrets=True only when you genuinely need the plaintext.
        """
        with self._lock:
            sid = self.ensure_login()
            params: list = [sid, module, method]
            if args is not None:
                params.append(args)
            payload = {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "call",
                "params": params,
            }
            try:
                result = self._post(payload)
            except RouterError as exc:
                if exc.code != ACCESS_DENIED:
                    raise
                self.sid = None
                params[0] = self.login()
                payload["id"] = self._next_id()
                result = self._post(payload)

        if reveal_secrets:
            return result

        redacted, hits = redact(result)
        # Say what was hidden. Silent removal reads identically to "the router
        # never had that field", which is worse than useless when you are
        # trying to work out what a method actually returns.
        if hits and isinstance(redacted, dict):
            redacted["_redacted"] = hits[:REDACTED_NOTE]
            if len(hits) > REDACTED_NOTE:
                redacted["_redacted"].append(f"...and {len(hits) - REDACTED_NOTE} more")
        return redacted


ROUTER = GlInet(CONFIG)


def tool_safe(fn):
    """
    Turn router and validation failures into a structured result.

    Without this, a RouterError escapes and the MCP layer reports only
    "Error executing tool <name>" -- the actual reason (method removed, bad
    argument, session gone) is discarded. That cost real time after the
    firmware upgrade, when several tools failed with no diagnostic at all.
    """

    @functools.wraps(fn)
    def inner(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RouterError as exc:
            out = {"error": exc.message, "code": exc.code}
            name = kwargs.get("method")
            if exc.code == METHOD_NOT_FOUND and isinstance(name, str):
                out["hint"] = hint_for(kwargs.get("module", ""), name)
            elif exc.code == ACCESS_DENIED:
                out["hint"] = "session rejected; the router may have rebooted or the password changed"
            return out
        except ValueError as exc:
            return {"error": str(exc)}

    return inner

# --------------------------------------------------------------------------
# the recovered API catalog (docs.gl-inet.com / dev.gl-inet.com, taken down
# Jan 2024; this copy comes from python-glinet, which bundles it)
# --------------------------------------------------------------------------

_CATALOG: dict | None = None


def catalog() -> dict:
    global _CATALOG
    if _CATALOG is None:
        if CATALOG_PATH.exists():
            _CATALOG = json.loads(CATALOG_PATH.read_text())
        else:
            _CATALOG = {}
    return _CATALOG


def find_method(module: str, method: str) -> dict | None:
    return catalog().get(module, {}).get("case_groups_data", {}).get(method)


def _uncertain(source: str) -> bool:
    """
    Does this catalog entry's provenance mean the method may not exist?

    The catalog is generated by build_catalog.py, which tags every entry with
    where it came from. Entries the router's own UI calls are known to exist;
    entries merged from an older catalog are guesses. Both server and api_search
    ask this one question so the phrasing can change in exactly one place.
    """
    s = source.lower()
    return "unconfirmed" in s or "not seen in this firmware" in s


def hint_for(module: str, method: str) -> str:
    """The catalog's own request example for a method, for error messages."""
    entry = find_method(module, method)
    if not entry:
        if not catalog():
            return ("no catalog loaded -- run ./build_catalog.py <firmware.bin> to "
                    "generate one from your router's firmware, or use rpc_call anyway "
                    "and let the router answer")
        return "no catalog entry for this method -- it may postdate the snapshot"
    source = entry.get("source", "")
    if _uncertain(source):
        # The common failure after a firmware upgrade: the method is in the
        # catalog and gone from the router. Saying so beats showing a confident
        # example request for something that no longer exists.
        return (f"{method} is in the catalog but was not seen in this firmware's "
                f"UI, so it may have been removed or renamed. Try api_search for "
                f"the replacement, or rebuild the catalog from your firmware.")
    return f"catalog example: {entry.get('in_example', 'n/a')}"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def require_mac(mac: str) -> str:
    mac = mac.strip().lower()
    if not MAC_RE.match(mac):
        raise ValueError(f"{mac!r} is not a colon-separated MAC address")
    return mac


def require_ip(ip: str) -> str:
    ip = ip.strip()
    if not IP_RE.match(ip) or any(int(p) > 255 for p in ip.split(".")):
        raise ValueError(f"{ip!r} is not an IPv4 address")
    return ip


# --------------------------------------------------------------------------
# secret redaction
#
# Why this exists: `system.get_status` returns the cleartext WPA passphrase of
# every SSID in a `passwd` field. Any tool that passes a router reply through
# verbatim therefore pushes your Wi-Fi keys into the model context and into
# OpenCode's logs. Redaction happens in ONE place -- GlInet.call() -- rather
# than per tool, so a tool added later cannot leak by forgetting to scrub.
#
# Deliberately NOT redacted: mac, sn, key/public_key/peer_key. Those are
# identifiers; hiding them makes the output unusable without protecting
# anything. Public keys are public.
# --------------------------------------------------------------------------

SECRET_KEYS = {
    "passwd",
    "password",
    "passcode",
    "psk",
    "preshared_key",
    "private_key",
    "privatekey",
    "priv_key",
    "privkey",
    "secret",
    "client_secret",
    "token",
    "authpass",
    "auth_pass",
    "pin",
    "otp",
    "hash",
    "sid",
}

REDACTED_NOTE = 12  # cap the path list so a huge reply cannot bloat context


def redact(node: Any, path: str = "$") -> tuple[Any, list[str]]:
    """
    Replace values under secret-looking keys with a marker, and report which
    paths were masked so the caller knows something is hidden rather than
    assuming the field was absent.

    Key-name based, so it catches structured secrets only. A private key inside
    an opaque config *string* (WireGuard and OpenVPN exports do this) is not
    caught -- see the "reveal_secrets" note in rpc_call.
    """
    if isinstance(node, dict):
        out: dict = {}
        hits: list[str] = []
        for key, value in node.items():
            here = f"{path}.{key}"
            if isinstance(value, str) and key.lower() in SECRET_KEYS:
                out[key] = f"[redacted {key}]"
                hits.append(here)
            elif isinstance(value, (dict, list)):
                child, child_hits = redact(value, here)
                out[key] = child
                hits.extend(child_hits)
            else:
                out[key] = value
        return out, hits
    if isinstance(node, list):
        out_list: list = []
        hits_l: list[str] = []
        for i, value in enumerate(node):
            child, child_hits = redact(value, f"{path}[{i}]")
            out_list.append(child)
            hits_l.extend(child_hits)
        return out_list, hits_l
    return node, []


def as_int(value: Any) -> int:
    """
    4.7.x sent total_rx/total_tx as integers; 4.10.x sends them as strings.
    Coerce rather than assume, so a type change in firmware cannot crash a tool.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def compact(result: Any, limit: int = 40_000) -> Any:
    """Keep a huge reply from flooding context. clients.get_list is big."""
    text = json.dumps(result)
    if len(text) <= limit:
        return result
    return {
        "_truncated": True,
        "_bytes": len(text),
        "_preview": text[:limit],
        "_note": f"reply was {len(text)} bytes; ask for a narrower method or filter",
    }


# --------------------------------------------------------------------------
# the server
# --------------------------------------------------------------------------

mcp = _Server(
    "glnet",
    instructions=(
        "Manage a GL.iNet router (GL.iNet firmware 4.x) over its vendor JSON-RPC API. "
        "Start with router_status and list_clients. DHCP reservations are 'static binds': "
        "list_static_binds / add_static_bind / remove_static_bind -- on firmware 4.10 the "
        "router implements these in its 'vlan_subnet' module, scoped to a subnet whose "
        "default name is 'main'. For anything not exposed as a curated tool, use api_search "
        "to find the vendor method and rpc_call to invoke it. Writes take effect immediately "
        "on the router."
    ),
)


@mcp.tool()
@tool_safe
def router_status() -> dict:
    """Model, firmware version, uptime, load. The thing to call first."""
    out: dict[str, Any] = {"endpoint": CONFIG.url}
    for method in ("get_info", "get_status", "get_load"):
        try:
            out[method] = ROUTER.call("system", method)
        except RouterError as exc:
            out[method] = f"unavailable: {exc.message}"
    return out


@mcp.tool()
@tool_safe
def api_modules() -> dict:
    """Every vendor module the API exposes, with its method names."""
    cat = catalog()
    return {
        "module_count": len(cat),
        "method_count": sum(len(m.get("case_groups_data", {})) for m in cat.values()),
        "modules": {
            name: sorted(m.get("case_groups_data", {}).keys()) for name, m in sorted(cat.items())
        },
    }


@mcp.tool()
@tool_safe
def api_search(query: str, limit: int = 15) -> dict:
    """
    Search the vendor API catalog by module, method or description.

    GL.iNet removed the public 4.x docs in Jan 2024, so this bundled catalog is
    how you find a method that no curated tool covers. Returns the exact request
    shape to hand to rpc_call.

    Each hit carries a `source`. A provenance naming the firmware's own UI means
    the router really calls it, so the method exists; one naming an older catalog
    means it may have been removed or renamed by an upgrade and the router has to
    be the arbiter. If no catalog has been generated, every search comes back
    empty and the note tells you how to build one.

    Matching is token-wise and underscore-insensitive, so "static bind" finds
    add_static_bind and "port forward" finds add_port_forward.
    """
    tokens = [t for t in re.split(r"[\s_\-]+", query.lower()) if t]
    if not tokens:
        return {"query": query, "hits": [], "note": "empty query"}

    scored: list[tuple[int, dict]] = []
    for mod, data in catalog().items():
        for name, entry in data.get("case_groups_data", {}).items():
            desp = ((entry.get("data") or {}).get("desp", "") or "").lower()
            # Underscores and hyphens in identifiers are word boundaries to a
            # human typing a phrase; treat them as spaces on both sides.
            ident = f"{mod} {name}".lower().replace("_", " ").replace("-", " ")
            hay = f"{ident} {desp}"
            ident_tokens = set(ident.split())
            desp_tokens = set(hay.split())
            # Every query token must appear somewhere, otherwise it is noise.
            if not all(t in desp_tokens for t in tokens):
                continue
            # Rank exact identifier matches above description-only matches.
            score = sum(3 if t in ident_tokens else 1 for t in tokens)
            if name.lower() == query.lower().replace(" ", "_"):
                score += 10
            source = entry.get("source", "")
            # A method the 4.10.1 UI really calls is known to exist; one left
            # over from the 4.7 snapshot is a guess. Rank guesses below facts and
            # say which is which, so a stale hit cannot read like a live one.
            if _uncertain(source):
                score -= 6
            scored.append(
                (
                    score,
                    {
                        "module": mod,
                        "method": name,
                        "description": ((entry.get("data") or {}).get("desp", "") or ""),
                        "params": [
                            {"name": p.get("keyName"), "type": p.get("dataType__name")}
                            for p in entry.get("params", [])
                        ],
                        "example": entry.get("in_example"),
                        "source": source or "unknown vintage",
                    },
                )
            )

    scored.sort(key=lambda pair: (-pair[0], pair[1]["module"], pair[1]["method"]))
    hits = [h for _, h in scored[:limit]]
    if not hits:
        hint = ("no catalog loaded; generate one with ./build_catalog.py <firmware.bin>"
                if not catalog() else
                "no catalog match; the method may postdate this catalog. Try "
                "api_modules, rebuild with ./build_catalog.py, or rpc_call anyway "
                "and let the router tell you.")
        return {"query": query, "hits": [], "note": hint}
    return {"query": query, "hits": hits, "total_matches": len(scored), "capped_at": limit if len(scored) > limit else None}



@mcp.tool()
@tool_safe
def rpc_call(module: str, method: str, params: dict | None = None,
             reveal_secrets: bool = False) -> dict:
    """
    Call any vendor JSON-RPC method directly. The escape hatch for the ~300
    methods without a curated tool; find names and arguments with api_search.

    Secret-looking fields (WPA passphrases, private keys, tokens) are replaced
    with a marker and listed under "_redacted". Pass reveal_secrets=True only
    when you actually need the plaintext -- it lands in the model context and
    in the session log.

    Example: rpc_call("system", "get_info", {})

    Note: the catalog is generated from a firmware image by build_catalog.py, and
    each entry says whether it was confirmed in that firmware's UI or only
    survives from an older catalog. "Method not found" on one of the latter means
    an upgrade removed or renamed it, not that you mistyped it.
    """
    try:
        return compact({"result": ROUTER.call(module, method, params or {},
                                             reveal_secrets=reveal_secrets)})
    except RouterError as exc:
        detail = ""
        if exc.code == METHOD_NOT_FOUND:
            detail = f" | {hint_for(module, method)}"
        elif exc.code == WRONG_PARAMS:
            detail = f" | expected shape: {hint_for(module, method)}"
        return {"error": exc.message, "code": exc.code, "hint": detail.lstrip(" |")}


# -- clients ---------------------------------------------------------------


def mac_is_randomized(mac: str) -> bool:
    """
    True if the MAC is locally administered, i.e. a randomly generated one.

    Android 10+ and iOS 14+ default to per-network random MACs and send no
    hostname, so on a modern network this bit is often the only device-type
    signal the router has. It is a hint, not an identification.
    """
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


@mcp.tool()
@tool_safe
def list_clients(online_only: bool = False, limit: int = 200) -> dict:
    """
    Connected and remembered devices: name, MAC, IP, interface, blocked state.

    Names come from the router's own alias/name field, which is only populated
    for devices you have labelled or that sent a hostname. Modern Android and
    iOS send neither and use a random MAC -- those show random_mac=true and an
    empty name, and cannot be identified from the router alone. If you need a
    specific phone or tablet, get its MAC from the device's Wi-Fi settings.

    This is where you find the MAC you need for a DHCP reservation.
    """
    result = ROUTER.call("clients", "get_list", {})
    clients = result.get("clients", result if isinstance(result, list) else [])
    if online_only:
        clients = [c for c in clients if c.get("online")]
    out = [
        {
            # 'name' is what this firmware actually sends; 'hostname' does not
            # exist on 4.7.x. 'alias' kept as a fallback for older layouts.
            "name": c.get("name") or c.get("alias") or "",
            "mac": c.get("mac"),
            "ip": c.get("ip"),
            "online": bool(c.get("online")),
            "interface": c.get("iface") or c.get("interface") or "",
            "blocked": bool(c.get("blocked")),
            "random_mac": mac_is_randomized(c.get("mac") or ""),
            "traffic_mb": round((as_int(c.get("total_rx")) + as_int(c.get("total_tx"))) / 1e6, 1),
        }
        for c in clients[:limit]
    ]
    return {"count": len(out), "total": len(clients), "clients": out}


@mcp.tool()
@tool_safe
def client_status() -> dict:
    """Totals only: how many clients online. Cheap."""
    return ROUTER.call("clients", "get_status", {})


@mcp.tool()
@tool_safe
def rename_client(mac: str, alias: str) -> dict:
    """Label a device in the router's UI. Non-destructive."""
    return ROUTER.call("clients", "set_info", {"mac": require_mac(mac), "alias": alias})


@mcp.tool()
@tool_safe
def block_client(mac: str, block: bool = True) -> dict:
    """Add to or remove from the router's blacklist. Denies network access."""
    return ROUTER.call("clients", "block_client", {"mac": require_mac(mac), "block": block})


# -- DHCP reservations -----------------------------------------------------
#
# Firmware 4.10 retired the whole `lan` module. Reservations moved to
# `vlan_subnet`, alongside the new 802.1Q VLAN feature, and each bind is now
# scoped to a subnet identified by `display_name` -- "main" is the default LAN.
# Names and argument shapes below were taken from the router's own UI bundle
# inside the 4.10.1 image (www/views/gl-sdk4-ui-vlan.common.js), then confirmed
# against the live API; they are not guesses from the stale 4.7 catalog.
#
#   call ["sid","vlan_subnet","get_static_bind_list"]                  (no args)
#   call ["sid","vlan_subnet","add_static_bind",
#         {name,mac,ip,hostname,display_name}]
#   call ["sid","vlan_subnet","set_static_bind",   {same}]
#   call ["sid","vlan_subnet","remove_static_bind",
#         {mode,display_name} + mac when mode==0]


DEFAULT_SUBNET = "main"


@mcp.tool()
@tool_safe
def list_static_binds(subnet: str = "") -> dict:
    """All DHCP reservations (the vendor calls these static binds).

    Each bind carries a `display_name` naming the subnet it belongs to; on a
    single-LAN router that is always "main". Pass subnet to narrow to one.
    """
    # get_static_bind_list takes no params object at all -- the router's own UI
    # calls it with three elements. Sending {} is accepted, but match the UI.
    result = ROUTER.call("vlan_subnet", "get_static_bind_list", None)
    if subnet:
        binds = result.get("static_bind_list", [])
        result = dict(result)
        result["static_bind_list"] = [
            b for b in binds if b.get("display_name") == subnet
        ]
        result["subnet_filter"] = subnet
    return result


@mcp.tool()
@tool_safe
def add_static_bind(name: str, mac: str, ip: str,
                    hostname: str = "", subnet: str = DEFAULT_SUBNET) -> dict:
    """
    Reserve an IP for a MAC address. Fails if the reservation already exists --
    use modify_static_bind in that case. Always re-reads the list afterwards so
    the caller sees the router's state rather than trusting this call's return.

    `hostname` is optional and separate from `name`: `name` is the label shown
    in the router UI, `hostname` is what gets handed to the client via DHCP.
    """
    name = name.strip()
    if not name:
        raise ValueError("name is required")
    args = {
        "name": name,
        "mac": require_mac(mac),
        "ip": require_ip(ip),
        "hostname": hostname,
        "display_name": subnet or DEFAULT_SUBNET,
    }
    result = ROUTER.call("vlan_subnet", "add_static_bind", args)
    return {"sent": args, "router_said": result,
            "verify": ROUTER.call("vlan_subnet", "get_static_bind_list", None)}


@mcp.tool()
@tool_safe
def modify_static_bind(name: str, mac: str, ip: str,
                       hostname: str = "", subnet: str = DEFAULT_SUBNET) -> dict:
    """Change an existing reservation's IP or name, matched on MAC.

    Send the full record: this replaces the entry rather than patching it, so
    omitting hostname clears it.
    """
    args = {
        "name": name.strip(),
        "mac": require_mac(mac),
        "ip": require_ip(ip),
        "hostname": hostname,
        "display_name": subnet or DEFAULT_SUBNET,
    }
    result = ROUTER.call("vlan_subnet", "set_static_bind", args)
    return {"sent": args, "router_said": result}


@mcp.tool()
@tool_safe
def remove_static_bind(mac: str, all_binds: bool = False, confirm: bool = False,
                       subnet: str = DEFAULT_SUBNET) -> dict:
    """
    Delete one DHCP reservation by MAC, or every reservation in a subnet with
    all_binds=True -- which needs confirm=True.
    """
    if all_binds and not confirm:
        return {
            "error": "refusing: all_binds=True deletes every reservation in "
            "that subnet. Re-call with confirm=True if you meant that."
        }
    args: dict = {"mode": 1 if all_binds else 0,
                  "display_name": subnet or DEFAULT_SUBNET}
    if not all_binds:
        args["mac"] = require_mac(mac)
    result = ROUTER.call("vlan_subnet", "remove_static_bind", args)
    return {"sent": args, "router_said": result}


# -- network / wifi / firewall ---------------------------------------------


@mcp.tool()
@tool_safe
def arp_table() -> dict:
    """ARP table: what the router actually sees on the wire right now, by IP/MAC/interface.

    On the 4.7.11 and 4.10.1 firmware this was built against, no method lists
    DHCP leases -- network.get_dhcp_leases appears in older catalogs and returns
    Method not found on both. This is the nearest equivalent for "which IP does
    this device currently have". Check api_search for your own version.
    """
    return compact(ROUTER.call("network", "get_arp_list", None))


@mcp.tool()
@tool_safe
def lan_config() -> dict:
    """Every IP subnet the router serves: address, netmask, DHCP pool bounds,
    lease time, DNS, attached wired/wireless interfaces, and isolation flags.

    On 4.10 this is vlan_subnet.get_subnets, which replaced lan.get_config_list.
    Read it before reserving an address so it lands outside the dynamic pool
    (dhcp_start_ip through the end of the pool).
    """
    return compact(ROUTER.call("vlan_subnet", "get_subnets", {}))


@mcp.tool()
@tool_safe
def wifi_status() -> dict:
    """Radio state: SSIDs, channels, enabled/hidden, encryption."""
    return compact(ROUTER.call("wifi", "get_status", {}))


@mcp.tool()
@tool_safe
def list_port_forwards() -> dict:
    """Firewall port forwarding rules."""
    return ROUTER.call("firewall", "get_port_forward_list", {})


@mcp.tool()
@tool_safe
def add_port_forward(
    dest_ip: str,
    dest_port: int,
    proto: str = "tcp",
    src_dport: int | None = None,
    name: str = "",
    src: str = "wan",
    dest: str = "lan",
    enabled: bool = True,
) -> dict:
    """
    Forward a WAN port to a LAN host. Exposes a device to the internet; only
    call this when you are sure the port should be open.
    """
    args: dict = {
        "proto": proto,
        "src": src,
        "src_dport": src_dport if src_dport is not None else dest_port,
        "dest": dest,
        "dest_ip": require_ip(dest_ip),
        "dest_port": dest_port,
        "enabled": enabled,
    }
    if name:
        args["name"] = name
    result = ROUTER.call("firewall", "add_port_forward", args)
    return {"sent": args, "router_said": result}


@mcp.tool()
@tool_safe
def router_reboot(confirm: bool = False) -> dict:
    """Reboot the router. Drops every connection including this one.
    Requires confirm=True."""
    if not confirm:
        return {"error": "refusing: this reboots the router and cuts the network. Re-call with confirm=True."}
    return ROUTER.call("system", "reboot", {})


@mcp.tool()
@tool_safe
def session_info() -> dict:
    """Local diagnostics: are we authenticated, to what, and is a password set."""
    alive = None
    if ROUTER.sid:
        try:
            ROUTER.call("system", "get_load")
            alive = True
        except RouterError as exc:
            alive = f"session dead: {exc.message}"
    return {
        "url": CONFIG.url,
        "user": CONFIG.user,
        "password_configured": bool(CONFIG.password),
        "session": alive if alive is not None else ("live" if ROUTER.sid else "not logged in yet"),
        "catalog_modules": len(catalog()),
        "tls_verification": CONFIG.verify_tls,
    }


# --------------------------------------------------------------------------
# configuration backup
#
# Not a vendor JSON-RPC method: on 4.10.1 (and in the older published catalog)
# there is no backup method in the API at all. Backup lives in LuCI, a second
# web UI on port 8443, served by /cgi-bin/cgi-backup -- a symlink to
# /usr/libexec/cgi-io, which selects its behaviour from argv[0].
#
# THE ARCHIVE IS THE SECRET. It contains etc/config/wireless (every Wi-Fi
# passphrase, in the clear) and /etc/shadow (the root password hash), plus
# reservations, firewall rules and VPN keys. So these tools are built to never
# return bytes: they write to disk with mode 0600 and report only metadata.
# redact() cannot help here -- there is nothing in the payload worth keeping.
#
# There is deliberately no restore tool. A restore reboots the router, can lock
# you out, and is not something to do because a language model asked politely.
# Do that in the browser, deliberately, at https://<router>:8443/cgi-bin/luci/
# --------------------------------------------------------------------------

LUCI_PORT = int(os.environ.get("GLNET_LUCI_PORT", "8443"))
BACKUP_DIR = Path(os.environ.get("GLNET_BACKUP_DIR", "/app/backups"))

# Presence of these is what makes an archive worth trusting. Checked by name
# only; their contents are never read.
CRITICAL_MEMBERS = (
    "etc/config/wireless",   # Wi-Fi passphrases
    "etc/config/dhcp",       # reservations
    "etc/config/firewall",   # port forwards, zones
    "etc/config/network",    # addressing
    "etc/shadow",            # root password hash
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The LuCI login answer is a 302 that carries the session cookie. Following
    it would hand us the page instead of the credential."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


def _luci_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ROUTER._ssl), _NoRedirect()
    )


def _luci_session() -> str:
    """
    Authenticate to LuCI and return the sysauth_https token.

    Separate credential domain from the JSON-RPC API: same username, but a
    different UI, a different port and its own session. On some setups the LuCI
    password is not the admin password the API uses -- point
    GLNET_LUCI_PASSWORD_FILE at it if so.
    """
    password = CONFIG.luci_password
    if not password:
        raise RouterError(
            -1,
            "no password available for LuCI. Set GLNET_LUCI_PASSWORD_FILE, or the "
            "same password file the API uses.",
        )
    body = urllib.parse.urlencode(
        {"luci_username": CONFIG.user, "luci_password": password}
    ).encode()
    req = urllib.request.Request(
        f"https://{CONFIG.host}:{LUCI_PORT}/cgi-bin/luci/",
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"https://{CONFIG.host}:{LUCI_PORT}/cgi-bin/luci/",
        },
        method="POST",
    )
    try:
        with _luci_opener().open(req, timeout=CONFIG.timeout) as resp:
            raw = resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as exc:
        raw = exc.headers.get_all("Set-Cookie") or [] if exc.headers else []
        if not raw:
            raise RouterError(
                -1,
                f"LuCI login failed with HTTP {exc.code} and set no session cookie. "
                f"LuCI on :{LUCI_PORT} likely has its own password, distinct from the "
                f"API password -- set GLNET_LUCI_PASSWORD_FILE.",
            ) from exc
    except urllib.error.URLError as exc:
        raise RouterError(
            -1, f"cannot reach LuCI on {CONFIG.host}:{LUCI_PORT}: {exc.reason}"
        ) from exc

    for cookie in raw:
        name, _, value = cookie.partition(";")[0].partition("=")
        if name.strip() == "sysauth_https":
            return value.strip()
    raise RouterError(-1, "LuCI set no sysauth_https cookie; login did not succeed")


def _describe_archive(path: Path) -> dict:
    """Metadata about an archive. Names only -- contents are never read."""
    import hashlib
    import tarfile

    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    out: dict = {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "mode": oct(path.stat().st_mode & 0o777),
    }
    try:
        with tarfile.open(path, "r:gz") as tar:
            names = set(tar.getnames())
        out["entries"] = len(names)
        out["critical_files_present"] = [m for m in CRITICAL_MEMBERS if m in names]
        out["critical_files_missing"] = [m for m in CRITICAL_MEMBERS if m not in names]
    except Exception as exc:  # noqa: BLE001 - a bad archive is an answer, not a crash
        out["error"] = f"not a readable gzip tar: {type(exc).__name__}: {exc}"
    return out


# --------------------------------------------------------------------------
# restore
#
# The LuCI ACL for this firmware is an exact argv allowlist, read from
# /usr/share/rpcd/acl.d/luci-mod-system.json inside the firmware image and then
# confirmed call by call against the live router:
#
#   exec  /bin/tar -tzf /tmp/backup.tar.gz                        allowed
#   exec  /sbin/sysupgrade --restore-backup /tmp/backup.tar.gz    allowed
#   exec  /sbin/sysupgrade --help                                 DENIED (argv not listed)
#   write /tmp/backup.tar.gz   via cgi-io upload                  allowed
#   write /tmp/glnet-probe.txt via cgi-io upload                  DENIED (path not listed)
#   read  /proc/uptime                                            DENIED (path not listed)
#   read  /proc/sys/kernel/hostname                               allowed
#
# That is why the remote path is a constant rather than a parameter, and why
# every argv below is built from literals. rpcd's file.exec is root command
# execution gated only by that list, so a tool taking a command string would be
# a remote root shell with an MCP schema around it. Nothing here accepts one.
# --------------------------------------------------------------------------

REMOTE_ARCHIVE = "/tmp/backup.tar.gz"   # the only writable staging path
CMD_VALIDATE = ("/bin/tar", ["-tzf", REMOTE_ARCHIVE])
CMD_RESTORE = ("/sbin/sysupgrade", ["--restore-backup", REMOTE_ARCHIVE])
MAX_UPLOAD_BYTES = 20 * 1024 * 1024     # a config backup is ~460 KB; more is a mistake


def _luci_rpc(token: str, method: str, args: dict) -> dict:
    """
    One rpcd call over LuCI's ubus bridge, returning the payload.

    admin/ubus sits under the session cookie's Path, so the cookie authenticates
    it -- the opposite of /cgi-bin/cgi-*, which the cookie cannot reach and which
    therefore needs the session as a body field.
    """
    req = urllib.request.Request(
        f"https://{CONFIG.host}:{LUCI_PORT}/cgi-bin/luci/admin/ubus",
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "call",
            "params": [token, "file", method, args],
        }).encode(),
        headers={
            "Content-Type": "application/json",
            "Cookie": f"sysauth_https={token}",
        },
        method="POST",
    )
    try:
        with _luci_opener().open(req, timeout=CONFIG.timeout) as resp:
            body = json.loads(resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as exc:
        raise RouterError(-1, f"LuCI ubus returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RouterError(-1, f"cannot reach LuCI ubus: {exc.reason}") from exc
    except ValueError as exc:
        raise RouterError(-1, f"LuCI ubus returned non-JSON: {exc}") from exc

    if "error" in body:
        raise RouterError(-1, f"LuCI ubus: {body['error'].get('message')}")
    result = body.get("result") or []
    code = result[0] if result else 0
    payload = result[1] if len(result) > 1 else {}
    if code == 6:
        raise RouterError(
            -1, "LuCI refused this call (rpcd ACL). The ACL is an exact argv "
                "allowlist; compare the command and path with "
                "/usr/share/rpcd/acl.d/luci-mod-system.json on the router.",
        )
    if code == 4:
        raise RouterError(-1, f"{args.get('path', '?')} does not exist on the router")
    if code != 0:
        raise RouterError(-1, f"LuCI rpcd returned code {code}")
    return payload


def _luci_upload(token: str, local: Path) -> dict:
    """
    PUT a local archive at the router's /tmp/backup.tar.gz.

    cgi-io reports back the size and the sha256 it computed, so the transfer can
    be verified against what we intended to send instead of merely trusted.
    """
    boundary = f"glnet{os.urandom(12).hex()}"
    head = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="sessionid"\r\n\r\n'
        f"{token}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="filename"\r\n\r\n'
        f"{REMOTE_ARCHIVE}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="filedata"; '
        f'filename="{local.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    with open(local, "rb") as fh:
        payload = head + fh.read() + tail

    req = urllib.request.Request(
        f"https://{CONFIG.host}:{LUCI_PORT}/cgi-bin/cgi-upload",
        data=payload,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Referer": f"https://{CONFIG.host}:{LUCI_PORT}/cgi-bin/luci/",
        },
        method="POST",
    )
    try:
        with _luci_opener().open(req, timeout=max(CONFIG.timeout, 120)) as resp:
            text = resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:200] if exc.fp else ""
        raise RouterError(-1, f"upload HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RouterError(-1, f"cannot reach LuCI upload endpoint: {exc.reason}") from exc

    try:
        report = json.loads(text)
    except ValueError:
        raise RouterError(-1, f"upload reply was not JSON: {text[:200]}") from exc
    if "sha256sum" not in report:
        raise RouterError(-1, f"upload reported no checksum: {text[:200]}")
    return report


def _luci_cleanup(token: str) -> bool:
    """Delete the staging archive. Best effort; a reboot clears /tmp anyway."""
    try:
        _luci_rpc(token, "remove", {"path": REMOTE_ARCHIVE})
        return True
    except RouterError:
        return False


def _fetch_backup(dest_dir: str = "", label: str = "",
                  token: str | None = None) -> dict:
    """
    Pull the running configuration archive from the router onto disk.

    Returns metadata only -- the archive is nothing but secrets. `token` may be
    passed in so a caller that already authenticated does not log in twice.
    """
    if token is None:
        token = _luci_session()
    out_dir = Path(dest_dir) if dest_dir else BACKUP_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)

    stamp = time.strftime("%Y-%m-%d")
    tag = f"-{re.sub(r'[^A-Za-z0-9._-]', '', label)}" if label else ""
    dest = out_dir / f"backup-{CONFIG.host}-{stamp}{tag}.tar.gz"

    req = urllib.request.Request(
        f"https://{CONFIG.host}:{LUCI_PORT}/cgi-bin/cgi-backup",
        data=f"sessionid={token}".encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with _luci_opener().open(req, timeout=max(CONFIG.timeout, 120)) as resp:
            head = resp.read(2)
            if head != b"\x1f\x8b":
                rest = resp.read(200)
                raise RouterError(
                    -1,
                    "cgi-backup did not return an archive: "
                    f"{(head + rest).decode(errors='replace')[:160]}",
                )
            # 0600 from the moment the file exists, not chmod after the fact.
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(head)
                shutil.copyfileobj(resp, fh)
    except urllib.error.HTTPError as exc:
        raise RouterError(-1, f"cgi-backup returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RouterError(-1, f"cannot reach LuCI: {exc.reason}") from exc

    info = _describe_archive(dest)
    info["note"] = ("archive written to disk with mode 0600; contents intentionally "
                    "not returned -- they are all secret")
    return info


@mcp.tool()
@tool_safe
def backup_config(dest_dir: str = "", label: str = "") -> dict:
    """
    Download a configuration backup from the router and save it to disk.

    Returns ONLY metadata -- path, size, sha256, entry count, which critical
    files are inside. The archive itself holds every Wi-Fi passphrase and the
    root password hash, so it is never returned, quoted, or summarised by
    content. Do not ask for the bytes; open the file locally if you need them.

    Written with mode 0600 for that reason. Keep it out of synced folders, and
    never attach one to a bug report.

    This reads the router; it changes nothing. The counterpart, restore_config,
    replaces everything and reboots -- read that one's warning before using it.
    """
    return _fetch_backup(dest_dir, label)


@mcp.tool()
@tool_safe
def restore_config(path: str, sha256: str, confirm: bool = False) -> dict:
    """
    Restore a configuration archive onto the router.

    *** THIS REPLACES THE RUNNING CONFIGURATION AND REBOOTS THE ROUTER. ***

    Every connection through it drops -- other hosts on the LAN, DNS, VPN, any
    service you run behind it, and this MCP session's own network path. Expect
    several minutes offline. A restore with the wrong archive, or one saved from
    a very different firmware, can leave the box unreachable, and recovering
    then means physical access: failsafe mode and a TFTP or sysupgrade flash.

    Without confirm=True nothing is changed. That call still uploads, has the
    router verify the archive, and deletes it again -- it is a real rehearsal, not
    a promise, and it is the most this can be tested without an outage.

    `sha256` is required and must be the hash of the file you are restoring. It
    is checked three times: against the local file, against what the router
    computes after receiving it, and again before the restore is dispatched. The
    point is not ceremony -- it is that a caller cannot restore a file it has not
    first looked at, which is the failure mode of a model guessing a filename.

    A safety backup of the current configuration is taken automatically first and
    its path is returned, so the state you are leaving is recoverable.

    Everything the router accepts here is fixed: the staging path is always
    /tmp/backup.tar.gz and the command is always
    `/sbin/sysupgrade --restore-backup /tmp/backup.tar.gz`, because the router's
    ACL permits no other invocation. There is no way to ask it for anything else.
    """
    local = Path(path)
    if not local.is_file():
        return {"aborted": True, "reason": f"no such file: {path}",
                "hint": "backup_config and inspect_backup report the paths they wrote"}

    want = (sha256 or "").strip().lower()
    if len(want) != 64 or any(c not in "0123456789abcdef" for c in want):
        return {"aborted": True,
                "reason": "sha256 must be the archive's full 64-character hash",
                "hint": "call inspect_backup or backup_config and pass the sha256 it returns"}

    info = _describe_archive(local)
    if "error" in info:
        return {"aborted": True, "reason": info["error"], "archive": info}
    if info["sha256"] != want:
        return {"aborted": True,
                "reason": "the file is not the archive that hash belongs to",
                "asked_for": want, "this_file_is": info["sha256"], "path": str(local)}
    if info["bytes"] > MAX_UPLOAD_BYTES:
        return {"aborted": True,
                "reason": f"archive is {info['bytes']} bytes; a config backup is far "
                          "smaller. This looks like a firmware image, not a backup."}
    if info.get("critical_files_missing"):
        return {"aborted": True,
                "reason": "archive lacks files a restore needs; restoring it would "
                          "leave those subsystems at defaults",
                "missing": info["critical_files_missing"]}

    token = _luci_session()

    # Insurance first: capture the state being replaced, while it still exists.
    try:
        safety = _fetch_backup(label="pre-restore", token=token)
        safety_out = {"pre_restore_backup": safety["path"],
                      "pre_restore_sha256": safety["sha256"]}
    except RouterError as exc:
        safety_out = {"pre_restore_backup": None,
                      "warning": f"no safety copy of the current config: {exc.message}"}

    report = _luci_upload(token, local)
    router_hash = str(report.get("sha256sum", "")).lower()
    if router_hash != want:
        _luci_cleanup(token)
        return {"aborted": True,
                "reason": "the router computed a different sha256 than the file we sent",
                "sent": want, "router_sees": router_hash,
                "action_taken": "staging archive deleted, nothing restored"}

    check = _luci_rpc(token, "exec", {"command": CMD_VALIDATE[0],
                                      "params": CMD_VALIDATE[1]})
    if check.get("code") != 0:
        _luci_cleanup(token)
        return {"aborted": True,
                "reason": "the router cannot read the archive it received",
                "tar": {"code": check.get("code"),
                        "stderr": str(check.get("stderr", ""))[:300]},
                "action_taken": "staging archive deleted, nothing restored"}

    if not confirm:
        removed = _luci_cleanup(token)
        return {
            "rehearsal_only": True,
            "reason": "confirm=True not passed, so nothing was restored",
            "verified": {
                "local_sha256": info["sha256"],
                "router_sha256": router_hash,
                "entries": info["entries"],
                "router_can_read_archive": True,
            },
            **safety_out,
            "staging_archive_removed": removed,
            "would_run": " ".join([CMD_RESTORE[0], *CMD_RESTORE[1]]),
            "what_happens_next": (
                "Calling again with confirm=True replaces the running config and "
                "reboots the router. Several minutes of no network for everything "
                "behind it. If the restored config changes the LAN address, the "
                "router may not be reachable at the address you know it by."
            ),
        }

    try:
        result = _luci_rpc(token, "exec", {"command": CMD_RESTORE[0],
                                           "params": CMD_RESTORE[1]})
        return {"restore_completed_cleanly": True, "reply": result, **safety_out,
                "next": "the router is rebooting; do not power-cycle it"}
    except RouterError as exc:
        # A dropped connection here is the expected outcome: sysupgrade reboots
        # the box mid-request, so the reply never arrives. A refusal is different
        # and must not be mistaken for success.
        refused = ("refused" in exc.message or "returned code" in exc.message
                   or "ubus:" in exc.message)
        if refused:
            return {"aborted": True, "restored": False,
                    "reason": f"the router rejected the restore: {exc.message}",
                    **safety_out,
                    "action_taken": "staging archive left in /tmp; reboot or "
                                    "restore_config again clears it"}
        return {"restore_initiated": True, "restored": "unknown", **safety_out,
                "reason": f"the connection to the router ended during the restore: "
                          f"{exc.message}",
                "next": ("this is what a successful restore looks like from here -- "
                         "sysupgrade reboots the router before it can answer. Wait "
                         "several minutes, then check reachability before anything "
                         "else. Do not power-cycle.")}


@mcp.tool()
@tool_safe
def inspect_backup(path: str) -> dict:
    """
    Report what a saved backup archive contains: size, sha256, entry count and
    whether the critical config files are inside. Metadata only; the contents
    are never read or returned.

    Use it to answer "is this backup any good?" without putting Wi-Fi keys or the
    root hash in front of a model.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}"}
    return _describe_archive(target)


if __name__ == "__main__":
    mcp.run()
