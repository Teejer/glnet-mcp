# glnet-mcp

An MCP server for **GL.iNet routers** (firmware 4.x), speaking the same vendor
JSON-RPC API the router's own admin panel uses.

It runs on your machine, authenticates as the router's normal web-UI user, and
installs **nothing on the router** — no SSH keys, no daemon, no agent.

Built and tested against a **GL.iNet GL-BE9300 (Flint 3)**. Most of what is here
applies to any GL.iNet on firmware 4.x, but see *Firmware drift* — the API moves
between releases and this project assumes it will.

## Why this exists

GL.iNet published a 4.x API reference at `dev.gl-inet.com` and **took it down in
January 2024**. It has not come back. What is left is the API the web UI calls,
which you can observe but not read about, and which changes across releases:

- **4.8** added a `hash-method` field to the login challenge.
- **4.10** deleted the entire `lan` module and moved DHCP reservations into a new
  `vlan_subnet` module built around the new 802.1Q VLAN feature.

So the interesting problem here is not "wrap 300 RPC methods". It is how to stay
useful against an API that is undocumented and moves under you. Two answers:

1. **Generate the method catalog from the firmware you actually run** — see below.
2. **Say "I don't know" instead of guessing.** Every catalog entry carries its
   provenance, and a method that only survives from an older catalog is labelled
   as such rather than presented as fact.

## Install

```bash
git clone https://github.com/Teejer/glnet-mcp && cd glnet-mcp
./build_catalog.py ~/Downloads/<your-model>-<version>.bin   # optional, see below
umask 077 && read -rs pw && printf '%s' "$pw" > glnet.password && echo
docker build -t glnet-mcp:1.0.0 .
```

Then point any MCP client at the launcher:

```json
{
  "mcp": {
    "servers": {
      "glnet": {
        "type": "local",
        "command": ["/absolute/path/to/glnet-mcp/glnet-mcp-container.sh"],
        "timeout": { "startup": 60000 }
      }
    }
  }
}
```

Prefer no container? `./glnet-mcp.sh` runs the same server from a venv
(`uv venv && uv pip install -r requirements.txt`). It is the path I use while
hacking, so I do not rebuild on every edit.

The catalog step is optional. Without it, every curated tool works and
`rpc_call` works; only `api_search` is blind, and it says so.

## Generating the catalog

`build_catalog.py` takes a firmware image and finds out, from the router itself,
which methods exist:

```bash
./build_catalog.py be9300-4.10.1_release1-1129-0918-1789732857.bin
```

It locates the squashfs inside the image by parsing superblocks rather than
trusting a fixed offset, extracts it with `unsquashfs` (or `7z`), and greps the
web UI's JavaScript bundles for the router's own call convention:

```js
$("call", ["sid", "vlan_subnet", "add_static_bind", payload])
```

That yields every `module.method` the UI actually invokes — the best available
record of what a given firmware really exposes. Pass `--legacy <older.json>` to
merge parameter documentation from an earlier catalog; those entries come through
labelled as unverified.

Images are at <https://dl.gl-inet.com/>. **Verify the download against the
checksum that page publishes.** This script will cheerfully build a catalog out
of a truncated file.

The catalog is deliberately **not committed here**. Shipping one guarantees it is
wrong for someone else's firmware, and the older circulated dumps are scrapes of
GL.iNet's dead documentation site with unclear redistribution terms. Everything
in this repo is written here; the catalog is a build artifact, like a lockfile.

On a BE9300 running 4.10.1 this produces 347 methods across 51 modules.

Rebuilding is not idempotent, and the first time I ran it over a working catalog
it cost 106 methods without complaining. `build_catalog.py` knows only what the
firmware's UI bundle and the `--legacy` catalog contain; it knows nothing about
methods recovered afterwards from the handler files, and those are where most of
the parameter knowledge lives. `merge_catalog.py` exists to make the rebuild
additive: it takes the rebuilt file as the base, because that is the only one
carrying the per-module `firmware_handler` cross-check, carries forward anything
the live catalog has that the rebuild dropped, and labels where each carried
entry actually came from. On 4.10.1 that is 89 handler-recovered methods carried
and none silently lost.

## Where parameters come from

The catalog knows which methods exist; parameters are a separate problem, and
the handlers themselves answer it. They ship in the firmware at
`usr/lib/oui-httpd/rpc`, one file per module, in three kinds:

| kind | count | what it gives up |
|---|---|---|
| plain Lua source | 18 | `params.<key>` reads, readable directly |
| Lua 5.1 bytecode | 37 | same, via a small disassembler |
| ELF shared object | 10 | nothing yet — policy tables need disassembly |

```bash
./extract_handler_docs.py /path/to/extracted-rootfs --apply
```

`luaread.py` reads the bytecode. It is **not stock Lua 5.1**: a 12-byte header
with no `LUAC_DATA`/`LUAC_INT` magic (stock `lua5.1` rejects these files as
"bad header"), field widths declared at bytes 7..10 that differ between builds,
upvalue records that are name-only, and an extra opcode inserted after
`GETTABLE` that shifts every opcode above it — so the table-store is 9, not 8.
Every one of those was settled by parsing a file compiled locally from known
source, not read out of a specification. 37 of 37 handler files parse to EOF.

A method name pairs with its body because `function M.get_config(params)`
compiles to a `CLOSURE` plus a store whose key is the string `"get_config"`, and
the parameters are the keys the body reads off its first argument. The rule is
deliberately narrow. Promoting upvalue-loaded registers to "the argument" also
promotes `uci` and `fs`, and turned `kmwan.set_sensitivity`'s single real key
into five, four of them file and JSON helpers. Requiring a declared parameter is
what stops `get_config()`, which uses register 0 for a uci cursor, from
inventing inputs.

Eight handler files also carry the vendor's own doc comments — `@in`/`@out` with
typed field paths plus a literal `@in-example`/`@out-example`. That is the only
source here stating intent rather than behaviour, and it wins on ties.

Recovered names are labelled with where they came from, because the two kinds of
claim are not equivalent:

```
"how_to_call": "needs a payload with sensitivity -- recovered from keys read
                off the argument in the firmware's handler bytecode"
"params_basis": "the handler's own doc comment"          # when that is the source
```

Keys the handler *reads* are behaviour, not contract: a key can be read and
ignored, and one validated inside a helper this pass does not follow is missing.
Treat the inferred list as a strong starting guess, and confirm on a read before
trusting it on a write.

Two answers were checked against sources outside this code: `kmwan.set_sensitivity`
yields exactly `sensitivity`, which the UI bundle's call site says, and
`sms-forward.get_config` yields exactly `modem_mode`, which the router's own error
message names.

## Firmware drift

What 4.7.11 → 4.10.1 actually did, measured by probing 110 read-only methods:
**57 survived, 53 returned** *Method not found*. Roughly half the API moved.

| 4.7 | 4.10 |
|---|---|
| `lan.get_static_bind_list` | `vlan_subnet.get_static_bind_list` — **takes no params object** |
| `lan.add_static_bind {name,mac,ip}` | `vlan_subnet.add_static_bind {name,mac,ip,hostname,display_name}` |
| `lan.remove_static_bind {mode,mac}` | `vlan_subnet.remove_static_bind {mode,display_name,mac}` |
| `lan.get_config_list` | `vlan_subnet.get_subnets` |
| `total_rx`/`total_tx` integers | same fields, now **strings** |

Two details that cost real time:

- **`get_static_bind_list` takes no third parameter at all.** The UI calls it as
  `[sid, module, method]`. Sending `{}` happens to work; matching the UI is safer.
- **Every reservation is scoped to a subnet** via `display_name`, defaulting to
  `"main"`. On a router with VLANs there is more than one, and a reservation in
  the wrong subnet is invisible to the one you are looking at.

`KNOWN_SHAPES` in `build_catalog.py` carries parameter shapes transcribed from
the router's minified UI code, because the UI is the only documentation left. If
a call fails for you, that dict is where to add what you learned.

## Tools (22)

**Read** — `router_status`, `list_clients`, `client_status`, `arp_table`,
`lan_config`, `wifi_status`, `list_static_binds`, `list_port_forwards`,
`session_info`, `api_modules`, `api_search`, `inspect_backup`

**Write** — `add_static_bind`, `modify_static_bind`, `remove_static_bind`,
`rename_client`, `block_client`, `add_port_forward`, `router_reboot`

**Config backup** — `backup_config`, and `restore_config` which reboots the
router. Both go through LuCI on port 8443, not the vendor API, because the vendor
API has no backup method at all. **Read [BACKUP.md](BACKUP.md) before calling
`restore_config`** — it explains the three independent guards on that call and
which parts of it cannot be tested without taking your network down. Neither tool
ever returns archive bytes: the archive is nothing but secrets.

**Generic** — `rpc_call`, any method your router exposes

`router_reboot` and `remove_static_bind(all_binds=True)` refuse to run without
`confirm=True`. `block_client` and `add_port_forward` have no guard — they are
routine operations — but they do cut a device off and open the firewall,
respectively. `add_static_bind` always re-reads the list afterwards and returns
it, because a write's own return value is not proof the write persisted.

## Security notes

**Reads return your Wi-Fi passphrases in cleartext.** `system.get_status`
includes a `passwd` field for every SSID — main, guest, IoT — as plaintext PSKs,
not hashes. An agent that dutifully passes router replies into model context is
therefore publishing your wireless keys into a transcript and a log file.

`redact()` runs inside `GlInet.call()`, the single choke point every reply passes
through, so a tool added later cannot leak by forgetting to scrub. It matches on
key name (`passwd`, `password`, `psk`, `private_key`, `secret`, `token`, `pin`,
`hash`, `sid`…) and leaves identifiers alone — MACs, serials and public keys
stay, because hiding them costs usability and protects nothing.

It reports what it hid rather than deleting it silently:

```json
{"wifi": [{"ssid": "Home-2.4G", "passwd": "[redacted passwd]", "up": true}],
 "_redacted": ["$.wifi[0].passwd", "$.wifi[1].passwd", "..."]}
```

Silent removal reads identically to "this field never existed", which is worse
than useless when you are mapping an API. `rpc_call` accepts
`reveal_secrets=true` for the rare case you need the real value — it then lands
in the transcript deliberately.

**Not caught:** a private key embedded inside an opaque config *string*, which
WireGuard and OpenVPN exports do. Key-name matching cannot see into a blob.

**The password is never an environment variable**, because env is readable via
`docker inspect`. The launcher stages it on tmpfs (`$XDG_RUNTIME_DIR`, dir 700,
file 600), bind-mounts it read-only, and deletes it on exit.

**TLS verification is off by default** — the router ships a self-signed
certificate. On a LAN that is a reasonable trade; `GLNET_VERIFY_TLS=1` turns
verification on if you have pinned the cert.

### Container sandbox

`--read-only` rootfs, `--cap-drop ALL`, `no-new-privileges`, pid and memory
limits, non-root, tmpfs `/tmp`. The only thing that leaves the container is HTTPS
to the router.

### TPM2 sealing, and the mistake it taught me

`seal-password.sh` can bind the password to a TPM2 so a stolen disk or an
off-site backup does not yield it. (It does not protect against a process already
running as you — that process can run the launcher and get plaintext like anyone
else.)

It now **refuses to seal** unless `/var/lib/systemd/tpm2/srk.pub` exists. The
reason is a story:

`systemd-analyze has-tpm2` returning yes does not mean systemd has a *persistent*
storage root key. On a machine where `systemd-tpm2-setup.service` is inactive —
and on many setups its `ConditionSecurity=measured-os` is never met, because
measured boot is not enabled — a seal is made against transient runtime state. It
decrypts fine for a while. Then that state goes away and the secret is
**permanently unrecoverable**.

This happened here. A seal was made, a same-session round-trip passed, the
plaintext was deleted on the strength of it, and about half an hour later the
router password existed nowhere. `seal-password.sh` now checks for the SRK file
first, and will not delete a plaintext without an explicit `--delete-plaintext`
plus a reboot-and-recheck. A round-trip in the same session proves the seal
works *now*, which is not the claim you are relying on when you delete the
fallback.

### Lifecycle, and a leak this found

`docker run` has no "exit when the client dies" flag, and this launcher cannot
background the `docker run` to wait on it: a backgrounded command in a
non-interactive shell gets stdin from `/dev/null`, and stdin *is* the MCP channel.
So a launcher killed by `SIGKILL` orphaned its container — and that container
holds the bind-mounted plaintext password.

This was not theoretical. Four killed test launches left four running containers
and four plaintext copies of the router password on tmpfs.

Three things handle it now:

- a detached watchdog subshell watches for the launcher's `/proc` entry to vanish
  and tears the container down behind it. `SIGKILL` reparents the subshell rather
  than killing it, so it still fires. Verified by `kill -9`.
- on startup the launcher reaps any `glnet-mcp-<pid>` container whose launcher PID
  is gone — the PID is in the container name, so liveness is checkable without
  guessing.
- staging directories are swept, but **age alone is not proof of death**: the
  sweep skips any directory still bind-mounted by a running container. The server
  reads the password lazily at every login, so deleting a live container's staged
  secret does not free an orphan — it breaks that server's next re-login.

## Findings from a live router

Things that only show up by running this against real hardware:

- `clients.get_list` sends **`name`**, not `hostname`, and **`iface`**, not
  `interface`. An early version read the wrong keys and silently returned every
  client with an empty name — no error, just useless output.
- Most clients have no name. Android 10+ and iOS 14+ use per-network randomised
  MACs and send no hostname, so `list_clients` reports `random_mac`, which is a
  hint at device class, not an identification. You cannot single out a specific
  phone or tablet from the router alone. Turning MAC randomisation off for that
  network fixes it: the device starts sending a real hostname and a stable OUI.
- **There is no per-device last-seen timestamp.** `online_time` looks like one and
  is not — 11 of 12 currently-online devices showed an `online_time` older than 30
  days. `last_update_rate` is a global stats-refresh stamp, identical for online
  and offline devices. So "which clients have not connected in months?" has no
  answer from this API, and `clients.remove_offline` is a sledgehammer: it drops
  every currently-offline record at once, names and aliases included.
- No method on 4.7.11 or 4.10.1 lists DHCP leases. `arp_table` is the nearest
  thing.
- Replies carry 60-sample `last_rx`/`last_tx` time series per client, which is why
  `list_clients` projects down to the fields that matter.
- **Concurrent calls used to produce spurious `-32000` "Access denied".** One
  session id is shared, and a re-login invalidated the ids other calls were
  mid-flight with: six parallel calls failed, the same six in series all
  succeeded. Fixed with a lock around request-and-re-login. If you fork this,
  note that MCP clients fire tools concurrently by default.
- **The upgrade check can fail while the UI reports "up to date".**
  `upgrade.check_firmware_online` returned `no resolver defined to resolve
  "fw.gl-inet.com"` while `diag.ping fw.gl-inet.com` from the router resolved and
  answered in 7 ms. The web UI showed that error as "no new firmware" — which is
  how a box sits 16 months behind with nobody told. Test the check, not the UI.
- **There is a second, undocumented admin interface on port 8443.** LuCI, the
  stock OpenWrt UI, with its own webroot, its own session and a backup/restore
  feature the GL.iNet panel on 443 does not expose. Grepping the 443 bundles for
  "backup" finds nothing but Chart.js `ctx.restore()` calls, which is how a whole
  subsystem stayed invisible for a full investigation.
- **rpcd's `file.exec` ACL is an allowlist of entire command lines, not of
  binaries.** `/bin/tar -tzf /tmp/backup.tar.gz` is permitted;
  `/sbin/sysupgrade --help` is denied while
  `/sbin/sysupgrade --restore-backup /tmp/backup.tar.gz` is allowed. Same for
  paths: writing `/tmp/backup.tar.gz` works, `/tmp/probe.txt` is refused. The
  table lives in `/usr/share/rpcd/acl.d/luci-mod-system.json` inside the
  firmware image. Every refusal is the bare integer `6`, which means
  `PermissionError` only if you happen to know LuCI's `fs.js` says so.
- **`wg-client` and `wg_client` are two different live modules.** Not spellings
  of one name: `wg_client.get_max_client` returns data while
  `wg-client.get_max_client` is Method not found, and `wg-client.add_config` is
  live where `wg_client.add_config` is not. `vlan_subnet` and `parental-control`
  in the same API show that the separator is just part of the name. Anything you
  write that treats `-` and `_` as interchangeable will silently merge two
  modules' documentation. Ask the router instead — `verify_modules.py` found 50
  live modules, 15 with no answering getter, and 3 it could not probe, out of 68.
- **An argument error is a successful response.** GL.iNet returns
  `{"err_msg":"parameter missing","err_code":20001011}` over a normal 200 with no
  JSON-RPC error. So "the call did not raise" does not mean "nothing happened" —
  for a write method it can equally mean the write worked. Probe read verbs, or
  diff a config backup afterwards.

## Scripts

Helpers alongside the server, all using the same credentials and none of them
requiring SSH:

| | |
|---|---|
| `build_catalog.py` | generate `api_description.json` from a firmware image |
| `merge_catalog.py` | rebuild without losing what the rebuild cannot know (see above) |
| `extract_handler_docs.py` | recover parameters and doc comments from the firmware's own handler files |
| `luaread.py` | reader for the vendor's non-standard Lua 5.1 bytecode; what the line above is built on |
| `client_sampler.py` | record when each device was actually last seen, and `--report 30` for stale ones |
| `test_client_sampler.py` | offline tests for the sampler; no router needed |
| `backup_config.sh` | same backup as `backup_config`, from a shell; `--verify` checks an existing archive |
| `snapshot_state.py` | record 17 readable config methods to `snapshots/`, and `--diff` against the previous one |
| `verify_modules.py` | ask the router, once per module, whether that module exists — and per method with `--module X --methods` |

`client_sampler.py` exists because the router cannot answer "when was this
device last here". Rebuild the catalog and you will find a field named
`online_time` that appears to answer it. It does not: it is `client.db`'s
`seen` column, which is when the row was created. Verified on a live router by
diffing two backups three hours apart with fifteen devices connected -- `tx`
moved on 14 rows, `seen` on none -- and then by comparing all 66 rows against
the API, where `online_time` equalled `seen` exactly, on every one. There is
no association history either: the log ring holds about five hours, the hostapd
log holds four lines since boot, and this vendor driver exports no station
records to nl80211, so there is no `inactive time` to read.

So last-seen has to be observed, which is what the sampler does: one
`clients.get_list` call on a timer into a SQLite file in
`~/.local/share/glnet-sampler/`. A `systemd --user` timer at 15 minutes suits
it, with `Persistent=true` so a missed slot catches up instead of leaving a
hole. Resolution is the poll interval: a device that connects and leaves between
two samples is invisible, and that is the honest limit of the design, not an
implementation detail to fix later.

`snapshot_state.py` is the one that pays for itself. Run it before probing an
undocumented method, run it again afterwards, and you know within seconds whether
the probe wrote something. It answered a question I could not otherwise answer:
after a session of uploads, ACL probing and a restore rehearsal, the diff against
the earlier baseline was **empty** — nothing had changed.

Two caveats, both measured. `clients.get_list` is not a stable baseline: two
snapshots 24 seconds apart differed because a randomised-MAC client renewed its
address. Treat client-table churn as noise and reservations, firewall, subnets,
DNS and Wi-Fi config as signal. And snapshots contain your SSIDs, hostnames, MACs
and reservations, so they are gitignored — do not commit one or paste one into an
issue.

## Configuration

| Variable | Default | |
|---|---|---|
| `GLNET_HOST` | `192.168.8.1` | router address |
| `GLNET_PORT` | `443` | |
| `GLNET_USER` | `root` | router admin user |
| `GLNET_PASSWORD_FILE` | `/run/secrets/glnet.password` in the container, `~/.config/opencode/glnet.password` otherwise | |
| `GLNET_CATALOG` | `./api_description.json` | generated by `build_catalog.py` |
| `GLNET_LUCI_PORT` | `8443` | LuCI, used only by backup/restore |
| `GLNET_LUCI_PASSWORD_FILE` | same as `GLNET_PASSWORD_FILE` | only if LuCI differs |
| `GLNET_BACKUP_DIR` | `/app/backups` in the container | where archives land; mode 0700 |
| `GLNET_VERIFY_TLS` | `0` | `1` to validate the router certificate |
| `GLNET_TIMEOUT` | `20` | seconds |
| `GLNET_MCP_IMAGE` | `glnet-mcp:1.0.0` | |

## Smoke test

```bash
( printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"p","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"router_status","arguments":{}}}';
  sleep 40 ) | ./glnet-mcp-container.sh
```

The `sleep` is load-bearing. The server exits on stdin EOF, so a tool call that
awaits the router loses the race against a closed pipe without it.

## Known gaps

- `wifi.set_config`, firewall rules beyond port forwards, and the VPN modules are
  `rpc_call`-only.
- Most methods confirmed present have **no parameter documentation** — the UI
  calls them, nothing describes them. About half now have names recovered from
  the firmware's own handlers (see *Where parameters come from*), and the rest
  are `rpc_call` guess-and-check against a live router, which is safe for reads
  and not for writes. The 10 ELF handlers (`wg-client.so`, `ovpn-*.so`,
  `modem.so`, …) are unread: their blobmsg policy tables would name the
  parameters, but that needs real disassembly.
- Mesh/EasyMesh, VLAN configuration, the IoT network and GL.iNet Account are
  unmodelled.
- No tests beyond the smoke test and the checks described above.

## Related

[openwrt-mcp](https://github.com/GlassOnTin/openwrt-mcp) is the other way to put
an agent on a GL.iNet: a resident daemon **on** the router, using root SSH plus
ubus/uci. It is broader — ubus is self-describing, so it does not need a catalog —
and it is better written than this. It is also a root service on your edge device.
This project is the lower-privilege option; if you need something the vendor API
does not expose, reach for that one.

[python-glinet](https://github.com/tomtana/python-glinet) preserved a copy of the
official 4.x method catalog. `build_catalog.py --legacy` can merge it for
parameter documentation if you have it.
