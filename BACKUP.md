# Config backup and restore

**The vendor JSON-RPC API has no backup method.** Not on 4.10.1, and not in the
older published 4.x catalog. There is no `system.backup`, no `upgrade.backup`,
nothing — `rpc_call` cannot do this, and no number of catalog rebuilds will find
a method that does not exist.

Backup lives somewhere else entirely: **a second web interface, LuCI, on a
different port.**

## Where it is

| | |
|---|---|
| Interface | LuCI (OpenWrt's own UI), separate from GL.iNet's `gl-ui` |
| URL | `https://<router>:8443/cgi-bin/luci/admin/system/flash` |
| Port | **8443** — not 443. Reachable on the LAN. |
| Mechanism | `/cgi-bin/cgi-backup`, a symlink to `/usr/libexec/cgi-io` |
| How it dispatches | `cgi-io` picks its behaviour from `argv[0]`: `cgi-backup`, `cgi-upload`, `cgi-download`, `cgi-exec` |
| Auth | an authenticated LuCI session cookie; unauthenticated POST returns `Backup permission denied` |
| RPC bridge | `/cgi-bin/luci/admin/ubus` — rpcd JSON-RPC, same `[sid, object, method, args]` shape as the vendor API |

The two UIs are genuinely separate — different webroot, different session,
different port. If you have only ever looked at the GL.iNet panel on 443 you will
not find this, and grepping the 443 bundles for "backup" turns up nothing but
Chart.js `ctx.restore()` calls. That mistake cost a full investigation; it is
written here so it does not repeat.

## Doing it

**Through this MCP** — `backup_config` does the whole sequence and saves the
archive. It returns metadata only: path, size, sha256, entry count, which
critical files are inside. Never the bytes.

**In the browser**: the URL above, System → Backup and Restore, download.

**Scripted**, which is what the tool does internally:

```bash
BASE=https://<router>:8443
# 1. log in to LuCI. Field names are luci_username / luci_password.
#    The response is a 302 whose Set-Cookie carries the session.
curl -sk -c jar -X POST -o /dev/null \
  --data-urlencode "luci_username=root" --data-urlencode "luci_password=<pw>" \
  "$BASE/cgi-bin/luci/"

# 2. fetch the archive. The session goes as a POST body field named sessionid.
tok=$(grep -o 'sysauth_https[^[:space:]]*' jar | awk '{print $NF}')
curl -sk -X POST --data "sessionid=$tok" -o backup.tar.gz \
  "$BASE/cgi-bin/cgi-backup"
```

Two traps in that sequence, both of which cost a wrong conclusion before they
were found:

- **The cookie cannot authorise the download.** Its `Path` is `/cgi-bin/luci/`
  and the endpoint is `/cgi-bin/cgi-backup`, so no correct client will send it
  there — passing the session as a `sessionid` body field is the only thing that
  works. A query-string `?sessionid=` is rejected; sending the cookie directly
  is rejected.
- **curl writes HttpOnly cookies as lines beginning `#HttpOnly_`.** Filtering
  comment lines when inspecting a cookie jar makes a successful login look like
  it set no cookie at all.

`cgi-io` also serves `cgi-upload`, `cgi-download` and `cgi-exec` by the same
argv[0] mechanism. `cgi-upload` is what a restore uses; see *Restoring*.

**Verified**: the archive this produces is byte-identical to the one the browser
downloads — same 463,436 bytes, same sha256.

**A sha256 verifies a transfer, not a configuration.** Two backups taken seconds
apart are byte-identical, so the archive is deterministic for unchanged state and
the hash is a sound check that an upload or copy survived intact. But two backups
taken minutes apart differ with *no* configuration change. The archive embeds
`etc/oui-tertf/client.db`, GL.iNet's client-history database, which churns
constantly on its own. Isolated by diffing two archives on filenames only:

```
Files a/etc/oui-tertf/client.db and b/etc/oui-tertf/client.db differ
```

So "the hashes differ" does not mean the config changed, and never will. To
answer that question, compare the *readable* state — see *Cheaper habit* below.

**Over SSH**, if dropbear is enabled:

```bash
ssh root@<router> 'sysupgrade -b /tmp/router.tgz'
scp root@<router>:/tmp/router.tgz ./backup-$(hostname)-$(date +%F).tar.gz
```

**The LuCI password is the router admin password** on this firmware: the same
`root` credential the JSON-RPC API accepts on 443 logs in on 8443. If login ever
returns no `sysauth_https` cookie the credential is worth suspecting, but it is
not the likely cause — `GLNET_LUCI_PASSWORD_FILE` and `GLNET_LUCI_PASSWORD` exist
only for devices configured the other way.

## What the archive contains, and why that matters

On a BE9300 / 4.10.1 the archive is ~460 KB compressed, 176 entries: the whole of
`etc/config` plus `etc/shadow`, AdGuard config, installed-package list and more.

Which means it contains, in recoverable form:

- **every Wi-Fi passphrase** (`etc/config/wireless`, `option key`)
- **the root password hash** (`etc/shadow`)
- your DHCP reservations, firewall rules, port forwards, DDNS, VPN configs

Roughly 30 lines in a typical archive match credential patterns.

So:

```bash
chmod 600 backup-*.tar.gz          # it arrives world-readable (644) from a browser
```

Do not commit one. Do not attach one to a bug report, a forum post, or a chat
transcript. If a directory of these lives in a synced folder, the sync is now
carrying your wireless keys and your root hash.

Verify what you have before trusting it:

```bash
file backup.tar.gz                                   # gzip compressed data
tar tzf backup.tar.gz | grep -E 'etc/config/(wireless|dhcp|firewall|network)'
tar tzf backup.tar.gz | grep -qx etc/shadow && echo "root hash present"
sha256sum backup.tar.gz                             # record it; archives differ run to run
```

## Restoring

**`restore_config` exists, and it will reboot your network.** Read this whole
section before calling it once.

A restore replaces the running configuration and reboots the router. Every
connection behind it drops for several minutes. With the wrong archive, or one
saved from a very different firmware, it can leave the box unreachable — and
recovering from *that* means physical access and a failsafe TFTP flash. The
destructive leg of this tool cannot be tested without causing exactly that
outage, so treat "it works" as unproven until you have run it during a window you
scheduled.

The tool is deliberately hard to fire by accident:

- **`sha256` is a required argument.** It is checked against the local file, then
  against the checksum the router computes on receipt, before anything runs. A
  caller cannot restore an archive it has not first inspected, which rules out
  the realistic model failure of guessing a plausible filename.
- **`confirm=True` is required**, and without it the call performs a full
  *rehearsal*: upload, remote validation, delete. That is a real dry run, not a
  promise, and it is the most that is verifiable without an outage.
- **A safety backup of the running config is taken first**, automatically, and its
  path is returned.
- **Nothing is parameterised.** The staging path is always `/tmp/backup.tar.gz`
  and the command is always `/sbin/sysupgrade --restore-backup /tmp/backup.tar.gz`.

### Why those two exact strings

The router's rpcd ACL is an **exact argv allowlist**, not a command allowlist. It
comes from `/usr/share/rpcd/acl.d/luci-mod-system.json`, shipped in the
`luci-mod-system` package inside the firmware image, and every entry below was
confirmed against the live box:

| call | result |
|---|---|
| `exec /bin/tar -tzf /tmp/backup.tar.gz` | allowed |
| `exec /sbin/sysupgrade --restore-backup /tmp/backup.tar.gz` | allowed |
| `exec /sbin/sysupgrade --help` | **denied** — argv not on the list |
| `upload → /tmp/backup.tar.gz` | allowed |
| `upload → /tmp/glnet-probe.txt` | **denied** — path not on the list |
| `read /proc/sys/kernel/hostname` | allowed |
| `read /proc/uptime` | **denied** |

That table explains a misleading hour of debugging: `file.exec` looked
unavailable, then worked, then failed again for a different argument. It is not a
permission on a binary, it is a permission on a *whole command line*. `rpcd`
answers all of these refusals with the bare integer `6`; LuCI's own
`fs.js` maps it to `PermissionError`, which is the only place that meaning is
recorded.

The same ACL also grants `/sbin/firstboot -r -y` (factory reset) and
`/sbin/reboot`, and every `sysupgrade` firmware-flash variant. This tool names two
of those strings and no others; there is no argument anywhere that accepts a
command, because `file.exec` with a caller-supplied command is a root shell on
your edge device with an MCP schema wrapped around it.

### The mechanism, if you want to do it by hand

```bash
BASE=https://<router>:8443
curl -sk -c jar -X POST -o /dev/null --data-urlencode "luci_username=root" \
  --data-urlencode "luci_password=<pw>" "$BASE/cgi-bin/luci/"
tok=$(awk '/sysauth_https/ {print $NF}' jar)

# stage the archive (only /tmp/backup.tar.gz and /tmp/firmware.bin are writable)
curl -sk -X POST -F "sessionid=$tok" -F "filename=/tmp/backup.tar.gz" \
  -F "filedata=@backup.tar.gz" "$BASE/cgi-bin/cgi-upload"
# -> {"size":463436,"checksum":"...","sha256sum":"..."}   check that hash

# validate, then restore. The restore reboots and never answers.
curl -sk -X POST -H 'Content-Type: application/json' -b jar \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$tok\",\"file\",\"exec\",
       {\"command\":\"/sbin/sysupgrade\",\"params\":[\"--restore-backup\",\"/tmp/backup.tar.gz\"]}]}" \
  "$BASE/cgi-bin/luci/admin/ubus"
```

Note the two different auth styles: `cgi-*` endpoints take the session as a
**body field** because the cookie's `Path` cannot reach them, while
`/cgi-bin/luci/admin/ubus` **is** under that path and takes the cookie. Getting
this backwards produces a `403` or a `6`, never a useful message.

A restore from a different firmware version is a supported-looking operation with
untested behaviour across a big jump; if you must, restore config saved from the
same major version. Expect the interface to estimate about 30 minutes.

`sysupgrade -r <file>` over SSH is the equivalent command-line restore.

## Cheaper habit: snapshot and diff

A backup protects against writes you knowingly make. It does not answer "did that
probe change anything?" — for that, `snapshot_state.py` records the readable
configuration state through the API, twice, and diffs it. Read-only, takes
seconds, no credentials beyond what the MCP already has.

One caveat measured here: `clients.get_list` is **not** a stable baseline. Two
snapshots 24 seconds apart differed because a randomised-MAC client renewed from
`.186` to `.187`. Treat client-table churn as noise; treat reservations, firewall
rules, subnets, DNS and Wi-Fi configuration as the signal.
