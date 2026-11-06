#!/usr/bin/env bash
# Take a configuration backup from a GL.iNet router running firmware 4.x.
#
# The vendor JSON-RPC API has no backup method -- not on 4.10.1 and not in the
# older published catalog. Backup lives in LuCI, a second web UI on port 8443,
# and the endpoint is /cgi-bin/cgi-backup: a symlink to /usr/libexec/cgi-io,
# which chooses its behaviour from argv[0]. See BACKUP.md for the details and
# the restore side.
#
#   ./backup_config.sh                       # -> backups/backup-<model>-<date>.tar.gz
#   ./backup_config.sh --verify <file>       # check an existing archive
#
# Credentials: read from $GLNET_PASSWORD_FILE (default
# ~/.config/opencode/glnet.password) or prompted, never passed as a command-line
# argument where `ps` could see it. The LuCI session token is treated the same
# way: it is a live credential, so it is piped through stdin rather than argv and
# every file that held it is shredded.
#
# The archive contains every Wi-Fi passphrase and /etc/shadow. This script
# chmods its output to 600 for that reason. Keep it out of synced folders and
# out of bug reports.
set -euo pipefail

HOST="${GLNET_HOST:-192.168.8.1}"
LUCI_PORT="${GLNET_LUCI_PORT:-8443}"
USER_NAME="${GLNET_USER:-root}"
PWFILE="${GLNET_PASSWORD_FILE:-$HOME/.config/opencode/glnet.password}"
BASE="https://$HOST:$LUCI_PORT"
OUTDIR="${GLNET_BACKUP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/backups}"

# Self-signed certificate on the router, so no verification. Pin it instead if
# you have the cert: set GLNET_CA to a PEM file and it is used and enforced.
CURL=(curl --silent --show-error --max-time 120)
if [ -n "${GLNET_CA:-}" ]; then
  CURL+=(--cacert "$GLNET_CA")
else
  CURL+=(--insecure)
fi

verify_only() {
  local f="$1"
  echo "verifying $f"
  file "$f" | grep -q gzip || { echo "  not a gzip archive"; return 1; }
  # List once, then match against the list. Piping tar into `grep -q` is a trap
  # under `set -o pipefail`: grep exits at the first match, tar takes SIGPIPE,
  # and the pipeline reports failure on a successful match -- which reads as
  # "file missing from the backup" for a file that is plainly there.
  # The listing is file *names* only; their contents are never read here.
  local names rc=0 want
  names=$(mktemp) || { echo "  mktemp failed"; return 1; }
  if ! tar -tzf "$f" >"$names"; then
    echo "  tar failed to list the archive"; rm -f "$names"; return 1
  fi
  echo "  $(wc -l <"$names") entries"
  for want in etc/config/wireless etc/config/dhcp etc/config/firewall \
              etc/config/network etc/shadow; do
    if grep -Fqx -- "$want" "$names" || grep -Fqx -- "./$want" "$names"; then
      echo "  ok  $want"
    else
      echo "  MISSING  $want"; rc=1
    fi
  done
  rm -f "$names"
  echo "  sha256 $(sha256sum "$f" | cut -d' ' -f1)"
  stat -c '  perms %a' "$f"
  return $rc
}

if [ "${1:-}" = "--verify" ]; then
  verify_only "${2:?usage: --verify <archive.tar.gz>}"
  exit $?
fi

if [ -f "$PWFILE" ]; then
  password="$(cat "$PWFILE")"
else
  read -rs 'password' && echo
fi

work="$(mktemp -d)"
chmod 700 "$work"
cleanup() {
  # Every intermediate held a credential or a live session token.
  find "$work" -type f -exec shred -u {} + 2>/dev/null || rm -rf "$work"
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

# --- 1. authenticate to LuCI -------------------------------------------------
if [ -z "${GLNET_CA:-}" ]; then
  echo "backup: TLS not verified (self-signed router cert). Set GLNET_CA to pin it." >&2
fi
# Body goes through a 0600 file: the password must not appear in process args.
# Percent-encode both fields: a password containing &, + or = would otherwise be
# silently truncated into separate form fields and fail as a bad password.
urlencode() {
  local s="" out="" i c
  for ((i = 0; i < ${#1}; i++)); do
    c=${1:i:1}
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) printf -v c '%%%02X' "'$c"; out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

printf 'luci_username=%s&luci_password=%s' \
  "$(urlencode "$USER_NAME")" "$(urlencode "$password")" > "$work/form"
chmod 600 "$work/form"
unset password

code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' \
  -c "$work/jar" -X POST --data-binary "@$work/form" \
  -H "Referer: $BASE/cgi-bin/luci/" \
  "$BASE/cgi-bin/luci/")
chmod 600 "$work/jar" 2>/dev/null || true

# curl writes HttpOnly cookies with a '#HttpOnly_' line prefix, so match on the
# field rather than filtering comment lines -- that mistake reads as "no cookie".
# Fields are TAB separated, so take the last field of the line: slicing with
# [^[:space:]]* stops at the first tab and yields the literal name, not the value.
token="$(awk '/sysauth_https/ {print $NF}' "$work/jar" 2>/dev/null | head -1 || true)"
if [ -z "$token" ]; then
  echo "backup: LuCI returned HTTP $code and set no sysauth_https cookie." >&2
  echo "        LuCI on :$LUCI_PORT may have its own password, distinct from the" >&2
  echo "        router admin password used by the JSON-RPC API on :443." >&2
  exit 1
fi

# --- 2. fetch the archive ---------------------------------------------------
# cgi-io wants the session as a POST body field. It cannot come from the cookie:
# the cookie's Path is /cgi-bin/luci/ and this endpoint is /cgi-bin/cgi-backup,
# so no client will send it here. Query-string sessionid is rejected too.
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"
stamp="$(date +%F)"
out="$OUTDIR/backup-${HOST}-$stamp.tar.gz"

http=$({ printf 'sessionid=%s' "$token"; } | "${CURL[@]}" \
  -o "$out" -w '%{http_code}' -X POST \
  --data-binary @- "$BASE/cgi-bin/cgi-backup")

if [ "$http" != "200" ] || ! file "$out" | grep -q gzip; then
  echo "backup: HTTP $http, response was not an archive:" >&2
  head -c 200 "$out" 2>/dev/null; echo >&2
  rm -f "$out"
  exit 1
fi
chmod 600 "$out"

echo "wrote $out"
verify_only "$out"
