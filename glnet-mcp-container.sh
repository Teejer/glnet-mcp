#!/usr/bin/env bash
# Hardened stdio launcher for the glnet MCP container.
# This is the command OpenCode spawns (see ~/.config/opencode/opencode.json).
#
# Sandbox mirrors the gmail/yahoo launchers: read-only rootfs, all capabilities
# dropped, no new privileges, no TTY, pid/memory limits. The only thing that
# leaves the container is HTTPS to the router on the LAN.
#
# Secret handling -- the part that differs from the other launchers:
# the password is NEVER passed as an env var, because env is readable through
# `docker inspect`. Instead it is staged onto tmpfs ($XDG_RUNTIME_DIR, mode
# 700 dir + 600 file, never hits disk) and bind-mounted read-only into the
# container at /run/secrets/glnet.password, then removed when we exit.
#
# Two secret sources, tried in this order:
#   1. TPM2-sealed blob  ~/.local/share/glnet/glnet.password.enc
#      Requires TPM access for your user (group `tss`). See seal-password.sh.
#   2. plaintext file    ~/.config/opencode/glnet.password  (mode 600)
#
# Keep comments OUT of the docker run block: a '#' line inside a backslash
# continuation truncates the command.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${GLNET_MCP_IMAGE:-glnet-mcp:1.0.0}"
SEALED="${GLNET_PASSWORD_ENC:-$HOME/.local/share/glnet/glnet.password.enc}"
PLAIN="${GLNET_PASSWORD_FILE:-$HOME/.config/opencode/glnet.password}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "glnet-mcp: image $IMAGE not found. Build it:" >&2
  echo "  docker build -t $IMAGE $DIR" >&2
  exit 1
fi

if [ ! -f "$SEALED" ] && [ ! -f "$PLAIN" ]; then
  echo "glnet-mcp: no router password found." >&2
  echo "  either: $PLAIN  (chmod 600)" >&2
  echo "  or:     $SEALED (see seal-password.sh)" >&2
  exit 1
fi

# --- stage the secret on tmpfs ---------------------------------------------
RUNTIME="${XDG_RUNTIME_DIR:-/tmp}"
if [ ! -d "$RUNTIME" ]; then
  echo "glnet-mcp: XDG_RUNTIME_DIR ($RUNTIME) does not exist" >&2
  exit 1
fi
STAGE_DIR="$(mktemp -d "$RUNTIME/glnet-mcp.XXXXXX")"
chmod 700 "$STAGE_DIR"
STAGED="$STAGE_DIR/glnet.password"

cleanup() {
  # Remove the plaintext before anything else can read it. Not a shred: the
  # backing store is tmpfs, so there is no on-disk copy to overwrite.
  rm -f "$STAGED" 2>/dev/null || true
  rmdir "$STAGE_DIR" 2>/dev/null || true
}

on_signal() { cleanup; trap - INT TERM; exit 143; }
trap cleanup EXIT
trap on_signal INT TERM

# Sweep staging dirs left behind by a SIGKILLed launcher. The secret inside is
# only readable by you and the dir is wiped at logout anyway, but a pile of
# them is untidy and one may still hold a password.
#
# Age alone is not proof of death. A long-lived OpenCode session holds its
# container for hours, and the server reads the password lazily at every login,
# so deleting that container's staging dir does not free a orphaned secret -- it
# breaks the live server the next time its session expires. Anything still
# bind-mounted by a running container is therefore off limits regardless of age.
in_use="$(docker ps -q --filter name=glnet-mcp- 2>/dev/null \
  | xargs -r docker inspect -f '{{range .Mounts}}{{.Source}}
{{end}}' 2>/dev/null)"
while IFS= read -r dir; do
  [ -d "$dir" ] || continue
  case "$in_use" in
    *"$dir/"*) continue ;;   # a live container is reading this file
  esac
  # Only sweep what is genuinely old and unreferenced.
  [ "$(find "$dir" -maxdepth 0 -mmin +60 2>/dev/null)" ] || continue
  rm -rf "$dir"
done < <(find "$RUNTIME" -maxdepth 1 -name 'glnet-mcp.*' -type d 2>/dev/null)

# Reap orphaned containers from earlier launches. The container name carries
# the launcher's PID, so liveness is checkable without guessing: /proc/<pid>
# works for processes we do not own, where `kill -0` would also report EPERM.
# Without this, a launcher killed by SIGKILL orphaned its container -- and that
# container holds a bind-mounted plaintext password -- indefinitely.
for name in $(docker ps --filter name=glnet-mcp- --format '{{.Names}}' 2>/dev/null); do
  pid="${name##*-}"
  if [[ "$pid" =~ ^[0-9]+$ ]] && [ ! -d "/proc/$pid" ]; then
    echo "glnet-mcp: reaping orphaned container $name (launcher $pid is gone)" >&2
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
done

# Unseal, borrowing the `tss` group if this process does not have it.
#
# Group membership is fixed at login and inherited by children. OpenCode runs
# under user@1002.service, whose group set comes from your original login, so
# every launcher it spawns will lack `tss` until you log all the way out and
# the user manager restarts. newgrp is setuid-root and succeeds for a group you
# already belong to, which lets the launcher unseal anyway -- so sealing works
# today instead of waiting on a logout that would also kill this session.
unseal() {
  systemd-creds decrypt --name=glnet.password --tpm2-device=auto "$SEALED" "$STAGED" 2>>"$UNSEAL_ERR" && return 0
  [ -x /usr/bin/newgrp ] || return 1
  newgrp tss <<EOF 2>>"$UNSEAL_ERR"
systemd-creds decrypt --name=glnet.password --tpm2-device=auto "$SEALED" "$STAGED"
EOF
}

if [ -f "$SEALED" ]; then
  UNSEAL_ERR="$(mktemp)"
  if ! unseal; then
    echo "glnet-mcp: unseal failed: $(head -1 "$UNSEAL_ERR" 2>/dev/null)" >&2
    echo "glnet-mcp: TPM2 sealing needs TPM access for your user. Fix: sudo usermod -aG tss \$USER, then log out and back in." >&2
    echo "glnet-mcp: falling back to $PLAIN" >&2
    rm -f "$UNSEAL_ERR"
    [ -f "$PLAIN" ] || {
      echo "glnet-mcp: FATAL - the sealed blob will not open and there is no plaintext fallback," >&2
      echo "           so the router password is unavailable. Restore it with:" >&2
      echo "             umask 077 && read -rs pw && printf '%s' \"\$pw\" > $PLAIN && echo" >&2
      echo "           Then remove the unusable blob: rm $SEALED" >&2
      exit 1
    }
    install -m 600 "$PLAIN" "$STAGED"
  else
    rm -f "$UNSEAL_ERR"
    chmod 600 "$STAGED"
  fi
else
  echo "glnet-mcp: using plaintext secret $PLAIN" >&2
  install -m 600 "$PLAIN" "$STAGED"
fi

# --- run -------------------------------------------------------------------
# The method catalog is generated from YOUR firmware by build_catalog.py and is
# deliberately not baked into the image -- a catalog from one version is wrong
# for another, and an image carrying no version-specific data can be shared.
# If one exists next to this script it is mounted read-only; without it every
# curated tool still works and only api_search is blind.
CATALOG="${GLNET_CATALOG_HOST:-$DIR/api_description.json}"
if [ -f "$CATALOG" ]; then
  CATALOG_MOUNT="--mount=type=bind,src=$CATALOG,dst=/app/api_description.json,readonly"
else
  CATALOG_MOUNT=""
  echo "glnet-mcp: no catalog at $CATALOG -- api_search will be empty." >&2
  echo "glnet-mcp: build one:  ./build_catalog.py <firmware.bin>" >&2
fi

# Backups land on the host, not in the container: the rootfs is read-only and an
# archive that vanishes with the container is worthless. Mode 700 because the
# contents are every Wi-Fi passphrase plus the router's root password hash.
BACKUP_HOST_DIR="${GLNET_BACKUP_HOST_DIR:-$DIR/backups}"
mkdir -p "$BACKUP_HOST_DIR" && chmod 700 "$BACKUP_HOST_DIR"

# Watchdog. docker has no "exit when the client dies" flag, and this launcher
# cannot background `docker run` in order to wait on it -- a backgrounded
# command in a non-interactive shell gets stdin from /dev/null, which is the
# MCP channel. So a detached subshell watches for this launcher to vanish and
# tears the container down behind it. A SIGKILL to the launcher reparents this
# subshell instead of killing it, so it still fires; file descriptors are
# dropped so it never keeps the stdio channel open after we exit.
# `$$` inside a subshell is the MAIN shell's pid ($BASHPID is the subshell's).
(
  trap '' TERM INT HUP
  while [ -d "/proc/$$" ]; do sleep 2; done
  docker rm -f "glnet-mcp-$$" >/dev/null 2>&1 || true
  rm -f "$STAGED" 2>/dev/null || true
  rmdir "$STAGE_DIR" 2>/dev/null || true
) >/dev/null 2>&1 &
WATCHDOG_PID=$!

# Run in the FOREGROUND, not backgrounded-then-waited. A backgrounded command
# in a non-interactive shell gets its stdin redirected to /dev/null, which
# would hand the container an immediate EOF and break the MCP stdio channel
# entirely. The cost is that a SIGKILL to this script skips the trap, which is
# what the watchdog and the sweeps above are for.
docker run -i --rm \
  --name "glnet-mcp-$$" \
  --hostname glnet-mcp \
  --init \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --memory 512m \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --env GLNET_HOST="${GLNET_HOST:-192.168.8.1}" \
  --env GLNET_USER="${GLNET_USER:-root}" \
  --env GLNET_PASSWORD_FILE=/run/secrets/glnet.password \
  --env GLNET_BACKUP_DIR=/app/backups \
  --mount "type=bind,src=$BACKUP_HOST_DIR,dst=/app/backups" \
  --mount "type=bind,src=$STAGED,dst=/run/secrets/glnet.password,readonly" \
  ${CATALOG_MOUNT:+"$CATALOG_MOUNT"} \
  "$IMAGE" "$@"
rc=$?
kill "$WATCHDOG_PID" 2>/dev/null || true
trap - INT TERM
cleanup
trap - EXIT
exit "$rc"
