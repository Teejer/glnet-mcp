#!/usr/bin/env bash
# Seal the router password to this machine's TPM2, so a stolen disk or an
# off-site backup does not yield it.
#
# REQUIRES TPM access for your user. Check with:
#   systemd-analyze has-tpm2
#   ls -l /dev/tpmrm0        # needs group `tss` (or an ACL) readable by you
# If /dev/tpmrm0 is root:tss and `id -nG` lacks tss:
#   sudo usermod -aG tss $USER      # then log out and back in
#
# What this does and does not protect:
#   protects  offline theft -- disk image, backup, lost SSD
#   does not  protect against a process already running as you, which can
#             simply run the launcher and get the plaintext like anyone else
#
# Sealing is bound to the TPM on THIS machine. Moving the .enc file to another
# host, or reflashing firmware with different PCRs, makes it undecryptable.
# Keep the plaintext until you have confirmed the round-trip works.
set -euo pipefail

STORE="${GLNET_SECRET_STORE:-$HOME/.local/share/glnet}"
ENC="$STORE/glnet.password.enc"
PLAIN="${GLNET_PASSWORD_FILE:-$HOME/.config/opencode/glnet.password}"

if [ -e "$ENC" ]; then
  echo "refusing to overwrite existing $ENC -- move it aside first" >&2
  exit 1
fi

if [ ! -c /dev/tpmrm0 ]; then
  echo "no /dev/tpmrm0 -- this machine has no usable TPM resource manager" >&2
  exit 1
fi
if ! systemd-analyze has-tpm2 >/dev/null 2>&1; then
  echo "systemd reports no usable TPM2" >&2
  exit 1
fi

# This is the check that was missing the first time, and it cost the only copy
# of a password. `systemd-analyze has-tpm2` proves the hardware exists; it does
# NOT prove systemd has a persistent Storage Root Key. Without the SRK written
# by systemd-tpm2-setup.service, a seal opens only against transient runtime
# state and becomes permanently undecryptable once that goes away -- while a
# round-trip test run moments later still passes. Check for the key itself.
SRK=/var/lib/systemd/tpm2/srk.pub
if [ ! -f "$SRK" ]; then
  echo "refusing to seal: no persistent TPM SRK at $SRK" >&2
  echo "  systemd-tpm2-setup.service status:" >&2
  systemctl status systemd-tpm2-setup.service --no-pager 2>&1 | sed -n '2,5p' | sed 's/^/    /' >&2
  echo "  A seal made here opens only until the runtime state holding the key" >&2
  echo "  goes away. Use the plaintext file (chmod 600) instead, or enable" >&2
  echo "  measured boot so systemd-tpm2-setup's ConditionSecurity=measured-os is met." >&2
  exit 1
fi
echo "persistent SRK present: $SRK"

if [ -f "$PLAIN" ]; then
  secret="$(cat "$PLAIN")"
  echo "reading secret from $PLAIN"
else
  read -rs 'secret' && printf '\n'
fi

mkdir -p "$STORE"
chmod 700 "$STORE"

# --with-key=tpm2 only: no host-key fallback, since the host key is a file on
# the same disk and would defeat the point of sealing.
printf '%s' "$secret" | systemd-creds encrypt --name=glnet.password --with-key=tpm2 - "$ENC"
chmod 600 "$ENC"
echo "sealed -> $ENC ($(stat -c %s "$ENC") bytes)"

# Prove it decrypts before saying anything good. But understand what this
# proves: only that it opens in the CURRENT runtime. A seal can survive this
# and still be dead after a reboot. So do not delete the plaintext here.
round="$(systemd-creds decrypt --name=glnet.password --tpm2-device=auto "$ENC")"
if [ "$round" != "$secret" ]; then
  echo "round-trip FAILED -- leaving $PLAIN in place" >&2
  exit 1
fi
echo "same-session round-trip OK (this is necessary, not sufficient)"

if [ "${1:-}" = "--delete-plaintext" ]; then
  if command -v shred >/dev/null; then shred -u "$PLAIN"; else rm -f "$PLAIN"; fi
  echo "removed plaintext $PLAIN"
else
  cat <<NOTE

Keeping $PLAIN. Before deleting it:

  1. reboot
  2. systemd-creds decrypt --name=glnet.password --tpm2-device=auto "$ENC"
  3. only if that still prints your password, delete the plaintext:
       ./seal-password.sh --delete-plaintext

A same-session round-trip is not evidence of durability. That distinction is
worth a reboot.
NOTE
fi
