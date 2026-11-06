#!/usr/bin/env bash
# Launcher for the glnet MCP server. Registered in ~/.config/opencode/opencode.json.
#
# Not containerised, unlike the gmail/yahoo servers in this directory: the
# router is on the LAN with a self-signed cert, so a container buys nothing
# here beyond a second network stack to debug.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "$DIR/.venv/bin/python" ]]; then
  echo "glnet-mcp: no venv. Run:" >&2
  echo "  cd $DIR && uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt" >&2
  exit 1
fi

exec "$DIR/.venv/bin/python" "$DIR/server.py" "$@"
