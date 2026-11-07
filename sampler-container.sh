#!/usr/bin/env bash
#
# Run the client sampler as a self-scheduling container.
#
# Why a container with its own loop instead of a systemd timer: the box this is
# meant for runs docker but gives the deploying user neither root nor lingering,
# so there is no timer that survives a reboot. Docker's restart policy is the
# one scheduler available without privilege. On a machine where you do have
# those, prefer the units in docs/systemd/ and run client_sampler.py once per
# tick instead.
#
#   ./sampler-container.sh              # start (15 min interval)
#   INTERVAL=600 ./sampler-container.sh # start at 10 min
#   docker logs -f glnet-sampler        # watch it work
#   docker exec glnet-sampler python /app/client_sampler.py --report 30
#   NAME=glnet-sampler ./sampler-container.sh stop
set -euo pipefail

IMAGE=${IMAGE:-glnet-mcp:1.0.0}
NAME=${NAME:-glnet-sampler}
DATA=${DATA:-$HOME/.local/share/glnet-sampler}
PW=${GLNET_PASSWORD_FILE:-$HOME/.config/opencode/glnet.password}
INTERVAL=${INTERVAL:-900}

if [ "${1:-start}" = "stop" ]; then
  docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped $NAME" || echo "not running"
  exit 0
fi

[ -d "$DATA" ] || { echo "no sampler directory at $DATA; create it first so the" \
                      "router password and database land somewhere you expect"; exit 1; }
[ -r "$PW" ] || { echo "cannot read the router password at $PW"; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "no $IMAGE; build it with docker build -t $IMAGE ."; exit 1; }

# Container-local timestamps, or `docker logs` reports in UTC and every entry
# reads six hours off. The stored values are epoch seconds either way.
TZ_NAME=${TZ:-$(readlink -f /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')}
TZ_NAME=${TZ_NAME:-UTC}

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --restart=unless-stopped \
  --user "$(id -u):$(id -g)" \
  --env "TZ=$TZ_NAME" \
  --env GLNET_SAMPLER_DB=/data/clients.sqlite3 \
  --mount "type=bind,src=$PW,dst=/run/secrets/glnet.password,readonly" \
  --mount "type=bind,src=$DATA,dst=/data" \
  --log-opt max-size=2m --log-opt max-file=2 \
  --cap-drop ALL --network host \
  --read-only --tmpfs /tmp:rw,size=16m \
  --entrypoint python "$IMAGE" /app/client_sampler.py --loop "$INTERVAL" >/dev/null

echo "started $NAME: sampling every ${INTERVAL}s into $DATA/clients.sqlite3 (tz $TZ_NAME)"
echo "verify with: docker logs --tail 3 $NAME"
