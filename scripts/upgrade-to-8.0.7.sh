#!/usr/bin/env bash
# Upgrade a Suricata 7.x Lua/syslog sensor to the 8.0.7 EVE + Vector sensor.
#
# The 7.x container (named "suricata") is stopped and renamed, not removed, so
# `--rollback` can bring it back. The 8.0.7 stack is a separate compose project
# ("suricata-v8") in --install-dir. If the new stack does not come up healthy the
# script rolls back on its own.
#
# Ship this script together with configs/vector.yaml (next to the script, or in
# ../configs/ as in the repository).
#
#   sudo ./upgrade-to-8.0.7.sh --kafka-server k1:9092,k2:9092 --sensor-id s-01 \
#        --project-id p-01 [--home-net 10.1.2.3/32] [--dry-run]
#   sudo ./upgrade-to-8.0.7.sh --rollback      # back to the 7.x container
#   sudo ./upgrade-to-8.0.7.sh --finalize      # remove the 7.x container
set -euo pipefail

IMAGE="public.ecr.aws/zuin/cybereyes/suricata:8.0.7"
VECTOR_IMAGE="timberio/vector:0.49.0-debian"
INSTALL_DIR="/opt/suricata-v8"
PROJECT="suricata-v8"
OLD_NAME="suricata"
BACKUP_NAME="suricata-v7-backup"
RULESET_VERSION="rules-v2"
SURICATA_MEM="4g"
VECTOR_MEM="1g"
HEALTH_TIMEOUT=180

KAFKA_SERVER="" SENSOR_ID="" SENSOR_IP="" PROJECT_ID="" HOME_NET="" INTERFACES=""
VECTOR_CONFIG="" IMAGE_ARCHIVE="" MODE="upgrade"
DRY_RUN=0 ASSUME_YES=0 SKIP_KAFKA_CHECK=0 NO_AUTO_ROLLBACK=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: $0 [options]

Required for an upgrade:
  --kafka-server LIST     Kafka bootstrap servers, host:port[,host:port...]
  --sensor-id ID          sensor identity (raw_sensor_id)
  --project-id ID         project identity for body signals

Optional:
  --sensor-ip IP          sensor address (default: IPv4 of the first interface)
  --interface IF          capture interface, repeatable (default: taken from the 7.x container)
  --home-net CIDRS        servers the sensor protects, e.g. "[10.1.2.0/24,10.1.3.4]"
                          (default: all private ranges; ET rules then miss private-to-private traffic)
  --image REF             Suricata image (default: $IMAGE)
  --vector-image REF      Vector image (default: $VECTOR_IMAGE)
  --image-archive FILE    docker save archive with both images, for hosts without registry access
  --vector-config FILE    vector.yaml (default: next to this script, or ../configs/vector.yaml)
  --install-dir DIR       where the 8.0 compose file goes (default: $INSTALL_DIR)
  --ruleset-version V     RULESET_VERSION for Vector (default: $RULESET_VERSION)
  --suricata-mem SIZE     Suricata memory limit (default: $SURICATA_MEM)
  --skip-kafka-check      do not require a TCP connection to Kafka before switching
  --no-auto-rollback      leave a failed 8.0 stack running for inspection
  --dry-run               run the checks and print the compose file, change nothing
  -y, --yes               do not ask for confirmation

Other modes:
  --rollback              stop the 8.0 stack and restart the 7.x container
  --finalize              remove the stopped 7.x container after the upgrade is accepted
EOF
}

log()  { printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "$2"; }
info() { log INFO "$*"; }
warn() { log WARN "$*" >&2; }
die()  { log ERROR "$*" >&2; exit 1; }

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    info "(dry-run) $*"
  else
    "$@"
  fi
}

confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  printf '%s [y/N] ' "$1"
  read -r answer
  case "$answer" in y|Y|yes|YES) return 0 ;; *) die "aborted" ;; esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --kafka-server)      KAFKA_SERVER="$2"; shift 2 ;;
    --sensor-id)         SENSOR_ID="$2"; shift 2 ;;
    --sensor-ip)         SENSOR_IP="$2"; shift 2 ;;
    --project-id)        PROJECT_ID="$2"; shift 2 ;;
    --interface)         INTERFACES="$INTERFACES $2"; shift 2 ;;
    --home-net)          HOME_NET="$2"; shift 2 ;;
    --image)             IMAGE="$2"; shift 2 ;;
    --vector-image)      VECTOR_IMAGE="$2"; shift 2 ;;
    --image-archive)     IMAGE_ARCHIVE="$2"; shift 2 ;;
    --vector-config)     VECTOR_CONFIG="$2"; shift 2 ;;
    --install-dir)       INSTALL_DIR="$2"; shift 2 ;;
    --ruleset-version)   RULESET_VERSION="$2"; shift 2 ;;
    --suricata-mem)      SURICATA_MEM="$2"; shift 2 ;;
    --skip-kafka-check)  SKIP_KAFKA_CHECK=1; shift ;;
    --no-auto-rollback)  NO_AUTO_ROLLBACK=1; shift ;;
    --dry-run)           DRY_RUN=1; shift ;;
    -y|--yes)            ASSUME_YES=1; shift ;;
    --rollback)          MODE="rollback"; shift ;;
    --finalize)          MODE="finalize"; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)                   usage >&2; die "unknown option: $1" ;;
  esac
done

COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

container_exists() { docker container inspect "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- rollback ---

rollback() {
  container_exists "$BACKUP_NAME" || die "no $BACKUP_NAME container: nothing to roll back to"
  info "stopping the 8.0 stack"
  if [ -f "$COMPOSE_FILE" ]; then
    # keep the volumes: unshipped EVE files and Vector checkpoints survive a second attempt
    run compose down --remove-orphans || warn "compose down failed"
  fi
  if container_exists "$OLD_NAME"; then
    run docker rm -f "$OLD_NAME"
  fi
  info "restoring the 7.x container"
  run docker rename "$BACKUP_NAME" "$OLD_NAME"
  local policy="unless-stopped"
  [ -f "$INSTALL_DIR/backup/restart-policy" ] && policy="$(cat "$INSTALL_DIR/backup/restart-policy")"
  run docker update --restart="$policy" "$OLD_NAME" >/dev/null
  run docker start "$OLD_NAME" >/dev/null
  info "rolled back: $(docker inspect -f '{{.Config.Image}} {{.State.Status}}' "$OLD_NAME" 2>/dev/null || echo "$OLD_NAME")"
}

if [ "$MODE" = "rollback" ]; then
  confirm "Stop the 8.0 stack and restart the 7.x container?"
  rollback
  exit 0
fi

if [ "$MODE" = "finalize" ]; then
  container_exists "$BACKUP_NAME" || die "no $BACKUP_NAME container"
  confirm "Remove $BACKUP_NAME? After this --rollback is no longer possible."
  run docker rm "$BACKUP_NAME"
  info "removed $BACKUP_NAME"
  exit 0
fi

# --------------------------------------------------------------- preflight ---

[ -n "$KAFKA_SERVER" ] || { usage >&2; die "--kafka-server is required"; }
[ -n "$SENSOR_ID" ]    || { usage >&2; die "--sensor-id is required"; }
[ -n "$PROJECT_ID" ]   || { usage >&2; die "--project-id is required"; }

command -v docker >/dev/null || die "docker not found"
docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon (run as root or a docker group member)"
docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin not found"

if [ -z "$VECTOR_CONFIG" ]; then
  for candidate in "$SCRIPT_DIR/vector.yaml" "$SCRIPT_DIR/../configs/vector.yaml"; do
    if [ -f "$candidate" ]; then VECTOR_CONFIG="$candidate"; break; fi
  done
fi
[ -n "$VECTOR_CONFIG" ] && [ -f "$VECTOR_CONFIG" ] || die "vector.yaml not found; pass --vector-config"

container_exists "$BACKUP_NAME" && die "$BACKUP_NAME already exists: a previous upgrade was not finalized (use --rollback or --finalize)"

OLD_IMAGE=""
if container_exists "$OLD_NAME"; then
  OLD_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$OLD_NAME")"
  if [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$OLD_NAME")" = "$PROJECT" ]; then
    die "$OLD_NAME already belongs to the $PROJECT stack: this sensor looks upgraded"
  fi
  info "found 7.x container $OLD_NAME ($OLD_IMAGE)"
  if [ -z "$INTERFACES" ]; then
    # 7.x commands look like ["-i eth0"] or ["-i eth0 -i eth1"]: one string or separate args
    INTERFACES="$(docker inspect -f '{{range .Config.Cmd}}{{.}} {{end}}' "$OLD_NAME" \
      | grep -oE -- '-i[[:space:]]*[^[:space:]]+' | sed -E 's/^-i[[:space:]]*//' | tr '\n' ' ')"
  fi
else
  warn "no container named $OLD_NAME: fresh install, nothing to roll back to"
fi

INTERFACES="$(echo "$INTERFACES" | xargs)"
[ -n "$INTERFACES" ] || die "could not determine the capture interface; pass --interface"
for iface in $INTERFACES; do
  if command -v ip >/dev/null && ! ip link show "$iface" >/dev/null 2>&1; then
    die "interface $iface does not exist on this host"
  fi
done
info "capture interfaces: $INTERFACES"

if [ -z "$SENSOR_IP" ]; then
  first_iface="${INTERFACES%% *}"
  if command -v ip >/dev/null; then
    SENSOR_IP="$(ip -4 -o addr show dev "$first_iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  fi
  [ -n "$SENSOR_IP" ] || die "could not read an IPv4 address from $first_iface; pass --sensor-ip"
fi
info "sensor ip: $SENSOR_IP"

# compose rejects a cpus value above the host's CPU count
host_cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
SURICATA_CPUS="2.0"; [ "$host_cpus" -lt 2 ] && SURICATA_CPUS="$host_cpus.0"
VECTOR_CPUS="1.0"
if [ "$host_cpus" -lt 3 ]; then
  warn "host has $host_cpus CPUs; the 8.0 sensor is sized for 2 capture CPUs plus 1 for Vector"
fi

check_tcp() {
  local host="$1" port="$2"
  if command -v timeout >/dev/null; then
    timeout 5 bash -c "</dev/tcp/$host/$port" 2>/dev/null
  else
    bash -c "</dev/tcp/$host/$port" 2>/dev/null
  fi
}

if [ "$SKIP_KAFKA_CHECK" -eq 0 ]; then
  reachable=0
  for server in $(echo "$KAFKA_SERVER" | tr ',' ' '); do
    if check_tcp "${server%:*}" "${server##*:}"; then
      info "kafka $server reachable"; reachable=1
    else
      warn "kafka $server not reachable"
    fi
  done
  [ "$reachable" -eq 1 ] || die "no Kafka bootstrap server reachable (use --skip-kafka-check to switch anyway)"
fi

# ------------------------------------------------------------------ images ---

if [ -n "$IMAGE_ARCHIVE" ]; then
  [ -f "$IMAGE_ARCHIVE" ] || die "image archive $IMAGE_ARCHIVE not found"
  info "loading images from $IMAGE_ARCHIVE"
  docker load -i "$IMAGE_ARCHIVE"
fi
for ref in "$IMAGE" "$VECTOR_IMAGE"; do
  if ! docker image inspect "$ref" >/dev/null 2>&1; then
    info "pulling $ref"
    docker pull "$ref" || die "cannot pull $ref"
  fi
done

SURICATA_ARGS=""
for iface in $INTERFACES; do SURICATA_ARGS="$SURICATA_ARGS \"-i\", \"$iface\","; done
if [ -n "$HOME_NET" ]; then
  SURICATA_ARGS="$SURICATA_ARGS \"--set\", \"vars.address-groups.HOME_NET=$HOME_NET\","
else
  warn "--home-net not set: ET rules will not match traffic between private addresses"
fi
SURICATA_ARGS="${SURICATA_ARGS%,}"

info "testing the Suricata configuration and rules in $IMAGE"
test_args=""
[ -n "$HOME_NET" ] && test_args="--set vars.address-groups.HOME_NET=$HOME_NET"
# shellcheck disable=SC2086
if ! test_out="$(docker run --rm --entrypoint suricata "$IMAGE" -T -v -c /etc/suricata/suricata.yaml $test_args 2>&1)"; then
  echo "$test_out" | grep -iE "error|failed" | tail -n 20 >&2
  die "suricata -T failed: the configuration or ruleset does not load"
fi
echo "$test_out" | grep -oE "[0-9]+ rules successfully loaded, [0-9]+ rules failed.*" | sed 's/^/    /' || true
echo "$test_out" | grep -q " 0 rules failed" || die "some rules failed to load in $IMAGE"

info "validating $VECTOR_CONFIG"
if ! docker run --rm -e KAFKA_SERVER="$KAFKA_SERVER" -v "$VECTOR_CONFIG:/etc/vector/vector.yaml:ro" \
     "$VECTOR_IMAGE" validate --no-environment /etc/vector/vector.yaml >/dev/null 2>&1; then
  docker run --rm -e KAFKA_SERVER="$KAFKA_SERVER" -v "$VECTOR_CONFIG:/etc/vector/vector.yaml:ro" \
    "$VECTOR_IMAGE" validate --no-environment /etc/vector/vector.yaml >&2 || true
  die "vector.yaml does not validate"
fi

# ----------------------------------------------------------------- compose ---

render_compose() {
  cat <<EOF
# Generated by upgrade-to-8.0.7.sh on $(date '+%F %T'). Replaces the 7.x container ${OLD_IMAGE:-(none)}.
services:
  suricata:
    image: $IMAGE
    container_name: suricata
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
      - SYS_NICE
    command: [ $SURICATA_ARGS ]
    volumes:
      - suricata-log:/var/log/suricata
    restart: unless-stopped
    mem_limit: $SURICATA_MEM
    cpus: $SURICATA_CPUS

  vector:
    image: $VECTOR_IMAGE
    container_name: suricata-vector
    environment:
      - KAFKA_SERVER=$KAFKA_SERVER
      - SENSOR_ID=$SENSOR_ID
      - SENSOR_IP=$SENSOR_IP
      - PROJECT_ID=$PROJECT_ID
      - RULESET_VERSION=$RULESET_VERSION
    volumes:
      - ./vector.yaml:/etc/vector/vector.yaml:ro
      - suricata-log:/var/log/suricata
      - vector-data:/var/lib/vector
    restart: unless-stopped
    mem_limit: $VECTOR_MEM
    cpus: $VECTOR_CPUS

volumes:
  suricata-log:
  vector-data:
EOF
}

if [ "$DRY_RUN" -eq 1 ]; then
  info "(dry-run) $COMPOSE_FILE would be:"
  render_compose
  info "(dry-run) checks passed; nothing was changed"
  exit 0
fi

cat <<EOF

About to switch this sensor to Suricata 8.0.7:
  stop + keep   : ${OLD_IMAGE:-(no 7.x container)} as $BACKUP_NAME
  start         : $IMAGE + $VECTOR_IMAGE (compose project $PROJECT in $INSTALL_DIR)
  kafka         : $KAFKA_SERVER (topics lgshlgs, pcap-body-signal-v1)
  sensor        : id=$SENSOR_ID ip=$SENSOR_IP project=$PROJECT_ID ruleset=$RULESET_VERSION
Syslog output stops: downstream must already consume the pcap_eve pipeline.

EOF
confirm "Proceed?"

mkdir -p "$INSTALL_DIR/backup"
chmod 700 "$INSTALL_DIR"
LOG_FILE="$INSTALL_DIR/upgrade-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
info "log: $LOG_FILE"

cp "$VECTOR_CONFIG" "$INSTALL_DIR/vector.yaml"
render_compose > "$COMPOSE_FILE"

if [ -n "$OLD_IMAGE" ]; then
  docker inspect "$OLD_NAME" > "$INSTALL_DIR/backup/suricata-v7.inspect.json"
  docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$OLD_NAME" > "$INSTALL_DIR/backup/restart-policy"
  info "stopping $OLD_NAME and keeping it as $BACKUP_NAME"
  docker update --restart=no "$OLD_NAME" >/dev/null
  docker stop "$OLD_NAME" >/dev/null
  docker rename "$OLD_NAME" "$BACKUP_NAME"
fi

fail() {
  warn "$1"
  compose logs --tail 50 >&2 || true
  if [ "$NO_AUTO_ROLLBACK" -eq 1 ] || [ -z "$OLD_IMAGE" ]; then
    die "upgrade failed; the 8.0 stack is left as is ($0 --rollback to undo)"
  fi
  warn "rolling back"
  rollback
  die "upgrade failed and was rolled back; see $LOG_FILE"
}

info "starting the 8.0 stack"
# -V: /etc/suricata is an anonymous volume in the base image; never reuse an old one
compose up -d --force-recreate -V || fail "docker compose up failed"

# ------------------------------------------------------------------ health ---

info "waiting up to ${HEALTH_TIMEOUT}s for the engine to start"
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
started=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  state="$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' suricata 2>/dev/null || echo "missing 0")"
  case "$state" in
    running\ 0) ;;
    *) fail "suricata container is not healthy: $state" ;;
  esac
  if docker logs suricata 2>&1 | grep -q "Engine started"; then started=1; break; fi
  sleep 5
done
[ "$started" -eq 1 ] || fail "Suricata did not report 'Engine started' within ${HEALTH_TIMEOUT}s"
info "Suricata engine started"

# stats are written every few seconds; Vector must stay up while it reads them
sleep 30
for c in suricata suricata-vector; do
  state="$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' "$c" 2>/dev/null || echo "missing 0")"
  [ "$state" = "running 0" ] || fail "$c is not healthy after 30s: $state"
done
if ! docker exec suricata sh -c 'ls /var/log/suricata/stats-*.json' >/dev/null 2>&1; then
  fail "Suricata wrote no stats file within 30s"
fi
if docker logs suricata-vector 2>&1 | grep -E " (ERROR|error) " | grep -qi kafka; then
  warn "Vector reports Kafka errors; check: docker logs suricata-vector"
fi
docker exec suricata sh -c 'tail -n 1 $(ls -t /var/log/suricata/stats-*.json | head -n1)' 2>/dev/null \
  | grep -oE '"kernel_(packets|drops)":[0-9]+' | tr '\n' ' ' | sed 's/^/    capture: /'
echo

cat <<EOF

Upgrade done: Suricata 8.0.7 + Vector are running ($COMPOSE_FILE).
  - Confirm downstream receives events from sensor $SENSOR_ID (Kafka topic lgshlgs, tag pcap_eve).
  - Undo:      $0 --rollback
  - Accept:    $0 --finalize   (removes $BACKUP_NAME)
EOF
