#!/usr/bin/env bash
# Run Suricata 8.0 twice over the same pcap with depth=1mb vs depth=10mb,
# emit eve.json + lua log, and surface the key counters.
set -euo pipefail

cd "$(dirname "$0")"

PCAP="${PCAP:-$PWD/pcap/traffic.pcap}"
RESULTS_DIR="${RESULTS_DIR:-$PWD/results}"
IMAGE="${IMAGE:-suricata-test:8.0.0-lua}"
LUA="$PWD/../../configs/suricata/http_custom_8.0.lua"

if [[ ! -f "$PCAP" ]]; then
    echo "ERROR: pcap not found at $PCAP — run generate-traffic via docker-compose.gen.yml first" >&2
    exit 1
fi
if [[ ! -f "$LUA" ]]; then
    echo "ERROR: lua not found at $LUA" >&2
    exit 1
fi

run_one() {
    local depth="$1"
    local out="$RESULTS_DIR/$depth"
    local name="dr-suri-$depth"
    mkdir -p "$out"
    find "$out" -mindepth 1 -delete 2>/dev/null || true

    sed -e "s/__DEPTH__/$depth/g" -e "s/__BODY_LIMIT__/${BODY_LIMIT:-100kb}/g" \
        suricata-test.yaml.tpl > "$out/suricata.yaml"

    echo
    echo "==== Suricata pass: depth=$depth ===="
    docker rm -f "$name" >/dev/null 2>&1 || true
    # Write output to container-internal /var/log/suricata (already exists in image).
    # Bind-mounting an output dir on Docker Desktop VirtioFS races with suricata's
    # eager open of eve.json and intermittently returns ENOENT.
    docker run --name "$name" \
        -v "$PCAP":/data/traffic.pcap:ro \
        -v "$out/suricata.yaml":/etc/suricata/suricata.yaml:ro \
        -v "$LUA":/etc/suricata/http_custom.lua:ro \
        --entrypoint suricata \
        "$IMAGE" \
        -c /etc/suricata/suricata.yaml \
        -r /data/traffic.pcap \
        -l /var/log/suricata \
        -k none \
        --runmode autofp \
        2>&1 | tail -8

    docker cp "$name:/var/log/suricata/." "$out/" 2>&1 | head -5
    docker rm -f "$name" >/dev/null
}

summarize() {
    local depth="$1"
    local out="$RESULTS_DIR/$depth"
    local eve="$out/eve.json"
    local lua_log="$out/http_custom.log"

    echo
    echo "==== Summary: depth=$depth ===="
    if [[ ! -f "$eve" ]]; then
        echo "  (no eve.json — Suricata may have failed)"
        return
    fi

    local n_http n_method_empty n_anomaly
    n_http=$(jq -c 'select(.event_type=="http")' "$eve" | wc -l | tr -d ' ')
    n_method_empty=$(jq -c 'select(.event_type=="http" and (.http.http_method // "")=="")' "$eve" | wc -l | tr -d ' ')
    n_anomaly=$(jq -c 'select(.event_type=="anomaly")' "$eve" | wc -l | tr -d ' ')

    echo "  http events:                          $n_http"
    echo "  http events with empty http_method:   $n_method_empty"
    echo "  anomaly events:                       $n_anomaly"

    # Pull the most interesting stats counters
    echo "  --- relevant stats counters (final snapshot) ---"
    jq -c 'select(.event_type=="stats") | .stats | {
        tcp_reassembly_gap: .tcp.reassembly_gap,
        tcp_stream_depth_reached: .tcp.stream_depth_reached,
        http_tx: .app_layer.tx.http,
        http_gap: (.app_layer.error.http.gap // 0),
        http_parser_error: (.app_layer.error.http.parser // 0),
        http_internal_error: (.app_layer.error.http.internal // 0)
    }' "$eve" | tail -1 | jq .

    # Lua-emitted methods, if any
    if [[ -f "$lua_log" ]]; then
        local n_lua_lines n_lua_empty_method
        n_lua_lines=$(wc -l < "$lua_log" | tr -d ' ')
        n_lua_empty_method=$(grep -cE '"method":""' "$lua_log" 2>/dev/null || echo 0)
        echo "  lua log lines:                        $n_lua_lines"
        echo "  lua log lines with empty method:      $n_lua_empty_method"
    fi
}

DEPTHS="${DEPTHS:-1mb 10mb}"
for d in $DEPTHS; do run_one "$d"; done
for d in $DEPTHS; do summarize "$d"; done

echo
echo "Done. Detailed output in $RESULTS_DIR/{1mb,10mb}/"
