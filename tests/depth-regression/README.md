# Stream Reassembly Depth Regression Test

Validates that `stream.reassembly.depth: 10mb` (vs the default `1mb`) prevents
libhtp from giving up on HTTP requests after the depth limit is hit on a TCP
keepalive connection (OISF Bug #6874).

## Outcomes (2026-05-18)

### Baseline: 2MB POST + 50 GETs (production-like body-limit 100kb)

| Metric | `depth: 1mb` | `depth: 10mb` |
|---|---|---|
| HTTP events with `http_method == ""` | 16 / 17 | 0 / 17 |
| Anomaly events (`stream.reassembly_depth_reached`, `UNABLE_TO_MATCH_RESPONSE_TO_REQUEST`) | 17 | 0 |
| `stats.tcp.stream_depth_reached` | 1 | 0 |

### Stress: 60 × 200KB POSTs + 20 GETs (extended body-limit 100mb)

| Metric | `depth: 1mb` | `depth: 10mb` | `depth: 20mb` |
|---|---|---|---|
| HTTP events with `http_method == ""` | 54 / 60 | **8 / 60** | 0 / 60 |
| Anomaly events | 55 | 9 | 0 |
| `stats.tcp.stream_depth_reached` | 1 | **1 (hit)** | 0 |

→ Same bug at higher cumulative still bites `depth=10mb`. depth is a threshold, not a fix.

## How to reproduce

```bash
# 1. Build the suricata test image (jasonish/suricata:8.0.0 + lua + lua-json)
docker build -t suricata-test:8.0.0-lua -f Dockerfile.suricata .

# 2a. Baseline trigger pcap (one keepalive conn, one 2MB POST, then 50 GETs)
docker compose -f docker-compose.gen.yml up -d
docker run --rm --network depth-regression_depth-net \
    -v "$PWD/generate-traffic.py":/script.py:ro \
    python:3.12-alpine \
    sh -c "pip install -q requests && python /script.py"
docker compose -f docker-compose.gen.yml down

./run-comparison.sh   # depth 1mb vs 10mb, BODY_LIMIT default 100kb

# 2b. Stress trigger pcap (60 × 200KB POSTs + 20 GETs, ~12MB cumulative)
docker compose -f docker-compose.gen.yml up -d
docker run --rm --network depth-regression_depth-net \
    -e NUM_POSTS=60 -e POST_KB=200 -e NUM_GETS=20 \
    -v "$PWD/generate-traffic-multi.py":/script.py:ro \
    python:3.12-alpine \
    sh -c "pip install -q requests && python /script.py"
docker compose -f docker-compose.gen.yml down
mv pcap/traffic.pcap pcap/traffic-60post.pcap

PCAP=$PWD/pcap/traffic-60post.pcap \
    RESULTS_DIR=$PWD/results-60post \
    DEPTHS="1mb 10mb 20mb" \
    BODY_LIMIT=100mb \
    ./run-comparison.sh
```

### `run-comparison.sh` env vars

| var | default | purpose |
|---|---|---|
| `PCAP` | `$PWD/pcap/traffic.pcap` | input pcap |
| `RESULTS_DIR` | `$PWD/results` | per-depth subdirs created here |
| `IMAGE` | `suricata-test:8.0.0-lua` | suricata image |
| `DEPTHS` | `"1mb 10mb"` | space-separated depth values to test |
| `BODY_LIMIT` | `100kb` | libhtp request/response body inspection limit |

Outputs land in `results/1mb/` and `results/10mb/` (eve.json,
http_custom.log if lua is enabled, fast.log, stats.log).

## Files

| File | Purpose |
|---|---|
| `Dockerfile.suricata` | jasonish/suricata:8.0.0 + `lua`/`lua-json` for the custom lua output |
| `docker-compose.gen.yml` | nginx (test target) + tcpdump (shares nginx netns to sniff) |
| `nginx.conf` | nginx config: accepts large bodies, keepalive 300s |
| `generate-traffic.py` | Single keepalive session: 2MB POST then 50 GETs |
| `suricata-test.yaml.tpl` | Minimal yaml template; `__DEPTH__` is substituted per run |
| `run-comparison.sh` | Substitutes depth into template, runs suricata twice, prints diff |

## Gotchas

- **Docker Desktop VirtioFS** races with `rm -rf` + `mkdir` + bind mount of the
  same path. The script writes Suricata output to `/var/log/suricata` inside
  the container, then `docker cp`s it out — never bind-mount the output dir.
- **Lua disabled in the test yaml**: enabling the project's `http_custom_8.0.lua`
  causes Suricata 8.0 to SIGSEGV after the first transaction in this image.
  Likely a `lua-json` ABI mismatch with Suricata 8.0's lua interface; out of
  scope for this regression test. eve.json carries the bug indicator we need
  (empty `http_method` on the affected transactions).
- **tcpdump sniffing**: docker bridges aren't broadcast, so a sidecar on the
  same bridge can't see inter-container traffic. `tcpdump` uses
  `network_mode: "service:nginx"` to share nginx's netns.
- **curl `--next`** chained args is unreliable for forcing connection reuse
  across N requests; use `requests.Session()` instead.

## Trigger mechanics

1. Python opens a `requests.Session` with `pool_connections=1, pool_maxsize=1`,
   guaranteeing one underlying urllib3 HTTPConnection.
2. POST 2MB to `/upload` — this alone exceeds `stream.reassembly.depth: 1mb`.
3. 50 small GETs to `/path1`..`/path50` reusing the same TCP connection.
4. With `depth: 1mb`, libhtp emits `stream.reassembly_depth_reached`, then
   `UNABLE_TO_MATCH_RESPONSE_TO_REQUEST` for the GETs, and populates
   `tx->request_line` with garbled bytes → eve.json `http_method` is empty.
5. With `depth: 10mb`, the 2MB POST fits, the GETs parse cleanly, no anomaly.
