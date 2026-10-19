# suricata

A containerized [Suricata 8.0](https://suricata.io/) sensor that logs HTTP / HTTP2 transactions with Suricata's native EVE JSON output. A [Vector](https://vector.dev/) sidecar ships the events to Kafka.

## Features

- Captures traffic directly on the host network interface using `network_mode: host`
- Native EVE output for HTTP, HTTP2, flow and engine stats; files rotate hourly and are removed by the sidecar after they are shipped
- Vector sidecar (`configs/vector.yaml`): masks secrets on the sensor, ships HTTP events to Kafka topic `lgshlgs` (tag `pcap_eve`) with acknowledgements and disk buffers, so a Kafka or downstream outage does not lose events
- HTTP detection signals (ruleset `rules-v2`, see [Rules](#rules)): request-body injection markers, protocol anomalies and request smuggling, signs of a successful attack in response bodies, script uploads, and selected ET Open rules. Alerts go to Kafka topic `pcap-body-signal-v1` with the rule's gid, rev, classtype and severity. No request or response body text leaves the sensor
- Connection records: `flow` events of HTTP and HTTP/2 connections (start, end, bytes and packets per direction, requests per connection, end reason, reset seen) go to the same topic as `type: "flow"`, keyed by sensor, ahead of the frontier that covers them
- Only HTTP / HTTP2 / TLS application-layer parsing is enabled; memcaps are bounded below the container memory limit
- No Lua: there are no Lua output scripts, and rules using the `lua` keyword are rejected at load time (`security.lua.allow-rules: false`). Suricata 8 always builds with Lua; it is present in the binary but unused

## Getting Started

### Using docker-compose

1. Copy the example configuration:

   ```bash
   cp example/docker-compose.yml docker-compose.yml
   ```

2. **Set the network interface to listen on:** replace `eth0` in the `suricata` service's `command` with the host interface (`ip link show`). Repeat `-i` for more interfaces, e.g. `[ "-i", "eth0", "-i", "eth1" ]`. The config runs one capture worker per interface (`af-packet.threads: 1`), matching `cpus: 2.0` for two interfaces.

3. **Configure the Vector sidecar** with the environment variables below, then start both containers:

   ```bash
   docker compose up -d
   ```

### Vector environment variables

| Variable | Description |
|---|---|
| `KAFKA_SERVER` | Kafka bootstrap servers |
| `SENSOR_ID` | Sensor identity, added to every event (`raw_sensor_id`) |
| `SENSOR_IP` | Sensor address (`raw_host_ip`) |
| `PROJECT_ID` | Project identity for request-body signals |
| `RULESET_VERSION` | `rules-v2`, the image's ruleset: request and response bodies are inspected. Empty to report bodies as "not inspected" |

### What leaves the sensor

- Values of `Authorization`, `Cookie` and `Set-Cookie` headers are replaced with `[REDACTED]` (the header's presence is kept).
- Values of `token`, `access_token`, `api_key`, `apikey`, `sig`, `signature` and `password` query parameters are replaced with `[REDACTED]`.
- Raw EVE files stay on the sensor (mode 600) for about an hour after they are shipped.

### Migrating from the 7.x Lua image

- The Lua syslog output (`http_custom.lua`) and its environment variables (`SYSLOG_HOST`, `SYSLOG_PORT`, `HTTP_BODY_MAX_SIZE`, `TCP_*`, `REDACT_SENSITIVE_HEADERS`, `ENABLE_RAW_CAPTURE`) are gone. Events go through the Vector sidecar to Kafka instead of TCP syslog.
- Field semantics: `body_bytes_out` is the on-wire response body (dechunked, not decompressed); header-inclusive `bytes_in` / `bytes_out` and `duration` are not produced.
- `/etc/suricata` is a volume in the base image: recreate the container with renewed anonymous volumes (`docker compose up -d --force-recreate -V`), otherwise an existing container keeps its old configuration.

## Rules

`configs/rules/`, loaded by `configs/suricata.yaml`. Alerts are signals only; nothing is blocked. Per-sid categories are in `sid_map.csv` (`ruleset_version,sid,category`).

| File | sid | What it flags |
|---|---|---|
| `body.rules` | 9100001–9100016 | injection patterns in request bodies |
| `protocol.rules` | 9101001–9101099 | request smuggling and parser evasion: Content-Length with Transfer-Encoding, Transfer-Encoding other than `chunked`, header folding, whitespace before the colon, Content-Length with extra data |
| bundled `http-events.rules`, `http2-events.rules` | 2221000–2221059, 2290000–2290021 | Suricata's HTTP / HTTP2 parser anomalies |
| `response.rules` | 9102001–9102099 | response bodies (decompressed, first 100 KB): `/etc/passwd`, command output, SQL errors, stack traces, phpinfo, directory listings, keys, webshell pages |
| `upload.rules` | 9103001–9103099 | multipart uploads: PHP / JSP / ASP.NET code, script file names, images that are not images |
| `et-http.rules` | ET Open | ET Open `attack_response`, `web_server`, `exploit` and `web_specific_apps`, HTTP rules only |

- **HOME_NET:** ET rules are directional. Set `HOME_NET` to the servers the sensor protects, e.g. append `--set vars.address-groups.HOME_NET=10.1.2.3` to the `suricata` command. With the default (all private ranges) traffic between private addresses never matches them.
- **Updating ET Open:** the sensor parses only HTTP / HTTP2, so rules for other protocols would fail to load. `tools/et-http-rules.py` keeps the enabled HTTP rules of those categories and drops the generic rules listed in it. The ET version is in the file header:

  ```bash
  curl -sSfO https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz && tar -xzf emerging.rules.tar.gz
  tools/et-http-rules.py rules "$(curl -sSf https://rules.emergingthreats.net/open/suricata-8.0/version.txt)" > configs/rules/et-http.rules
  ```

  A new ruleset needs a new `RULESET_VERSION` and its rows in `sid_map.csv`.
- **Cost:** offline, single thread, the ruleset adds about 9 CPU seconds at start (8,269 rules, peak memory +80–100 MiB) and costs about 4× the request-body-only ruleset per transaction on small API traffic, mostly in the ET rules. Size the capture CPUs for that, or trim `et-http.rules`.

## Container Image

```
ghcr.io/reflective-technology/suricata:latest
```

Built on top of `jasonish/suricata:8.0.7`.

## Building the Image

```bash
docker build --target prod -t suricata .
```

## Testing

Tests run Suricata against offline PCAP files and check the EVE http events against the expected values in each target's `http.log`, and check that every rule file loads:

```bash
docker build --target dev -t suricata-dev .
docker run --rm suricata-dev bash test.sh
```

The Vector configuration has unit tests:

```bash
docker run --rm -e KAFKA_SERVER=localhost:9092 -v $PWD/configs/vector.yaml:/etc/vector/vector.yaml:ro \
  timberio/vector:0.49.0-debian test /etc/vector/vector.yaml
```

## License

See [LICENSE.md](LICENSE.md).
