# suricata

A containerized [Suricata 8.0](https://suricata.io/) sensor that logs HTTP / HTTP2 transactions with Suricata's native EVE JSON output. A [Vector](https://vector.dev/) sidecar ships the events to Kafka.

## Features

- Captures traffic directly on the host network interface using `network_mode: host`
- Native EVE output for HTTP, HTTP2, flow and engine stats; files rotate hourly and are removed by the sidecar after they are shipped
- Vector sidecar (`configs/vector.yaml`): masks secrets on the sensor, ships HTTP events to Kafka topic `lgshlgs` (tag `pcap_eve`) with acknowledgements and disk buffers, so a Kafka or downstream outage does not lose events
- Optional request-body signals: a small marker ruleset (`configs/rules/body.rules`) flags injection patterns in request bodies; the alerts go to Kafka topic `pcap-body-signal-v1`. No request body text leaves the sensor
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
| `RULESET_VERSION` | `body-v1` when the request-body ruleset is loaded; empty to report "not inspected" |

### What leaves the sensor

- Values of `Authorization`, `Cookie` and `Set-Cookie` headers are replaced with `[REDACTED]` (the header's presence is kept).
- Values of `token`, `access_token`, `api_key`, `apikey`, `sig`, `signature` and `password` query parameters are replaced with `[REDACTED]`.
- Raw EVE files stay on the sensor (mode 600) for about an hour after they are shipped.

### Migrating from the 7.x Lua image

- The Lua syslog output (`http_custom.lua`) and its environment variables (`SYSLOG_HOST`, `SYSLOG_PORT`, `HTTP_BODY_MAX_SIZE`, `TCP_*`, `REDACT_SENSITIVE_HEADERS`, `ENABLE_RAW_CAPTURE`) are gone. Events go through the Vector sidecar to Kafka instead of TCP syslog.
- Field semantics: `body_bytes_out` is the on-wire response body (dechunked, not decompressed); header-inclusive `bytes_in` / `bytes_out` and `duration` are not produced.
- `/etc/suricata` is a volume in the base image: recreate the container with renewed anonymous volumes (`docker compose up -d --force-recreate -V`), otherwise an existing container keeps its old configuration.

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

Tests run Suricata against offline PCAP files and check the EVE http events against the expected values in each target's `http.log`, and check that the request-body ruleset loads:

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
