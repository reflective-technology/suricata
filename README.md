# suricata

A containerized [Suricata 7.0](https://suricata.io/) that forwards HTTP traffic details to a remote Syslog server in real time via a Lua script.

## Features

- Captures traffic directly on the host network interface using `network_mode: host`
- Parses HTTP requests and responses with a Lua script (`http_custom.lua`) and forwards structured messages over TCP Syslog
- Configurable Syslog target, TCP retry behavior, and HTTP body size limit
- Only HTTP / HTTP2 application-layer parsing is enabled, keeping resource usage minimal

## Getting Started

### Using docker-compose

1. Copy the example configuration:

   ```bash
   cp example/docker-compose.yml docker-compose.yml
   ```

2. **Set the network interface to listen on:**

   Edit `docker-compose.yml` and replace `eth0` in the `command` field with the name of the actual interface on your host.
   To list available interfaces, run:

   ```bash
   ip link show
   # or
   ifconfig
   ```

   ```yaml
   command: [ "-i eth0" ]   # replace eth0 with your interface name, e.g. ens3, enp0s3, bond0
   ```

   To listen on multiple interfaces, repeat the `-i` flag:

   ```yaml
   command: [ "-i eth0 -i eth1" ]
   ```

3. Adjust the environment variables as needed (see below), then start the container:

   ```bash
   docker compose up -d
   ```

### Environment Variables

| Variable                     | Default     | Description                                                                 |
|------------------------------|-------------|-------------------------------------------------------------------------------|
| `SYSLOG_HOST`                | `127.0.0.1` | Syslog server IP address                                                    |
| `SYSLOG_PORT`                | `514`       | Syslog server TCP port                                                      |
| `HTTP_BODY_MAX_SIZE`         | `1024`      | Maximum number of bytes captured from the HTTP body                        |
| `TCP_MAX_RETRIES`            | `10`        | Maximum TCP reconnect attempts on connection failure                        |
| `TCP_RETRY_DELAY`            | `10`        | Seconds to wait between reconnect attempts                                  |
| `REDACT_SENSITIVE_HEADERS`   | `true`      | Redact `Authorization`/`Cookie`/`Set-Cookie` to `[REDACTED]` when present   |
| `ENABLE_RAW_CAPTURE`         | `false`     | Ship raw `request_header`/`response_header`/`request_body`/`response_body` |

See [Migrating from older versions](#migrating-from-older-versions) if you're upgrading an existing deployment.

### Full docker-compose.yml Example

```yaml
services:
  suricata:
    image: ghcr.io/reflective-technology/suricata:latest
    container_name: suricata
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
      - SYS_NICE
    environment:
      - SYSLOG_HOST=192.168.1.100   # change to your Syslog server address
      - SYSLOG_PORT=514
      - HTTP_BODY_MAX_SIZE=1024
      - TCP_MAX_RETRIES=10
      - TCP_RETRY_DELAY=10
      - REDACT_SENSITIVE_HEADERS=true
      - ENABLE_RAW_CAPTURE=false
    command: [ "-i ens3" ]          # change to your network interface name
    restart: unless-stopped
```

### Migrating from older versions

- **`BODY_MAX_SIZE` is renamed to `HTTP_BODY_MAX_SIZE`** (the old name was too generic). Update your compose file; the old name is no longer read, and the default also changed from `4096` to `1024`.
- **`Authorization`, `Cookie`, and `Set-Cookie` are now redacted to `[REDACTED]` by default.** Set `REDACT_SENSITIVE_HEADERS=false` if your pipeline needs the raw values.
- **Raw `request_header`/`response_header`/`request_body`/`response_body` capture is now off by default**, and the fields are omitted entirely (not sent as empty strings) when off. Set `ENABLE_RAW_CAPTURE=true` if your pipeline depends on this data.

## Container Image

```
ghcr.io/reflective-technology/suricata:latest
```

Built on top of `jasonish/suricata`.

## Building the Image

```bash
docker build --target prod -t suricata .
```

## Testing

Tests run Suricata against offline PCAP files and verify the output matches expectations:

```bash
docker build --target dev -t suricata-dev .
docker run --rm suricata-dev bash test.sh
```

## License

See [LICENSE.md](LICENSE.md).
