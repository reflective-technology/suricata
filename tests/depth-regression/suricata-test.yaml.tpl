%YAML 1.1
---
# Minimal Suricata yaml for offline pcap regression test.
# Placeholders __DEPTH__ replaced by run-comparison.sh before each pass.

# default-log-dir intentionally omitted; -l on the command line wins.

outputs:
  # Lua intentionally disabled in test rig — http_custom_8.0.lua crashes
  # suricata after first tx in this image (likely lua-json ABI mismatch).
  # eve.json carries the bug indicators we need (anomaly events).
  - lua:
      enabled: no
      scripts-dir: /etc/suricata
      scripts:
        - http_custom.lua
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - http:
            enabled: yes
            extended: yes
        - stats:
            totals: yes
            threads: no
            deltas: no
        - anomaly:
            enabled: yes
            types:
              applayer: yes
              decode: yes
              stream: yes

stats:
  enabled: yes
  interval: 1
  totals: yes

logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes

app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          # Per-pass substituted by run-comparison.sh. Production default is 100kb;
          # raise to e.g. 100mb to expose depth bug at lower cumulative totals.
          request-body-limit: __BODY_LIMIT__
          response-body-limit: __BODY_LIMIT__

stream:
  memcap: 256mb
  checksum-validation: no
  reassembly:
    memcap: 1gb
    # Replaced per pass by run-comparison.sh
    depth: __DEPTH__

flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 1000

defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

host:
  hash-size: 4096
  prealloc: 1000
  memcap: 16mb

vars:
  address-groups:
    HOME_NET: "[172.30.0.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"

runmode: autofp

# pcap-file mode flags
pcap-file:
  checksum-checks: no
