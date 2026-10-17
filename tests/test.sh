#!/bin/bash
# Runs Suricata on every target pcap and checks the EVE http events against the
# target's expected values (http.log).
set -u

for target in target/*/; do
    target_name=$(basename "$target")
    echo "Testing target: $target_name"
    out=$(mktemp -d); chmod 777 "$out"   # suricata drops to the suricata user (run-as)
    /usr/bin/suricata -c /etc/suricata/suricata.yaml --runmode autofp -r "$target/capture.pcap" -l "$out" -k none &> "$out/suricata.log"
    if python3 check_eve.py "$out"/eve-*.json "$target/http.log"; then
        echo "Test Passed: $target_name"
    else
        echo "Test Failed: $target_name" >&2
        cat "$out/suricata.log" >&2
        exit 1
    fi
done

# the request-body ruleset loads completely
if /usr/bin/suricata -T -v -c /etc/suricata/suricata.yaml 2>&1 | grep -q " 0 rules failed"; then
    echo "Test Passed: body.rules loaded"
else
    echo "Test Failed: body.rules did not load cleanly" >&2
    exit 1
fi
