# replace the `runmode: workers` to `runmode: autofp` in `/etc/suricata/suricata.yaml` for analyzing the offline pcap
sed -i 's/runmode: workers/runmode: autofp/g' /etc/suricata/suricata.yaml

# add the `print(syslog_format_message)` in the first line of the function `sendToSyslogServer` in `/etc/suricata/http_custom_7.0.lua`
sed -i 's/--print(message)/print(message)/g' /etc/suricata/http_custom_7.0.lua

# Test all targets in /tmp/targets/
for target in targets/*/; do
    target_name=$(basename "$target")
    echo "Testing target: $target_name"

    # Run suricata on the capture.pcap file for this target
    /usr/bin/suricata -c /etc/suricata/suricata.yaml -r "$target/capture.pcap" -l /tmp/ -k none &> /tmp/suricata.log

    # Check if /tmp/suricata.log contains all lines from the expected http.log 
    if grep -Fxf "$target/http.log" /tmp/suricata.log > /dev/null; then
        echo "Test Passed: $target_name: /tmp/suricata.log contains all content from http.log"
    else
        echo "Test Failed: $target_name: /tmp/suricata.log is missing some content from http.log" >&2
        exit 1
    fi
done

# test if required lua packages are installed
for module in socket json; do 
    lua -e "require('$module')" 2>/dev/null && echo "Test Passed: $module test success" || { echo "$module test failed" && exit 1; }
done
