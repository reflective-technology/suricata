
-- Appended to the 7.x http_custom.lua by run-comparison.sh: write each message
-- to a file instead of TCP syslog, so 7.x and 8.0 output can be diffed.
function establish_tcp_connection() return nil end
function template_syslog_message(message) return message end
local setup_7x = setup
function setup(args)
    setup_7x(args)
    out_file = assert(io.open("/var/log/suricata/http_custom.log", "a"))
end
function sendToSyslogServer(message)
    out_file:write(message .. "\n")
    out_file:flush()
end
