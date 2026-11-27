-- http_custom.lua for Suricata 8.0: the 7.x message format (same fields, same
-- order, same redaction), ported to the suricata.* Lua libraries because the
-- 7.x global functions (HttpGet*, SCFlow*, SCPacketTimeString) are gone in 8.0.
--
-- Writes one message per HTTP transaction to HTTP_CUSTOM_LOG (default
-- /var/log/suricata/http_custom.log). Shipping it (syslog, Kafka) is left to a
-- separate reader: the 8.0 image has no luasocket.

local http = require("suricata.http")
local flow = require("suricata.flow")
local packet = require("suricata.packet")

function init (args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function env_bool(name, default)
    local value = os.getenv(name)
    if value == nil then
        return default
    end
    value = string.lower(value)
    if value == "false" or value == "0" or value == "no" then
        return false
    elseif value == "true" or value == "1" or value == "yes" then
        return true
    else
        return default
    end
end

function setup (args)
    local filename = os.getenv("HTTP_CUSTOM_LOG") or "/var/log/suricata/http_custom.log"
    file = assert(io.open(filename, "a"))

    body_max_size = tonumber(os.getenv("HTTP_BODY_MAX_SIZE")) or 1024
    redact_sensitive_headers = env_bool("REDACT_SENSITIVE_HEADERS", true)
    enable_raw_capture = env_bool("ENABLE_RAW_CAPTURE", false)
end

-- JSON string encoding for the raw-capture fragment, byte for byte as 7.x's
-- lua-json (which also escapes "/").
function json_string(s)
    s = s or ""
    s = s:gsub('[%c"\\/]', function(c)
        if c == '"' then return '\\"' end
        if c == '\\' then return '\\\\' end
        if c == '/' then return '\\/' end
        if c == '\n' then return '\\n' end
        if c == '\r' then return '\\r' end
        if c == '\t' then return '\\t' end
        return string.format('\\u%04x', string.byte(c))
    end)
    return '"' .. s .. '"'
end

-- Each header counts as "Name: Value\r\n", as in 7.x.
function headers_size(headers)
    local total_size = 0
    if type(headers) ~= "table" then
        return total_size
    end
    for name, value in pairs(headers) do
        total_size = total_size + string.len(name) + 2 + string.len(value) + 2
    end
    return total_size
end

-- Body chunks as a table (8.0 returns chunks, offset, end-of-body).
function body_chunks_of(chunks)
    if type(chunks) == "string" then
        return { chunks }
    elseif type(chunks) == "table" then
        return chunks
    end
    return {}
end

function body_length(chunks)
    local total_size = 0
    for _, chunk in ipairs(body_chunks_of(chunks)) do
        total_size = total_size + string.len(chunk)
    end
    return total_size
end

function body_prefix(chunks)
    local body = ""
    for _, chunk in ipairs(body_chunks_of(chunks)) do
        if (string.len(body) + string.len(chunk)) > body_max_size then
            body = body .. string.sub(chunk, 1, body_max_size - string.len(body))
            break
        end
        body = body .. chunk
    end
    return body
end

function extract_http_variables(tx, f)
    local timestamp = ""
    local p = packet.get()
    if p then
        local sec = p:timestamp()
        if sec then
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", sec)
        end
    end

    local ip_version, src_ip, dest_ip, protocol, src_port, dest_port = f:tuple()

    local method = tx:request_line() or ""
    method = method:match("^(%S+)") or ""
    local uri = tx:request_uri_raw() or ""
    local status_line = tx:response_line() or ""

    local uri_path = uri
    local uri_query = ""
    local query_start = string.find(uri, "?", 1, true)
    if query_start then
        uri_path = string.sub(uri, 1, query_start - 1)
        uri_query = string.sub(uri, query_start + 1)
    end

    local function req(name) return tx:request_header(name) or "" end
    local function res(name) return tx:response_header(name) or "" end
    local function redact(value)
        if redact_sensitive_headers and value ~= "" then return "[REDACTED]" end
        return value
    end

    return {
        timestamp = timestamp,
        src_ip = src_ip or "",
        dest_ip = dest_ip or "",
        src_port = src_port or "",
        dest_port = dest_port or "",
        method = method,
        hostname = tx:request_host() or "",
        uri_path = uri_path,
        uri_query = uri_query,
        file_extension = string.match(uri_path, "%.([^./]+)$") or "",
        status = status_line:match("HTTP/[%d%.]+%s+(%d+)") or "",
        version = status_line:match("(HTTP/[%d%.]+)") or "HTTP/1.1",
        user_agent = req("User-Agent"),
        accept = req("Accept"),
        referrer = req("Referer"),
        x_forwarded_for = req("X-Forwarded-For"),
        connection = req("Connection"),
        request_content_type = req("Content-Type"),
        request_content_length = req("Content-Length"),
        response_content_type = res("Content-Type"),
        response_content_length = res("Content-Length"),
        authorization = redact(req("Authorization")),
        host = req("Host"),
        etag = res("ETag"),
        last_modified = res("Last-Modified"),
        server = res("Server"),
        http_accept_language = req("Accept-Language"),
        location = res("Location"),
        set_cookie = redact(res("Set-Cookie")),
        cookie = redact(req("Cookie")),
        x_forwarded_host = req("X-Forwarded-Host"),
        x_powered_by = res("X-Powered-By"),
        x_client_ip = req("X-Client-IP"),
        x_real_ip = req("X-Real-IP"),
    }
end

function calculate_duration(f)
    local start_sec, last_sec, start_usec, last_usec = f:timestamps()
    if not (start_sec and start_usec and last_sec and last_usec) then
        return 0
    end
    local duration = math.floor(((last_sec - start_sec) * 1000000 + (last_usec - start_usec)) / 1000)
    if duration < 0 then
        return 0
    end
    return duration
end

-- Same format string as 7.x, field for field.
function format_message(vars, request_body_len, response_body_len, req_header_length, res_header_length, duration)
    return string.format(
        'time="%s" src="%s" dest="%s" src_port=%s dest_port=%s ' ..
        'http_method="%s" version="%s" uri_path="%s" ' ..
        'uri_query="%s" file_extension="%s" url_domain="%s" ' ..
        'request_connection="%s" http_user_agent="%s" http_accept="%s" ' ..
        'http_referrer="%s" x_forwarded_for="%s" request_content_type="%s" ' ..
        'request_content_length="%s" bytes_in=%d status="%s" ' ..
        'response_content_type="%s" response_content_length="%s" ' ..
        'authorization="%s" host="%s" etag="%s" last_modified="%s" server="%s" ' ..
        'http_accept_language="%s" location="%s" set_cookie="%s" cookie="%s" ' ..
        'x_forwarded_host="%s" x_powered_by="%s" ' ..
        'bytes_out="%s" duration=%d ' ..
        'body_bytes_out="%s" body_bytes_in="%s" ' ..
        'x_client_ip="%s" x_real_ip="%s"',
        vars.timestamp, vars.src_ip, vars.dest_ip, vars.src_port, vars.dest_port,
        vars.method, vars.version, vars.uri_path,
        vars.uri_query, vars.file_extension, vars.hostname,
        vars.connection, vars.user_agent, vars.accept,
        vars.referrer, vars.x_forwarded_for, vars.request_content_type,
        vars.request_content_length, req_header_length + request_body_len, vars.status,
        vars.response_content_type, vars.response_content_length,
        vars.authorization, vars.host, vars.etag, vars.last_modified, vars.server,
        vars.http_accept_language, vars.location, vars.set_cookie, vars.cookie,
        vars.x_forwarded_host, vars.x_powered_by,
        res_header_length + response_body_len, duration,
        response_body_len, request_body_len,
        vars.x_client_ip, vars.x_real_ip
    )
end

function format_raw_capture(tx)
    return string.format(
        ' request_header=%s response_header=%s request_body=%s response_body=%s',
        json_string(tx:request_headers_raw()), json_string(tx:response_headers_raw()),
        json_string(body_prefix(tx:request_body())), json_string(body_prefix(tx:response_body()))
    )
end

function log(args)
    local tx = http.get_tx()
    local f = flow.get()
    if tx == nil or f == nil then
        return
    end

    local message = format_message(
        extract_http_variables(tx, f),
        body_length(tx:request_body()), body_length(tx:response_body()),
        headers_size(tx:request_headers()), headers_size(tx:response_headers()),
        calculate_duration(f))
    if enable_raw_capture then
        message = message .. format_raw_capture(tx)
    end

    file:write(message .. "\n")
    file:flush()
end

function deinit (args)
    if file then
        file:close()
    end
end
