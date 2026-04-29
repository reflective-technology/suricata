function init (args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function setup (args)
    --filename = "/var/log/suricata/http_custom.log"
    --file = assert(io.open(filename, "a"))

    -- Establish TCP connection to syslog server
    tcp_max_retries = tonumber(os.getenv("TCP_MAX_RETRIES")) or 10
    tcp_retry_delay = tonumber(os.getenv("TCP_RETRY_DELAY")) or 10
    tcp_client = establish_tcp_connection(0)

    -- load the required env variables
    body_max_size = tonumber(os.getenv("BODY_MAX_SIZE")) or 4096

    -- Load json library as global
    json = require("json")

end

function establish_tcp_connection(tcp_retried_times)
    local socket = require("socket")
    local syslog_host = os.getenv("SYSLOG_HOST") or "127.0.0.1"
    local syslog_port = os.getenv("SYSLOG_PORT") or 514
    tcp_client = socket.tcp()
    local result, err = tcp_client:connect(syslog_host, syslog_port)
    if not result then
        print("Error: Failed to connect to syslog server: " .. (err or "unknown error"))
        if tcp_retried_times < tcp_max_retries then
            print("Reconnect to the syslog serer on the", tcp_retried_times + 1, " times")
            socket.sleep(tcp_retry_delay)
            tcp_client = establish_tcp_connection(tcp_retried_times + 1)
        else
            print("Stop reconnecting to the syslog server as the max_retries exceeded")
            tcp_client = nil
        end
    else
        print("Info: Connected to remote syslog server: " .. syslog_host .. ":" .. syslog_port)
    end
    return tcp_client
end

function calculate_request_headers_size()
    local headers = HttpGetRequestHeaders()
    local total_size = 0

    if not headers then
        return total_size
    end

    for name, value in pairs(headers) do
        -- Each header follows format: "Name: Value\r\n"
        total_size = total_size + string.len(name) + 2 + string.len(value) + 2
    end

    return total_size
end

function calculate_response_headers_size()
    local headers = HttpGetResponseHeaders()
    local total_size = 0

    if not headers then
        return total_size
    end

    for name, value in pairs(headers) do
        -- Each header follows format: "Name: Value\r\n"
        total_size = total_size + string.len(name) + 2 + string.len(value) + 2
    end

    return total_size
end

function calculate_request_body_length()
    local body_chunks, offset, end_marker = HttpGetRequestBody()
    if not body_chunks then
	 return 0
    end

    -- Handle table of chunks
    local total_size = 0
    for i, chunk in ipairs(body_chunks) do
        total_size = total_size + string.len(chunk)
    end

    return total_size
end

function calculate_response_body_length()
    local body_chunks, offset, end_marker = HttpGetResponseBody()
    if not body_chunks then
	 return 0
    end

    -- Handle table of chunks
    local total_size = 0
    for i, chunk in ipairs(body_chunks) do
        total_size = total_size + string.len(chunk)
    end

    return total_size
end

function extract_http_variables()
    local timestring = SCPacketTimeString()
    local timestamp = ""
    if timestring then
        local parsed_time = timestring:match("(%d+/%d+/%d+-%d+:%d+:%d+)")
        if parsed_time then
            timestamp = parsed_time:gsub("(%d+)/(%d+)/(%d+)-", "%3-%1-%2T") .. "Z"
        end
    end

    local ip_version, src_ip, dest_ip, protocol, src_port, dest_port = SCFlowTuple()
    src_ip = src_ip or ""
    dest_ip = dest_ip or ""
    src_port = src_port or ""
    dest_port = dest_port or ""

    local method = HttpGetRequestLine() or ""
    method = method:match("^(%S+)") or ""
    local hostname = HttpGetRequestHost() or ""
    local uri = HttpGetRequestUriRaw() or ""
    local status_line = HttpGetResponseLine() or ""
    local status = status_line:match("HTTP/[%d%.]+%s+(%d+)") or ""

    -- Parse URI to separate path and query
    local uri_path = ""
    local uri_query = ""
    if uri ~= "" then
        local query_start = string.find(uri, "?")
        if query_start then
            uri_path = string.sub(uri, 1, query_start - 1)
            uri_query = string.sub(uri, query_start + 1)
        else
            uri_path = uri
        end
    end

    -- Extract file extension from path
    local file_extension = ""
    if uri_path ~= "" then
        local ext_match = string.match(uri_path, "%.([^./]+)$")
        if ext_match then
            file_extension = ext_match
        end
    end

    -- Get HTTP headers
    local user_agent = HttpGetRequestHeader("User-Agent") or ""
    local accept = HttpGetRequestHeader("Accept") or ""
    local referrer = HttpGetRequestHeader("Referer") or ""
    local x_forwarded_for = HttpGetRequestHeader("X-Forwarded-For") or ""
    local connection = HttpGetRequestHeader("Connection") or ""
    local request_content_type = HttpGetRequestHeader("Content-Type") or ""
    local request_content_length = HttpGetRequestHeader("Content-Length") or ""

    local response_content_type = HttpGetResponseHeader("Content-Type") or ""
    local response_content_length = HttpGetResponseHeader("Content-Length") or ""

    local authorization = HttpGetRequestHeader("Authorization") or ""
    local host = HttpGetRequestHeader("Host") or ""
    local etag = HttpGetResponseHeader("ETag") or ""
    local last_modified = HttpGetResponseHeader("Last-Modified") or ""
    local server = HttpGetResponseHeader("Server") or ""
    local http_accept_language = HttpGetRequestHeader("Accept-Language") or ""
    local location = HttpGetResponseHeader("Location") or ""
    local set_cookie = HttpGetResponseHeader("Set-Cookie") or ""
    local x_forwarded_host = HttpGetRequestHeader("X-Forwarded-Host") or ""
    local x_powered_by = HttpGetResponseHeader("X-Powered-By") or ""

    -- Extract HTTP version from response line
    local version = "HTTP/1.1"
    local response_line = HttpGetResponseLine() or ""
    local version_match = response_line:match("(HTTP/[%d%.]+)")
    if version_match then
        version = version_match
    end

    return {
        timestamp = timestamp,
        src_ip = src_ip,
        dest_ip = dest_ip,
        src_port = src_port,
        dest_port = dest_port,
        method = method,
        hostname = hostname,
        uri_path = uri_path,
        uri_query = uri_query,
        file_extension = file_extension,
        status = status,
        version = version,
        user_agent = user_agent,
        accept = accept,
        referrer = referrer,
        x_forwarded_for = x_forwarded_for,
        connection = connection,
        request_content_type = request_content_type,
        request_content_length = request_content_length,
        response_content_type = response_content_type,
        response_content_length = response_content_length,
        authorization = authorization,
        host = host,
        etag = etag,
        last_modified = last_modified,
        server = server,
        http_accept_language = http_accept_language,
        location = location,
        set_cookie = set_cookie,
        x_forwarded_host = x_forwarded_host,
        x_powered_by = x_powered_by,
    }
end

function calculate_duration()
    local start_sec, last_sec, start_usec, last_usec = SCFlowTimestamps()
    local duration = 0

    if not (start_sec and start_usec and last_sec and last_usec) then
        print("Warning: incomplete timestamp data")
        return 0
    end

    local duration_ms = (last_sec - start_sec) * 1000000 + (last_usec - start_usec)
    local duration = math.floor(duration_ms / 1000)

    if duration < 0 then
	print(string.format("Warning: negative duration %d ms calculated, timestamps may be invalid, %d", duration))
        return 0
    else
	return duration
    end
end

function format_message(vars, request_body_len, response_body_len, req_header_length, res_header_length, duration, raw_request_headers, raw_response_headers, request_body, response_body)
    return string.format(
        'time="%s" src="%s" dest="%s" src_port=%s dest_port=%s ' ..
        'http_method="%s" version="%s" uri_path="%s" ' ..
        'uri_query="%s" file_extension="%s" url_domain="%s" ' ..
        'request_connection="%s" http_user_agent="%s" http_accept="%s" ' ..
        'http_referrer="%s" x_forwarded_for="%s" request_content_type="%s" ' ..
        'request_content_length="%s" bytes_in=%d status="%s" ' ..
        'response_content_type="%s" response_content_length="%s" ' ..
        'authorization="%s" host="%s" etag="%s" last_modified="%s" server="%s" ' ..
        'http_accept_language="%s" location="%s" set_cookie="%s" ' ..
        'x_forwarded_host="%s" x_powered_by="%s" ' ..
        'bytes_out="%s" duration=%d ' ..
        'body_bytes_out="%s" body_bytes_in="%s" ' ..
        'request_header=%s ' .. 
	'response_header=%s ' ..
	'request_body=%s ' ..
	'response_body=%s',
        vars.timestamp, vars.src_ip, vars.dest_ip, vars.src_port, vars.dest_port,
        vars.method, vars.version, vars.uri_path,
        vars.uri_query, vars.file_extension, vars.hostname,
        vars.connection, vars.user_agent, vars.accept,
        vars.referrer, vars.x_forwarded_for, vars.request_content_type,
        vars.request_content_length, count_http_bytes_in_and_bytes_out(req_header_length, request_body_len), vars.status,
        vars.response_content_type, vars.response_content_length,
        vars.authorization, vars.host, vars.etag, vars.last_modified, vars.server,
        vars.http_accept_language, vars.location, vars.set_cookie,
        vars.x_forwarded_host, vars.x_powered_by,
        count_http_bytes_in_and_bytes_out(res_header_length, response_body_len), duration,
        response_body_len, request_body_len,
        raw_request_headers, raw_response_headers,
        request_body, response_body
    )
end

function count_http_bytes_in_and_bytes_out(header_len, body_len)
    if header_len == nil then
        header_len = 0
    end

    if body_len == nil then
        body_len = 0
    end

    return header_len + body_len
end

function getRawRequestHeaders()
    local headers = HttpGetRawRequestHeaders()
    if headers == nil then
        return "{}"
    else
	return json.encode(headers)
    end
end

function getRawResponseHeaders()
    local headers = HttpGetRawResponseHeaders()
    if headers == nil then
        return "{}"
    else
	return json.encode(headers)
    end
end

function template_syslog_message(message)
    local pri = 13 -- facility: user (1) + severity: notice (5) = 1*8+5 = 13
    local datetime = os.date("%b %d %H:%M:%S")
    local hostname = "suricata"
    local app_name = "pcap"
    return string.format(
	"<%d>%s %s %s: %s\n",
	pri, datetime, hostname, app_name, message
    )
end

function retry_establish_tcp_connection()
    print("Start to retry the tcp connection")
    tcp_client = establish_tcp_connection(0)
end

function sendToSyslogServer(syslog_format_message)
    if tcp_client ~= nil then
        local message, err = tcp_client:send(syslog_format_message)
        if err == "closed" or err == "timeout" then
            retry_establish_tcp_connection()
        end
    else
        print("Failed to send the message as the tcp_client is nil")
    end
end

function getRequestBody()
    local body_chunks, offset, end_marker = HttpGetRequestBody()
    
    local body = ""
    if not body_chunks then
	 return json.encode(body)
    end

     -- Handle table of chunks
    for i, chunk in ipairs(body_chunks) do
        if (string.len(body) + string.len(chunk)) > body_max_size then
            --print("Warning: request body size exceeds body_max_size limit")
            body = body .. string.sub(chunk,1,body_max_size-string.len(body))
            break
        end
        body = body .. chunk
    end

    return json.encode(body)
end

function getResponseBody()
    local body_chunks, offset, end_marker = HttpGetResponseBody()
    
    local body = ""
    if not body_chunks then
	 return json.encode(body)
    end

     -- Handle table of chunks
    for i, chunk in ipairs(body_chunks) do
        if (string.len(body) + string.len(chunk)) > body_max_size then
            --print("Warning: response body size exceeds body_max_size limit")
            body = body .. string.sub(chunk,1,body_max_size-string.len(body))
            break
        end
        body = body .. chunk
    end

    return json.encode(body)
end

function log(args)
    local vars = extract_http_variables()
    local duration = calculate_duration()

    local request_body_len = calculate_request_body_length()
    local response_body_len = calculate_response_body_length()
    local req_header_length = calculate_request_headers_size()
    local res_header_length = calculate_response_headers_size()
    local raw_request_headers = getRawRequestHeaders()
    local raw_response_headers = getRawResponseHeaders()
    local request_body = getRequestBody()
    local response_body = getResponseBody()

    local message = format_message(vars, request_body_len, response_body_len, req_header_length, res_header_length, duration, raw_request_headers, raw_response_headers, request_body, response_body)
    --print(message) -- test stage will uncomment this line for the parsing tests

    sendToSyslogServer(template_syslog_message(message))
    --if file then
    --    file:write(message .. "\n")
    --    file:flush()
    --end
end

function deinit (args)
    --if file then
    --    file:close()
    --end

    if tcp_client then
        tcp_client:close()
        print("Info: Closed connection to remote syslog server")
    end
end

