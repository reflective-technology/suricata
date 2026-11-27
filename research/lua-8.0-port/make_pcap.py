#!/usr/bin/env python3
"""Synthetic HTTP/1.1 sessions for the 7.x vs 8.0 Lua comparison.

Each case is its own TCP connection: handshake, request, response, FIN.
usage: make_pcap.py OUT.pcap
"""
import sys
from scapy.all import IP, TCP, Ether, wrpcap

CLIENT, SERVER = "10.1.0.10", "10.1.0.20"

CASES = [
    # sensitive headers, client-ip headers, many response headers
    (b"GET /account/profile.php?id=7 HTTP/1.1\r\nHost: shop.example\r\n"
     b"User-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Language: zh-TW,en;q=0.8\r\n"
     b"Authorization: Bearer abc.def.ghi\r\nCookie: sid=s3cr3t; theme=dark\r\n"
     b"X-Client-IP: 203.0.113.5\r\nX-Real-IP: 198.51.100.7\r\nX-Forwarded-Host: shop.example\r\n"
     b"Referer: https://shop.example/\r\nConnection: keep-alive\r\n\r\n",
     b"HTTP/1.1 302 Found\r\nServer: nginx/1.25\r\nX-Powered-By: PHP/8.2\r\n"
     b"Location: /login\r\nSet-Cookie: sid=newsecret; HttpOnly\r\n"
     b"Last-Modified: Wed, 01 Jan 2025 00:00:00 GMT\r\nETag: \"abc123\"\r\n"
     b"Content-Type: text/html\r\nContent-Length: 5\r\n\r\nmoved"),
    # space inside the URI (8.0 upgrade notes: parsed differently)
    (b"GET /a b HTTP/1.1\r\nHost: shop.example\r\nUser-Agent: curl/8\r\n\r\n",
     b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\n\r\nbad"),
    # POST with a body, a token in the query and a duplicated header
    (b"POST /api/login?token=abc&next=/home HTTP/1.1\r\nHost: api.example\r\n"
     b"Content-Type: application/json\r\nContent-Length: 27\r\n"
     b"X-Forwarded-For: 192.0.2.1\r\nX-Forwarded-For: 192.0.2.2\r\n\r\n"
     b'{"user":"a","pass":"b1234"}',
     b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}"),
    # chunked response with a quote and a tab in a header value
    (b"GET /download/report.csv HTTP/1.1\r\nHost: files.example\r\nUser-Agent: x\"y\tz\r\n\r\n",
     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/csv\r\n\r\n"
     b"5\r\na,b,c\r\n6\r\n\n1,2,3\r\n0\r\n\r\n"),
    # header without a space after the colon, lower-case names, HTTP/1.0
    (b"GET /plain HTTP/1.0\r\nhost:legacy.example\r\nuser-agent:old\r\n\r\n",
     b"HTTP/1.0 200 OK\r\ncontent-type:text/plain\r\ncontent-length:2\r\n\r\nhi"),
]


def session(sport, request, response, t0):
    pkts = []
    t = [t0]

    def add(src, dst, sp, dp, flags, seq, ack, payload=b""):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack) / payload
        p.time = t[0]
        t[0] += 0.001
        pkts.append(p)

    c, s = 1000, 5000
    add(CLIENT, SERVER, sport, 80, "S", c, 0); c += 1
    add(SERVER, CLIENT, 80, sport, "SA", s, c); s += 1
    add(CLIENT, SERVER, sport, 80, "A", c, s)
    add(CLIENT, SERVER, sport, 80, "PA", c, s, request); c += len(request)
    add(SERVER, CLIENT, 80, sport, "A", s, c)
    add(SERVER, CLIENT, 80, sport, "PA", s, c, response); s += len(response)
    add(CLIENT, SERVER, sport, 80, "A", c, s)
    add(CLIENT, SERVER, sport, 80, "FA", c, s); c += 1
    add(SERVER, CLIENT, 80, sport, "FA", s, c); s += 1
    add(CLIENT, SERVER, sport, 80, "A", c, s)
    return pkts


pkts = []
for i, (req, resp) in enumerate(CASES):
    pkts += session(40000 + i, req, resp, 1767225600 + i)
wrpcap(sys.argv[1], pkts)
print("wrote %d packets, %d sessions" % (len(pkts), len(CASES)))
