#!/usr/bin/env python3
"""Checks Suricata EVE http events against a target's http.log (the KV line the
former Lua output produced, kept as the expected values).

Usage: check_eve.py <eve.json> <http.log>
"""
import json
import re
import sys

KV = re.compile(r'(\w+)=("(?:[^"]|"(?=[^ ]))*"|\S+)')
FIELDS = {  # http.log key -> function(eve http event) -> value
    "http_method": lambda h, r: h.get("http_method", ""),
    "url_domain": lambda h, r: h.get("hostname", ""),
    "uri_path": lambda h, r: h.get("url", "").split("?", 1)[0],
    "uri_query": lambda h, r: h.get("url", "").split("?", 1)[1] if "?" in h.get("url", "") else "",
    "status": lambda h, r: str(h.get("status", "")),
    "http_user_agent": lambda h, r: h.get("http_user_agent", ""),
    "response_content_type": lambda h, r: r.get("content-type", h.get("http_content_type", "")),
    "response_content_length": lambda h, r: r.get("content-length", ""),
}


def expected(path):
    for line in open(path):
        d = {k: v[1:-1] if v.startswith('"') and v.endswith('"') else v for k, v in KV.findall(line)}
        if d.get("http_method"):
            yield d


def main():
    eve = [json.loads(l) for l in open(sys.argv[1]) if '"event_type":"http"' in l]
    exp = list(expected(sys.argv[2]))
    if len(eve) != len(exp):
        print(f"FAIL: {len(eve)} EVE http events, expected {len(exp)}")
        return 1
    bad = 0
    for e, x in zip(eve, exp):
        h = e["http"]
        res = {i["name"].lower(): i["value"] for i in h.get("response_headers", [])}
        for k, f in FIELDS.items():
            got = f(h, res)
            if got != x.get(k, ""):
                print(f"FAIL: {k}: got {got!r}, expected {x.get(k)!r}")
                bad += 1
    if bad:
        return 1
    print(f"OK: {len(eve)} transaction(s), {len(FIELDS)} fields each")
    return 0


if __name__ == "__main__":
    sys.exit(main())
