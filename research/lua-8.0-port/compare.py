#!/usr/bin/env python3
"""Compare 7.x and 8.0 http_custom.log field by field.

Values are not quote-escaped (etag holds quotes), so lines are split on the
known keys in their fixed order instead of parsed as key=value pairs.
usage: compare.py CMP_DIR PCAP...
"""
import os
import re
import sys
from collections import Counter

KEYS = ("time src dest src_port dest_port http_method version uri_path uri_query "
        "file_extension url_domain request_connection http_user_agent http_accept "
        "http_referrer x_forwarded_for request_content_type request_content_length "
        "bytes_in status response_content_type response_content_length authorization "
        "host etag last_modified server http_accept_language location set_cookie cookie "
        "x_forwarded_host x_powered_by bytes_out duration body_bytes_out body_bytes_in "
        "x_client_ip x_real_ip").split()


def parse(line):
    pos = []
    start = 0
    for k in KEYS:
        m = re.compile(r'(?:^| )' + k + '=').search(line, start)
        if not m:
            raise ValueError("missing key %s in %r" % (k, line[:120]))
        pos.append((k, m.start(), m.end()))
        start = m.end()
    out = {}
    for i, (k, _, vstart) in enumerate(pos):
        vend = pos[i + 1][1] if i + 1 < len(pos) else len(line)
        v = line[vstart:vend].strip()
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = v[1:-1]
        out[k] = v
    return out


def load(path):
    with open(path) as fh:
        return [parse(l.rstrip("\n")) for l in fh if l.strip()]


cmp_dir = sys.argv[1]
total_tx = 0
identical_tx = 0
diff_fields = Counter()
examples = {}
for pcap in sys.argv[2:]:
    a = load(os.path.join(cmp_dir, "v7", pcap, "http_custom.log"))
    b = load(os.path.join(cmp_dir, "v8", pcap, "http_custom.log"))
    # order by flow and time so both sides line up
    key = lambda r: (r["src_port"], r["time"], r["http_method"], r["uri_path"])
    a.sort(key=key)
    b.sort(key=key)
    if len(a) != len(b):
        print("%s: tx count differs %d vs %d" % (pcap, len(a), len(b)))
    for ra, rb in zip(a, b):
        total_tx += 1
        diffs = [k for k in KEYS if ra[k] != rb[k]]
        if not diffs:
            identical_tx += 1
        for k in diffs:
            diff_fields[k] += 1
            examples.setdefault(k, []).append((pcap, ra["http_method"], ra[k], rb[k]))

print("transactions: %d, identical in every field: %d" % (total_tx, identical_tx))
for k in KEYS:
    if diff_fields[k]:
        print("\n%-24s differs in %d tx" % (k, diff_fields[k]))
        seen = Counter()
        for pcap, method, va, vb in examples[k]:
            sig = (pcap, method, va, vb)
            seen[sig] += 1
        for (pcap, method, va, vb), n in seen.most_common(6):
            print("   %3dx %-18s %-5s 7.x=%-14s 8.0=%s" % (n, pcap, method, va[:60], vb[:60]))
