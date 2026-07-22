#!/usr/bin/env python3
"""Trigger Bug #6874 via cumulative POSTs on one keepalive TCP connection.
N small POSTs avoid the TSO/GRO artifacts a single huge POST creates, while
their summed bytes still exceed stream.reassembly.depth."""
import os
import requests
from requests.adapters import HTTPAdapter

NGINX = os.environ.get("NGINX", "172.30.0.10")
NUM_POSTS = int(os.environ.get("NUM_POSTS", "11"))
POST_KB = int(os.environ.get("POST_KB", "1024"))  # per POST body size
NUM_GETS = int(os.environ.get("NUM_GETS", "20"))

sess = requests.Session()
sess.mount("http://", HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0))

payload = b"\x00" * (POST_KB * 1024)
total_mb = (NUM_POSTS * POST_KB * 1024) / (1024 * 1024)
print(f"[gen] {NUM_POSTS} POSTs x {POST_KB}KB ({total_mb:.1f}MB total) + {NUM_GETS} GETs on one keepalive conn to {NGINX}", flush=True)

for i in range(1, NUM_POSTS + 1):
    r = sess.post(f"http://{NGINX}/upload{i}", data=payload,
                  headers={"Connection": "keep-alive"})
    if r.status_code != 200:
        print(f"[gen] POST {i} status {r.status_code}!", flush=True)
print(f"[gen] {NUM_POSTS} POSTs done", flush=True)

for i in range(1, NUM_GETS + 1):
    sess.get(f"http://{NGINX}/path{i}", headers={"Connection": "keep-alive"})
print(f"[gen] {NUM_GETS} GETs done", flush=True)
sess.close()
