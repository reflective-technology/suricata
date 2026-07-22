#!/usr/bin/env python3
"""Trigger Bug #6874: one keepalive connection carries a >1MB POST, then
many small GETs on the same connection. requests.Session reuses the
underlying urllib3 HTTPConnection, so all requests share one TCP."""
import os
import sys
import requests
from requests.adapters import HTTPAdapter

NGINX = os.environ.get("NGINX", "172.30.0.10")
NUM_GETS = int(os.environ.get("NUM_GETS", "50"))
POST_MB = int(os.environ.get("POST_MB", "2"))

# Force pool_maxsize=1 so we get exactly one underlying TCP connection.
sess = requests.Session()
sess.mount("http://", HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0))

payload = b"\x00" * (POST_MB * 1024 * 1024)
print(f"[gen] POST {POST_MB}MB to http://{NGINX}/upload", flush=True)
r = sess.post(f"http://{NGINX}/upload", data=payload, headers={"Connection": "keep-alive"})
print(f"[gen] POST -> {r.status_code}", flush=True)

success = 0
for i in range(1, NUM_GETS + 1):
    r = sess.get(f"http://{NGINX}/path{i}", headers={"Connection": "keep-alive"})
    if r.status_code == 200:
        success += 1
print(f"[gen] GETs completed: {success}/{NUM_GETS}", flush=True)
sess.close()
