#!/bin/sh
# Triggers Bug #6874: one TCP keepalive connection carries a >1MB POST,
# then many small GETs on the same connection. With depth=1mb the GETs
# should hit /libhtp::request_uri_not_seen and produce garbled tx->request_line.
set -e

NGINX="${NGINX:-172.30.0.10}"
NUM_GETS="${NUM_GETS:-50}"
POST_MB="${POST_MB:-2}"

PAYLOAD=/tmp/big.bin
dd if=/dev/zero of="$PAYLOAD" bs=1M count="$POST_MB" status=none

# Build a curl multi-request invocation. --next starts a new request
# but the connection is reused for the same host on HTTP/1.1.
ARGS="--silent --output /dev/null --http1.1 --keepalive-time 300"
ARGS="$ARGS -X POST --data-binary @$PAYLOAD http://$NGINX/upload"
i=1
while [ $i -le "$NUM_GETS" ]; do
    ARGS="$ARGS --next --silent --output /dev/null http://$NGINX/path$i"
    i=$((i + 1))
done

echo "[gen] POST ${POST_MB}MB + ${NUM_GETS} GETs on one connection to $NGINX"
# shellcheck disable=SC2086
curl $ARGS
echo "[gen] done"
