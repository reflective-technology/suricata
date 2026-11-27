#!/usr/bin/env bash
# Run each pcap through Suricata 7.x with the 7.x http_custom.lua and through
# Suricata 8.0 with http_custom_8.0.lua, then compare the messages field by field.
#
#   ./run-comparison.sh [pcap...]          # default: edge.pcap
#   RAW_CAPTURE=true ./run-comparison.sh   # also compare the raw-capture fragment
#
# The 7.x script is taken from git (V7_REF:configs/http_custom.lua) and gets
# v7-file-output.lua appended so it writes to a file instead of TCP syslog.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_7="${IMAGE_7:-public.ecr.aws/zuin/cybereyes/suricata:7.0.19}"
IMAGE_8="${IMAGE_8:-public.ecr.aws/zuin/cybereyes/suricata:8.0.7-rc8}"
V7_REF="${V7_REF:-origin/main}"
RAW_CAPTURE="${RAW_CAPTURE:-false}"
OUT="${OUT:-$HERE/results}"

[ $# -gt 0 ] || set -- "$HERE/edge.pcap"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/v7" "$work/v8"
git -C "$HERE" show "$V7_REF:configs/http_custom.lua" > "$work/v7/http_custom.lua"
cat "$HERE/v7-file-output.lua" >> "$work/v7/http_custom.lua"
cp "$HERE/http_custom_8.0.lua" "$work/v8/http_custom.lua"

# tests/target/<case>/capture.pcap is named after its directory
pcap_name() {
  local name
  name="$(basename "$1" .pcap)"
  [ "$name" = "capture" ] && name="$(basename "$(dirname "$1")")"
  echo "$name"
}

run() { # side image pcap
  local side="$1" image="$2" pcap="$3" name
  name="$(pcap_name "$pcap")"
  docker rm -f lua-parity >/dev/null 2>&1 || true
  # Output goes to the container and is copied out: no bind mount of the output dir
  docker run --name lua-parity -e ENABLE_RAW_CAPTURE="$RAW_CAPTURE" \
    -v "$HERE/compare.yaml:/m.yaml:ro" -v "$work/$side:/s:ro" -v "$pcap:/p.pcap:ro" \
    --entrypoint sh "$image" \
    -c 'suricata -c /m.yaml -r /p.pcap -k none --runmode single > /var/log/suricata/console.txt 2>&1; echo "exit=$?" >> /var/log/suricata/console.txt' >/dev/null
  rm -rf "${OUT:?}/$side/$name"
  mkdir -p "$OUT/$side"
  docker cp -q lua-parity:/var/log/suricata "$OUT/$side/$name"
  docker rm lua-parity >/dev/null
  if grep -qiE "failed to run|error" "$OUT/$side/$name/console.txt"; then
    echo "$side $name: Lua or engine errors, see $OUT/$side/$name/console.txt" >&2
  fi
}

names=()
for pcap in "$@"; do
  pcap="$(cd "$(dirname "$pcap")" && pwd)/$(basename "$pcap")"
  run v7 "$IMAGE_7" "$pcap"
  run v8 "$IMAGE_8" "$pcap"
  names+=("$(pcap_name "$pcap")")
done

echo "7.x: $(docker run --rm --entrypoint suricata "$IMAGE_7" -V)"
echo "8.0: $(docker run --rm --entrypoint suricata "$IMAGE_8" -V)"
python3 -I "$HERE/compare.py" "$OUT" "${names[@]}"
if [ "$RAW_CAPTURE" = "true" ]; then
  for name in "${names[@]}"; do
    n="$(diff <(sort "$OUT/v7/$name/http_custom.log") <(sort "$OUT/v8/$name/http_custom.log") | grep -c '^<' || true)"
    echo "raw capture $name: $n line(s) differ"
  done
fi
