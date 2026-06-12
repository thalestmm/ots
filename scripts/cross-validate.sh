#!/usr/bin/env bash
# Cross-validate the Go server's wire format against the official Python
# OpenTimestamps client. Requires uv (https://docs.astral.sh/uv/) and a
# running relay: just run    (or any instance on $OTS_URL; needs network for upstream calendars)
set -euo pipefail

OTS_URL="${OTS_URL:-http://127.0.0.1:14788}"
OTS_PY=(uvx --from opentimestamps-client ots)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> server: $OTS_URL"
curl -sf "$OTS_URL/api/v1/health" > /dev/null || { echo "server not reachable"; exit 1; }

echo "==> relay stamps file via /api/v1/stamp-file"
echo "cross-validation $(date)" > "$WORK/doc.txt"
curl -sf -F "file=@$WORK/doc.txt" "$OTS_URL/api/v1/stamp-file" -o "$WORK/doc.txt.ots"
test -f "$WORK/doc.txt.ots"

echo "==> python client parses relay-served proof"
"${OTS_PY[@]}" info "$WORK/doc.txt.ots" > /dev/null

echo "==> relay JSON stamp, python client parses the .ots"
DIGEST=$(shasum -a 256 "$WORK/doc.txt" | awk '{print $1}')
PROOF=$(curl -sf -X POST "$OTS_URL/api/v1/timestamps" \
  -H "Content-Type: application/json" \
  -d "{\"digest\":\"$DIGEST\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["proof"])')
python3 -c "import binascii; open('$WORK/go-stamped.ots','wb').write(binascii.unhexlify('$PROOF'))"
"${OTS_PY[@]}" info "$WORK/go-stamped.ots" > /dev/null

echo "==> relay upgrade endpoint round-trips"
UPGRADE=$(curl -sf -X POST "$OTS_URL/api/v1/upgrade" \
  -H "Content-Type: application/json" \
  -d "{\"digest\":\"$DIGEST\",\"proof\":\"$PROOF\"}")
echo "$UPGRADE" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert "proof" in d'

echo "OK: wire format cross-validated against python-opentimestamps"
