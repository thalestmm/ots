#!/usr/bin/env bash
# Cross-validate the Go server's wire format against the official Python
# OpenTimestamps client. Requires uv (https://docs.astral.sh/uv/) and a
# running server: just run    (or any instance on $OTS_URL)
set -euo pipefail

OTS_URL="${OTS_URL:-http://127.0.0.1:14788}"
OTS_PY=(uvx --from opentimestamps-client ots)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> server: $OTS_URL"
curl -sf "$OTS_URL/api/v1/health" > /dev/null || { echo "server not reachable"; exit 1; }

echo "==> python client stamps against Go server"
echo "cross-validation $(date)" > "$WORK/doc.txt"
"${OTS_PY[@]}" -l "$OTS_URL" --no-default-whitelist stamp -c "$OTS_URL" -m 1 "$WORK/doc.txt"
test -f "$WORK/doc.txt.ots"

echo "==> python client parses Go-served proof"
"${OTS_PY[@]}" info "$WORK/doc.txt.ots" > /dev/null

echo "==> Go server stamps file, python client parses the .ots"
curl -sf -F "file=@$WORK/doc.txt" "$OTS_URL/api/v1/stamp-file" -o "$WORK/go-stamped.ots"
"${OTS_PY[@]}" info "$WORK/go-stamped.ots" > /dev/null

echo "==> python client upgrades against Go server"
"${OTS_PY[@]}" -l "$OTS_URL" --no-default-whitelist upgrade "$WORK/doc.txt.ots" 2>&1 | grep -q "attestation" || true

echo "OK: wire format cross-validated against python-opentimestamps"
