# OTS

OpenTimestamps relay API and SDK written in Go.

Stamps document hashes via **public upstream calendars** (alice.btc, bob.btc, etc.)
and returns standard `.ots` proofs, interoperable with the official
[OpenTimestamps](https://opentimestamps.org) Python client. No Bitcoin node
required to stamp or upgrade — upstream calendars handle anchoring.

## Quick start

Requires [Go 1.26+](https://go.dev/) and [just](https://github.com/casey/just).

```bash
just run            # relay on :14788, default public calendars
```

- API: `http://127.0.0.1:14788`
- Swagger UI: `http://127.0.0.1:14788/swagger/index.html`

With Docker (no Bitcoin node):

```bash
docker compose up -d
```

## Tasks

```bash
just                # list recipes
just run            # relay API (public upstream calendars)
just run-calendars "https://alice.btc.calendar.opentimestamps.org"  # custom upstreams
just build          # relay binary → bin/ots-server
just build-calendar # self-hosted calendar binary → bin/ots-calendar
just test           # unit + e2e tests
just calendar-run   # self-hosted calendar (dev, in-memory)
just swagger        # regenerate OpenAPI docs
just check          # tidy + swagger + test
```

## How it works

```
client digest ──► relay API ──► upstream calendars (parallel)
                                      │
                                      ▼
                              pending .ots proof (merged)
                                      │
                         poll upgrade until complete
                                      ▼
                    confirmed .ots (Bitcoin attestation)
```

The relay fans out each stamp to multiple public calendars and merges the
returned proofs. Upgrade resolves pending attestations against the correct
upstream calendar (by URI embedded in each attestation). Verification of
confirmed proofs requires a Bitcoin header source (`-btc-rpc-*` or your own
node via the SDK).

See [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for proof semantics and the
threat model.

## API

### OTS-native (binary, python-client compatible)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/digest` | Submit raw digest bytes (max 64), returns OTS proof |
| `GET` | `/timestamp/{hex}` | Fetch upgraded proof for a commitment |

### JSON / file API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/timestamps` | Create timestamp from hex digest |
| `POST` | `/api/v1/upgrade` | Resolve pending attestations, return upgraded proof |
| `POST` | `/api/v1/verify` | Verify digest + proof (needs `-btc-rpc-*` for `valid=true`) |
| `POST` | `/api/v1/stamp-file` | Multipart file upload → detached `.ots` proof |
| `POST` | `/api/v1/verify-file` | Multipart file + `.ots` → verification result |
| `GET` | `/api/v1/status` | Upstream calendar reachability |
| `GET` | `/api/v1/health` | Health incl. upstream calendar status |

### Verify response

```json
{
  "valid": true,
  "status": "confirmed",
  "verified_at": "2026-06-12T14:58:30Z",
  "block_height": 850000,
  "block_hash": "00000000000000000002...",
  "attestations": [
    {"kind": "bitcoin", "status": "confirmed", "detail": "height=850000 ..."}
  ]
}
```

`status` is one of `confirmed`, `pending`, `invalid`, `unverified`.
`valid` is `true` **only** when a Bitcoin attestation was cryptographically
checked against a block header (fail closed).

## Integration guide

Typical compliance flow:

1. **Stamp**: `POST /api/v1/stamp-file` (or hash locally and `POST /digest`).
   Store the returned `.ots` bytes next to your document.
2. **Poll**: `POST /api/v1/upgrade` with the proof until `"complete": true`.
   Recommended interval: **30–60 minutes**. Upstream calendars anchor on
   their own schedule; expect **several hours** on mainnet.
   Persist the upgraded proof — it verifies offline, forever.
3. **Verify**: independently with your own Bitcoin node — see
   [docs/COMPLIANCE.md](docs/COMPLIANCE.md). Treat `"valid": false` with
   `"status": "pending"` as *not yet evidence*.

### SDK

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/thalestmm/ots/pkg/ots"
)

func main() {
    ctx := context.Background()
    client := ots.NewClient("https://alice.btc.calendar.opentimestamps.org")

    f, _ := os.Open("contract.pdf")
    det, err := ots.StampFile(ctx, client, f)
    f.Close()
    if err != nil {
        log.Fatal(err)
    }
    proofBytes, _ := det.SerializeBytes()
    os.WriteFile("contract.pdf.ots", proofBytes, 0o644)

    waitCtx, cancel := context.WithTimeout(ctx, 12*time.Hour)
    defer cancel()
    if err := ots.UpgradeUntilConfirmed(waitCtx, client, det.Timestamp, time.Minute); err != nil {
        log.Fatal(err)
    }

    headers, _ := ots.BitcoinRPCHeaderSource("127.0.0.1:8332", "user", "pass", "mainnet")
    result, _ := ots.VerifyFile(ctx, client, headers, "contract.pdf", "contract.pdf.ots")
    fmt.Printf("valid=%v at %s (block %d)\n", result.Valid, result.VerifiedAt, result.BlockHeight)
}
```

Or use the relay HTTP API directly — no SDK required.

## Deployment

```bash
docker compose up -d
```

Relay server flags:

```
-addr                listen address (default :14788)
-calendars           comma-separated upstream URLs (default: public mainnet calendars)
-calendar-timeout    per-upstream HTTP timeout (default 30s)
-log-json             structured JSON logs
-btc-rpc-host/user/pass/network   optional; enables confirmed verify on /api/v1/verify
```

Environment:

| Variable | Purpose |
|----------|---------|
| `OTS_CALENDARS` | Comma-separated upstream calendar URLs |

Default upstream calendars:

- `https://alice.btc.calendar.opentimestamps.org`
- `https://bob.btc.calendar.opentimestamps.org`
- `https://finney.calendar.eternitywall.com`

Put a TLS reverse proxy in front of port 14788 for public exposure.

## Self-hosted calendar (optional)

The original calendar server with Bitcoin anchoring is still available for
operators who want to run their own calendar:

```bash
just build-calendar
just calendar-run-persistent   # or deploy/calendar/docker-compose.yml
```

See [deploy/calendar/docker-compose.yml](deploy/calendar/docker-compose.yml).

## Architecture

```
cmd/server          Relay HTTP API (default)
cmd/calendar        Self-hosted calendar server (optional)
api/server          Relay route handlers
api/calendarserver  Calendar server handlers (optional binary)
internal/core       OTS protocol (serialize, ops, attestations, timestamps)
internal/calendar   Calendar server internals
internal/stamper    Bitcoin OP_RETURN anchoring
internal/bitcoin    Bitcoin Core RPC, block proofs, header source
internal/verify     Fail-closed proof verification
pkg/ots             Public SDK + multi-calendar Pool client
```

## License

Licensed under the [GNU Lesser General Public License v3.0 or later](LICENSE)
(LGPL-3.0+). See [NOTICE](NOTICE) for upstream attribution.
