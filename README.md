# OTS

OpenTimestamps calendar server and SDK written in Go, with Bitcoin anchoring.

Stamps document hashes into the Bitcoin blockchain and produces standard
`.ots` proofs, interoperable with the official
[OpenTimestamps](https://opentimestamps.org) Python client. Verification is
trust-minimized: a confirmed proof checks against Bitcoin block headers, not
against this server's claims.

## Quick start

Requires [Go 1.26+](https://go.dev/) and [just](https://github.com/casey/just).

```bash
just run            # in-memory dev server, no Bitcoin
```

- API: `http://127.0.0.1:14788`
- Swagger UI: `http://127.0.0.1:14788/swagger/index.html`

With Bitcoin anchoring on a disposable regtest chain (requires Docker):

```bash
just regtest-up     # bitcoind regtest + funded wallet
just run-regtest    # server with 5s anchoring, 1 confirmation
just regtest-mine   # confirm pending anchors
```

## Tasks

```bash
just                # list recipes
just run            # dev server (in-memory)
just run-persistent # server with data dir ~/.otsd/calendar
just test           # unit + e2e tests
just test-all       # incl. regtest integration (needs regtest-up)
just cross-validate # wire-format check against python-opentimestamps
just swagger        # regenerate OpenAPI docs
just check          # tidy + swagger + test
```

## How it works

```
client digest ──► aggregator (1s merkle batch) ──► calendar commitment
                                                    │  (journal + bbolt, fsync)
                                                    ▼
                                            Bitcoin stamper
                                     batches commitments ──► OP_RETURN tx
                                                    │
                                     after N confirmations:
                                     block merkle proof + attestation
                                                    ▼
                          .ots proof: digest ─ops─► Bitcoin block merkle root
```

A proof starts **pending** (calendar receipt) and becomes **confirmed** once
its anchor transaction is buried under `--btc-min-confirmations` blocks. Only
confirmed proofs verify as `valid`. See
[docs/COMPLIANCE.md](docs/COMPLIANCE.md) for what each stage proves and the
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
| `POST` | `/api/v1/verify` | Verify digest + proof against Bitcoin headers |
| `POST` | `/api/v1/stamp-file` | Multipart file upload → detached `.ots` proof |
| `POST` | `/api/v1/verify-file` | Multipart file + `.ots` → verification result |
| `GET` | `/api/v1/status` | Pending count, unconfirmed txs, wallet balance, height |
| `GET` | `/api/v1/health` | Health incl. Bitcoin RPC reachability |

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
   Store the returned `.ots` bytes next to your document. The server keeps
   only the hash.
2. **Poll**: `POST /api/v1/upgrade` with the proof until `"complete": true`.
   Recommended interval: **30–60 minutes**. Anchoring batches every
   `--btc-min-tx-interval` (default 6h) and needs 6 confirmations (~1h), so
   expect **up to ~8 hours** on defaults; faster polling buys nothing.
   Persist the upgraded proof — it now verifies offline, forever.
3. **Verify**: `POST /api/v1/verify-file` (or verify independently — see
   [docs/COMPLIANCE.md](docs/COMPLIANCE.md)). Treat `"valid": false` with
   `"status": "pending"` as *not yet evidence*, and `"invalid"` as an alarm.

Error handling: the native `GET /timestamp/{hex}` returns 404 with body
`"Pending confirmation in Bitcoin blockchain"` while anchoring is in
progress, and `"Commitment not found"` for unknown digests.

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
    client := ots.NewClient("http://127.0.0.1:14788")

    // Stamp a file → detached .ots proof
    f, _ := os.Open("contract.pdf")
    det, err := ots.StampFile(ctx, client, f)
    f.Close()
    if err != nil {
        log.Fatal(err)
    }
    proofBytes, _ := det.SerializeBytes()
    os.WriteFile("contract.pdf.ots", proofBytes, 0o644)

    // Block until the proof is Bitcoin-confirmed (bound it with a timeout)
    waitCtx, cancel := context.WithTimeout(ctx, 12*time.Hour)
    defer cancel()
    if err := ots.UpgradeUntilConfirmed(waitCtx, client, det.Timestamp, time.Minute); err != nil {
        log.Fatal(err)
    }

    // Verify against your own Bitcoin node — no trust in the calendar
    headers, _ := ots.BitcoinRPCHeaderSource("127.0.0.1:8332", "user", "pass", "mainnet")
    result, _ := ots.VerifyFile(ctx, client, headers, "contract.pdf", "contract.pdf.ots")
    fmt.Printf("valid=%v at %s (block %d)\n", result.Valid, result.VerifiedAt, result.BlockHeight)
}
```

## Production deployment

```bash
BTC_RPC_PASS=change-me OTS_CALENDAR_URI=https://cal.example.com docker compose up -d
```

The compose file runs a pruned Bitcoin Core node on an internal network — the
RPC port is never exposed. Put a TLS reverse proxy in front of port 14788.

Server flags:

```
-addr                    listen address (default :14788)
-calendar-uri            public URI embedded in proofs (persisted on first boot)
-data-dir                calendar state (default ~/.otsd/calendar; "memory" for dev)
-log-json                structured JSON logs
-btc-rpc-host/user/pass  Bitcoin Core RPC (host empty = stamper disabled)
-btc-network             mainnet | testnet | regtest (checked against the node)
-btc-min-confirmations   default 6
-btc-min-tx-interval     anchor batching interval, default 6h
-btc-max-fee             max anchor tx fee in BTC, default 0.001
-max-pending             stamper pool bound, default 100000
```

Operational notes:

- **Backup** = the data dir: `journal`, `db/`, `hmac-key`, `uri`. See
  [docs/COMPLIANCE.md](docs/COMPLIANCE.md#backup-and-restore).
- **Wallet**: keep a small fee balance; `GET /api/v1/status` reports it.
- **Restarts** are safe at any point: the journal is fsync'd before any
  response is returned, and the stamper re-queues unanchored commitments on
  boot. Reorged/conflicted anchor transactions are re-queued automatically.
- **Network isolation**: the server aborts on startup if the node's chain
  does not match `-btc-network`, preventing testnet proofs from a mainnet
  calendar.

## Architecture

```
cmd/server          HTTP server (stdlib net/http + swaggo)
api/server          Route handlers (native OTS + JSON + file API)
internal/core       OTS protocol (serialize, ops, attestations, timestamps)
internal/calendar   Aggregator, journal, bbolt store, data dir
internal/stamper    Bitcoin OP_RETURN anchoring + confirmation tracking
internal/bitcoin    Bitcoin Core RPC, block proofs, header source
internal/verify     Fail-closed proof verification
pkg/ots             Public SDK (stamp, upgrade, verify)
```

Cross-client compatibility is exercised in CI-style tests: real mainnet
proof vectors from `opentimestamps-client` verify in Go, and
`scripts/cross-validate.sh` round-trips proofs with the Python client.

## License

Licensed under the [GNU Lesser General Public License v3.0 or later](LICENSE)
(LGPL-3.0+).

This matches the license of the upstream OpenTimestamps reference
implementations from which portions of this project are derived. See
[NOTICE](NOTICE) for attribution details.

### Source file headers

Files ported from upstream should include a header like:

```
// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// It is subject to the license terms in the LICENSE file found in the top-level
// directory of this distribution.
//
// Portions derived from <upstream-repo>/<path> (LGPL-3.0+).
```
