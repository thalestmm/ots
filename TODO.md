# OTS Phase 2 — Trust-Minimized Timestamps for Compliance

**Status: implemented.** This document tracked the work to move OTS from a
calendar-only v1 to a production-grade timestamp service. The workstreams
below are done; remaining follow-ups are listed at the end.

## Current state

| Capability | Status |
|------------|--------|
| OTS wire-format create (`POST /digest`) | Done |
| JSON create / verify API | Done |
| Calendar HMAC + `PendingAttestation` | Done |
| Aggregator (1s batch merkle) | Done |
| Persistent journal + bbolt commitment DB (`--data-dir`) | Done |
| Startup recovery (journal replay → stamper pool) | Done |
| Bitcoin OP_RETURN stamper (batching, confirmations, reorg re-queue) | Done |
| Block inclusion proofs (`cat_sha256d`, Satoshi odd-leaf duplication) | Done |
| `BitcoinBlockHeaderAttestation` verification (fail closed) | Done |
| `.ots` detached file API (`stamp-file`, `verify-file`) | Done |
| Upgrade flow (`/api/v1/upgrade`, SDK `UpgradeUntilConfirmed`) | Done |
| Status + health endpoints (wallet, height, pending) | Done |
| Public SDK (`pkg/ots`): stamp, upgrade, verify, header source | Done |
| Structured logging (`-log-json`) for stamp/anchor/confirm | Done |
| Graceful shutdown (drain aggregator, flush journal) | Done |
| Network isolation (node chain checked against `-btc-network`) | Done |
| Docker image + compose with pruned bitcoind | Done |
| `docs/COMPLIANCE.md` (proof semantics, threat model, retention) | Done |
| Swagger for full API surface | Done |

## Verification evidence (2026-06-12)

- All unit + e2e tests pass (`go test ./...`): journal crash recovery, bbolt
  merge, block-proof construction, fail-closed verify, API round trips.
- Real mainnet vector: `opentimestamps-client` `hello-world.txt.ots`
  (block 358391) verifies cryptographically in Go
  (`internal/verify/vector_test.go`).
- Regtest integration (`TestRegtestEndToEnd`, gated on
  `OTS_REGTEST_RPC_HOST`): journal → OP_RETURN → mined → proof verified
  against real bitcoind.
- Cross-client: Python `ots stamp`/`upgrade` against the Go server ends in
  **"Success! Timestamp complete"**, and Python `ots verify --bitcoin-node`
  accepts the Go-anchored proof: *"Success! Bitcoin block 105 attests
  existence"*. Reverse direction (Go parses/verifies Python proofs) covered
  by the vector test. Script: `scripts/cross-validate.sh`.
- Restart acceptance: server restarted mid-flow; commitments, hmac-key, and
  URI persisted; `verify-file` returned `confirmed` after restart.

## Remaining follow-ups (not blocking)

- [ ] Automatic RBF fee-bumping for stuck anchor txs (txs are sent
      replaceable; bumping is currently manual via `bitcoin-cli bumpfee`)
- [ ] CI workflow wiring (`just test-all` + `scripts/cross-validate.sh`
      exist; no `.github/workflows` yet)
- [ ] Optional `ots-cli` binary (stamp/upgrade/verify from the shell via
      `pkg/ots`)
- [ ] Rate limiting / authentication for public deployments

## Out of scope (future phases)

- Litecoin / Ethereum attestations
- Multi-calendar aggregation pools (a.pool-style)
- Multi-tenancy
- HA / horizontal scaling (single calendar instance per data-dir)
- HSM for `hmac-key` and wallet keys

## Reference implementations ported from

- [`opentimestamps-server/otsserver/calendar.py`](https://github.com/opentimestamps/opentimestamps-server/blob/master/otsserver/calendar.py) — journal, storage, aggregator
- [`opentimestamps-server/otsserver/stamper.py`](https://github.com/opentimestamps/opentimestamps-server/blob/master/otsserver/stamper.py) — Bitcoin anchoring
- [`python-opentimestamps/opentimestamps/bitcoin.py`](https://github.com/opentimestamps/python-opentimestamps/blob/master/opentimestamps/bitcoin.py) — block proof construction
- [`opentimestamps-client/otsclient/cmds.py`](https://github.com/opentimestamps/opentimestamps-client/blob/master/otsclient/cmds.py) — upgrade + verify flows

> Do not deploy to compliance customers on mainnet with
> `--btc-min-confirmations` below 6. See `docs/COMPLIANCE.md`.
