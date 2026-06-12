# OTS — Relay API

**Status: relay refactor complete.** The default binary is a stateless HTTP
relay that stamps and upgrades via public upstream calendars.

## Current state

| Capability | Status |
|------------|--------|
| Multi-calendar relay (`pkg/ots/pool.go`) | Done |
| URI-aware upgrade (`internal/verify`) | Done |
| Relay HTTP API (`cmd/server`, `api/server`) | Done |
| Optional Bitcoin verify (`-btc-rpc-*`) | Done |
| Self-hosted calendar binary (`cmd/calendar`) | Done |
| Public SDK (`pkg/ots`): stamp, upgrade, verify, pool | Done |
| Docker relay deployment (no bitcoind) | Done |
| `docs/COMPLIANCE.md` | Done |
| Swagger for relay API | Done |

## Remaining follow-ups

- [ ] Rate limiting / authentication for public relay deployments
- [ ] CI workflow wiring (`just test` + optional integration test)
- [ ] Optional `ots-cli` binary (stamp/upgrade/verify from the shell)
- [ ] Gated live integration test (`OTS_INTEGRATION=1`) against real public calendars
- [ ] Automatic RBF fee-bumping for calendar server anchor txs

## Self-hosted calendar (cmd/calendar)

The calendar server with Bitcoin anchoring remains available under
`cmd/calendar` and `deploy/calendar/docker-compose.yml` for operators who
want to run their own calendar instead of using public upstreams.

## Reference implementations ported from

- [`opentimestamps-server`](https://github.com/opentimestamps/opentimestamps-server) — calendar + stamper
- [`python-opentimestamps`](https://github.com/opentimestamps/python-opentimestamps) — block proofs
- [`opentimestamps-client`](https://github.com/opentimestamps/opentimestamps-client) — upgrade + verify flows
