# OTS Compliance Guide

Plain-language explanation of what an OTS timestamp proves, for legal,
audit, and compliance reviewers. No cryptography background assumed.

## What a timestamp proves, at each stage

An `.ots` proof moves through two states. **They prove different things.**

### Stage 1 — Pending (calendar receipt)

Immediately after stamping, the proof contains a *pending attestation*: a
signed-path commitment showing this calendar server received your document's
hash at a claimed time.

**What it proves:** the calendar operator claims to have seen the hash.

**What you must trust:** the calendar operator — their clock, their honesty,
their continued existence. A pending proof is a **receipt, not evidence**.

Verification of a pending proof returns `"valid": false, "status": "pending"`
by design. This is fail-closed behavior: the API never reports a timestamp as
valid based on an operator's claim alone.

### Stage 2 — Confirmed (Bitcoin anchored)

The server periodically batches all pending hashes into a single commitment
and embeds it in a Bitcoin transaction. Once that transaction is buried under
enough blocks, the proof is upgraded to contain a *Bitcoin block header
attestation*.

**What it proves:** the document's hash existed **before** the timestamp in
Bitcoin block N. Anyone with a copy of the Bitcoin blockchain can re-derive
this independently — the calendar server is no longer needed and no longer
trusted.

**What you must trust:** the Bitcoin network's consensus (the same assumption
securing hundreds of billions of dollars), and the integrity of SHA-256.

Verification returns:

```json
{
  "valid": true,
  "status": "confirmed",
  "verified_at": "2026-06-12T14:58:30Z",
  "block_height": 850000,
  "block_hash": "0000000000000000000...",
  "attestations": [
    {"kind": "bitcoin", "status": "confirmed", "detail": "height=850000 ..."}
  ]
}
```

`verified_at` is the block's `nTime` field, read from the block header itself
— not from any database this server controls.

## Threat model

| Period | Who can lie to you | Mitigation |
|--------|-------------------|------------|
| Pending window (stamp → confirmation) | The calendar operator could back-date or refuse service | Keep the pending `.ots`; stamp with multiple independent calendars for critical evidence |
| After Bitcoin confirmation | Nobody, short of rewriting the Bitcoin blockchain below the attesting block | Choose confirmation depth by risk (below) |
| Verification time | A malicious *verifier setup* (wrong Bitcoin node) could feed false headers | Verify against your own node, or cross-check with a second independent source |

Notes:

- Bitcoin block `nTime` is accurate to roughly ± 2 hours by consensus rules.
  An OTS proof is therefore evidence of existence *before* a point in time
  with ~hours granularity, not a precision clock.
- A timestamp proves **existence**, not authorship, possession, or content
  validity.

## Recommended confirmation depth

Set with `--btc-min-confirmations`. The proof is only released to verifiers
after this depth is reached.

| Confirmations | Use case |
|---------------|----------|
| 1 | Demos, internal testing |
| 6 (default) | Production compliance use |
| 12+ | High-value audit evidence, adversarial settings |

## Data retention

- The commitment **journal is append-only by design**. There is no deletion
  API. Every hash ever submitted remains recorded, which is itself an audit
  property: the operator cannot silently un-receive a document.
- The server stores **only hashes**, never document content. Uploaded files
  (`/api/v1/stamp-file`) are hashed in-stream and discarded.
- Hashes reveal nothing about document content, but identical documents
  produce identical hashes. The aggregation path adds a random nonce before
  anything reaches the public calendar tree, so submitted digests are not
  recoverable from published data.

## Independent verification (do not trust this server)

A confirmed `.ots` file verifies without contacting this server. Reviewers
should reproduce verification through at least one independent path:

**Python reference client** (official OpenTimestamps implementation):

```bash
pip install opentimestamps-client
ots verify document.pdf.ots          # uses your local Bitcoin Core node
```

**This project's SDK** against your own Bitcoin node:

```go
headers, _ := ots.BitcoinRPCHeaderSource("127.0.0.1:8332", "user", "pass", "mainnet")
result, _ := ots.VerifyFile(ctx, nil, headers, "document.pdf", "document.pdf.ots")
```

**Web** (convenience only, trusts the site): <https://opentimestamps.org>

Cross-client compatibility is tested: proofs from this server are accepted by
the Python `ots` client and vice versa.

## Operational guarantees relevant to audits

- Commitments survive server restarts (append-only journal + embedded
  database, both fsync'd).
- The server refuses to start the Bitcoin stamper without persistent storage.
- The configured network (mainnet/testnet/regtest) is checked against the
  connected Bitcoin node at startup; mismatches abort.
- All stamp / anchor / confirm events are logged with commitment hex and
  transaction ids (`-log-json` for machine-readable audit logs).

## Backup and restore

The entire calendar state is the data directory (default `~/.otsd/calendar`):

```
journal        append-only commitment log   ← irreplaceable
db/ots.db      proof trees                  ← rebuildable while txs are pending, irreplaceable after
hmac-key       calendar identity secret     ← irreplaceable
uri            public calendar URL
```

Back up with the server stopped, or use filesystem snapshots:

```bash
tar -czf ots-backup-$(date +%F).tar.gz -C ~/.otsd calendar
```

Restore = untar to the data directory and start the server; the stamper
re-queues any commitment that was journaled but not yet anchored.
