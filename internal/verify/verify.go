// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-client/otsclient/cmds.py
// and python-opentimestamps/opentimestamps/core/notary.py (LGPL-3.0+).

package verify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

type Upgrader interface {
	GetTimestamp(ctx context.Context, commitment []byte) (*timestamp.Timestamp, error)
}

// Options configures verification. Upgrader (optional) resolves pending
// attestations against a calendar. Headers (optional) provides Bitcoin block
// headers; without it Bitcoin attestations cannot be confirmed and
// verification fails closed.
type Options struct {
	Upgrader Upgrader
	Headers  bitcoin.HeaderSource
}

// Attestation statuses reported in results.
const (
	StatusConfirmed  = "confirmed"  // cryptographically verified against a block header
	StatusPending    = "pending"    // calendar receipt, not yet anchored
	StatusInvalid    = "invalid"    // attestation contradicts the blockchain
	StatusUnverified = "unverified" // no header source available to check
	StatusUnknown    = "unknown"    // unrecognized attestation type
)

type AttestationInfo struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	Status string `json:"status"`
}

// Result is the auditable outcome of a verification. Valid is true only when
// at least one Bitcoin attestation was cryptographically verified against a
// block header; VerifiedAt then carries the earliest such block's nTime.
type Result struct {
	Valid        bool              `json:"valid"`
	Status       string            `json:"status"`
	Reason       string            `json:"reason,omitempty"`
	VerifiedAt   *time.Time        `json:"verified_at,omitempty"`
	BlockHeight  uint64            `json:"block_height,omitempty"`
	BlockHash    string            `json:"block_hash,omitempty"`
	Attestations []AttestationInfo `json:"attestations"`
}

func VerifyDigest(proof *timestamp.Timestamp, digest []byte) error {
	if !bytes.Equal(proof.Msg, digest) {
		return fmt.Errorf("proof root does not match digest")
	}
	return nil
}

func VerifyDetached(ctx context.Context, opts Options, file io.Reader, det *timestamp.Timestamp) (*Result, error) {
	sha := &op.SHA256Op{}
	computed, err := sha.HashReader(file)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(computed, det.Msg) {
		return &Result{Valid: false, Status: StatusInvalid, Reason: "file hash does not match proof"}, nil
	}
	return VerifyProof(ctx, opts, det, computed)
}

// VerifyProof checks digest binding, upgrades pending attestations via the
// calendar when possible, and verifies Bitcoin attestations against block
// headers. It fails closed: no confirmed attestation means Valid == false.
func VerifyProof(ctx context.Context, opts Options, proof *timestamp.Timestamp, digest []byte) (*Result, error) {
	if err := VerifyDigest(proof, digest); err != nil {
		return &Result{Valid: false, Status: StatusInvalid, Reason: err.Error()}, nil
	}

	if opts.Upgrader != nil {
		if err := upgradePending(ctx, opts.Upgrader, proof); err != nil {
			return &Result{Valid: false, Status: StatusInvalid, Reason: err.Error()}, nil
		}
	}

	result := &Result{Attestations: []AttestationInfo{}}
	sawPending := false
	sawInvalid := false

	for _, item := range proof.AllAttestations() {
		switch att := item.Att.(type) {
		case *notary.PendingAttestation:
			sawPending = true
			result.Attestations = append(result.Attestations, AttestationInfo{
				Kind: "pending", Detail: att.URI, Status: StatusPending,
			})
		case *notary.BitcoinBlockHeaderAttestation:
			info := verifyBitcoin(ctx, opts.Headers, att, item.Msg)
			result.Attestations = append(result.Attestations, info.AttestationInfo)
			switch info.Status {
			case StatusConfirmed:
				if result.VerifiedAt == nil || info.blockTime.Before(*result.VerifiedAt) {
					t := info.blockTime
					result.VerifiedAt = &t
					result.BlockHeight = att.Height
					result.BlockHash = info.blockHash
				}
			case StatusInvalid:
				sawInvalid = true
			}
		case *notary.LitecoinBlockHeaderAttestation:
			result.Attestations = append(result.Attestations, AttestationInfo{
				Kind: "litecoin", Detail: fmt.Sprintf("height=%d", att.Height), Status: StatusUnverified,
			})
		default:
			result.Attestations = append(result.Attestations, AttestationInfo{
				Kind: att.Kind(), Detail: "unknown attestation", Status: StatusUnknown,
			})
		}
	}

	switch {
	case len(result.Attestations) == 0:
		result.Status = StatusInvalid
		result.Reason = "no attestations found"
	case result.VerifiedAt != nil:
		result.Valid = true
		result.Status = StatusConfirmed
	case sawInvalid:
		result.Status = StatusInvalid
		result.Reason = "bitcoin attestation does not match block header"
	case sawPending:
		result.Status = StatusPending
		result.Reason = "not yet confirmed in the Bitcoin blockchain; proof is a calendar receipt only"
	default:
		result.Status = StatusUnverified
		result.Reason = "no bitcoin block header source available to confirm attestations"
	}
	return result, nil
}

type bitcoinVerifyInfo struct {
	AttestationInfo
	blockTime time.Time
	blockHash string
}

// verifyBitcoin ports verify_against_blockheader: the attested message must
// be exactly the 32-byte merkle root of the block at the attested height,
// and the block header's nTime becomes the verified timestamp.
func verifyBitcoin(ctx context.Context, headers bitcoin.HeaderSource, att *notary.BitcoinBlockHeaderAttestation, msg []byte) bitcoinVerifyInfo {
	detail := fmt.Sprintf("height=%d", att.Height)
	if headers == nil {
		return bitcoinVerifyInfo{AttestationInfo: AttestationInfo{
			Kind: "bitcoin", Detail: detail, Status: StatusUnverified,
		}}
	}
	if len(msg) != 32 {
		return bitcoinVerifyInfo{AttestationInfo: AttestationInfo{
			Kind: "bitcoin", Detail: detail + "; attested message is not 32 bytes", Status: StatusInvalid,
		}}
	}
	header, err := headers.BlockHeader(ctx, att.Height)
	if err != nil {
		return bitcoinVerifyInfo{AttestationInfo: AttestationInfo{
			Kind: "bitcoin", Detail: fmt.Sprintf("%s; header fetch failed: %v", detail, err), Status: StatusUnverified,
		}}
	}
	if !bytes.Equal(msg, header.MerkleRoot) {
		return bitcoinVerifyInfo{AttestationInfo: AttestationInfo{
			Kind: "bitcoin", Detail: detail + "; merkle root mismatch", Status: StatusInvalid,
		}}
	}
	return bitcoinVerifyInfo{
		AttestationInfo: AttestationInfo{
			Kind:   "bitcoin",
			Detail: fmt.Sprintf("height=%d block=%s time=%s", att.Height, header.Hash, header.Time.UTC().Format(time.RFC3339)),
			Status: StatusConfirmed,
		},
		blockTime: header.Time.UTC(),
		blockHash: header.Hash,
	}
}

func upgradePending(ctx context.Context, upgrader Upgrader, ts *timestamp.Timestamp) error {
	_, err := Upgrade(ctx, upgrader, ts)
	return err
}

// Upgrade resolves pending attestations against the calendar, merging any
// returned subtrees in place. It reports whether the proof gained new
// attestations. Calendar errors (e.g. still pending) are skipped, not fatal.
func Upgrade(ctx context.Context, upgrader Upgrader, ts *timestamp.Timestamp) (bool, error) {
	before := len(ts.AllAttestations())
	for _, item := range ts.AllAttestations() {
		if _, ok := item.Att.(*notary.PendingAttestation); !ok {
			continue
		}
		upgraded, err := upgrader.GetTimestamp(ctx, item.Msg)
		if err != nil {
			continue
		}
		sub, err := findNode(ts, item.Msg)
		if err != nil {
			continue
		}
		if err := sub.Merge(upgraded); err != nil {
			return false, err
		}
	}
	return len(ts.AllAttestations()) > before, nil
}

// IsComplete reports whether the proof contains a Bitcoin attestation.
func IsComplete(ts *timestamp.Timestamp) bool {
	for _, item := range ts.AllAttestations() {
		if _, ok := item.Att.(*notary.BitcoinBlockHeaderAttestation); ok {
			return true
		}
	}
	return false
}

// findNode locates the subtree whose message equals msg.
func findNode(ts *timestamp.Timestamp, msg []byte) (*timestamp.Timestamp, error) {
	if bytes.Equal(ts.Msg, msg) {
		return ts, nil
	}
	for _, opStamp := range ts.Ops {
		if found, err := findNode(opStamp.Stamp, msg); err == nil {
			return found, nil
		}
	}
	return nil, fmt.Errorf("node not found")
}
