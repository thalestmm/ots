// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package verify

import (
	"crypto/sha256"
	"testing"

	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

func TestParseProofBitcoinHeight(t *testing.T) {
	ts, digest, _ := proofWithBitcoinAtt(t, 850000)
	result, err := ParseProof(ts, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete {
		t.Fatal("expected complete")
	}
	if result.BlockHeight != 850000 {
		t.Fatalf("block_height = %d, want 850000", result.BlockHeight)
	}
	if len(result.BlockHeights) != 1 || result.BlockHeights[0] != 850000 {
		t.Fatalf("block_heights = %v", result.BlockHeights)
	}
}

func TestParseProofMultipleBitcoinHeights(t *testing.T) {
	digest := sha256.Sum256([]byte("multi-anchor"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	node, err := ts.AddOp(op.NewSHA256())
	if err != nil {
		t.Fatal(err)
	}
	node.Attestations = append(node.Attestations,
		&notary.BitcoinBlockHeaderAttestation{Height: 900000},
		&notary.BitcoinBlockHeaderAttestation{Height: 850000},
	)

	result, err := ParseProof(ts, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.BlockHeight != 850000 {
		t.Fatalf("block_height = %d, want earliest 850000", result.BlockHeight)
	}
	if len(result.BlockHeights) != 2 || result.BlockHeights[0] != 850000 || result.BlockHeights[1] != 900000 {
		t.Fatalf("block_heights = %v", result.BlockHeights)
	}
}

func TestParseProofPendingOnly(t *testing.T) {
	digest := sha256.Sum256([]byte("pending"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	node, err := ts.AddOp(op.NewSHA256())
	if err != nil {
		t.Fatal(err)
	}
	att, err := notary.NewPendingAttestation("https://alice.btc.calendar.opentimestamps.org")
	if err != nil {
		t.Fatal(err)
	}
	node.Attestations = append(node.Attestations, att)

	result, err := ParseProof(ts, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.BlockHeight != 0 {
		t.Fatalf("got %+v, want incomplete with no height", result)
	}
	if len(result.PendingURIs) != 1 {
		t.Fatalf("pending_calendars = %v", result.PendingURIs)
	}
}

func TestParseProofWrongDigest(t *testing.T) {
	ts, digest, _ := proofWithBitcoinAtt(t, 1)
	other := sha256.Sum256([]byte("wrong"))
	if _, err := ParseProof(ts, other[:]); err == nil {
		t.Fatal("expected digest mismatch error")
	}
	_ = digest
}
