// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package verify

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

type fakeHeaders struct {
	root []byte
	time time.Time
	err  error
}

func (f fakeHeaders) BlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &bitcoin.BlockHeader{Height: height, Hash: "00ab", MerkleRoot: f.root, Time: f.time}, nil
}

// proofWithBitcoinAtt builds digest → sha256 → (attested node).
func proofWithBitcoinAtt(t *testing.T, height uint64) (*timestamp.Timestamp, []byte, []byte) {
	t.Helper()
	digest := sha256.Sum256([]byte("evidence.pdf"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	node, err := ts.AddOp(op.NewSHA256())
	if err != nil {
		t.Fatal(err)
	}
	node.Attestations = append(node.Attestations, &notary.BitcoinBlockHeaderAttestation{Height: height})
	return ts, digest[:], node.Msg
}

func TestVerifyConfirmed(t *testing.T) {
	ts, digest, root := proofWithBitcoinAtt(t, 850000)
	blockTime := time.Date(2026, 6, 12, 14, 0, 0, 0, time.UTC)
	result, err := VerifyProof(context.Background(), Options{Headers: fakeHeaders{root: root, time: blockTime}}, ts, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.Status != StatusConfirmed {
		t.Fatalf("got %+v, want confirmed", result)
	}
	if result.BlockHeight != 850000 || result.VerifiedAt == nil || !result.VerifiedAt.Equal(blockTime) {
		t.Fatalf("wrong block facts: %+v", result)
	}
}

func TestVerifyInvalidMerkleRoot(t *testing.T) {
	ts, digest, _ := proofWithBitcoinAtt(t, 850000)
	wrong := sha256.Sum256([]byte("attacker"))
	result, err := VerifyProof(context.Background(), Options{Headers: fakeHeaders{root: wrong[:]}}, ts, digest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.Status != StatusInvalid {
		t.Fatalf("got %+v, want invalid (fail closed)", result)
	}
}

func TestVerifyNoHeaderSourceFailsClosed(t *testing.T) {
	ts, digest, _ := proofWithBitcoinAtt(t, 850000)
	result, err := VerifyProof(context.Background(), Options{}, ts, digest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatalf("got valid=true without header source: %+v", result)
	}
	if result.Status != StatusUnverified {
		t.Fatalf("status = %s, want %s", result.Status, StatusUnverified)
	}
}

func TestVerifyPendingOnlyFailsClosed(t *testing.T) {
	digest := sha256.Sum256([]byte("doc"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	node, err := ts.AddOp(op.NewSHA256())
	if err != nil {
		t.Fatal(err)
	}
	att, err := notary.NewPendingAttestation("http://cal.example.com")
	if err != nil {
		t.Fatal(err)
	}
	node.Attestations = append(node.Attestations, att)

	result, err := VerifyProof(context.Background(), Options{}, ts, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.Status != StatusPending {
		t.Fatalf("got %+v, want pending + valid=false", result)
	}
}

func TestVerifyNoAttestations(t *testing.T) {
	digest := sha256.Sum256([]byte("doc"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyProof(context.Background(), Options{}, ts, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.Status != StatusInvalid {
		t.Fatalf("got %+v, want invalid", result)
	}
}

func TestVerifyWrongDigest(t *testing.T) {
	ts, _, root := proofWithBitcoinAtt(t, 1)
	other := sha256.Sum256([]byte("different file"))
	result, err := VerifyProof(context.Background(), Options{Headers: fakeHeaders{root: root}}, ts, other[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("wrong digest accepted")
	}
}
