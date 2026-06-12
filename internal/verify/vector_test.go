// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package verify

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

// Known mainnet vector from opentimestamps-client/examples: hello-world.txt
// is anchored in Bitcoin block 358391. Public chain facts, independently
// checkable on any block explorer.
const (
	helloWorldDigest     = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"
	helloWorldHeight     = uint64(358391)
	helloWorldMerkleRoot = "007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a" // internal byte order (explorers display the reverse)
	helloWorldBlockHash  = "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319"
	helloWorldBlockTime  = 1432827678 // nTime of block 358391
)

func TestKnownMainnetVector(t *testing.T) {
	data, err := os.ReadFile("testdata/hello-world.txt.ots")
	if err != nil {
		t.Fatal(err)
	}
	det, err := timestamp.DeserializeDetachedBytes(data)
	if err != nil {
		t.Fatalf("real-world .ots failed to parse: %v", err)
	}

	wantDigest, _ := hex.DecodeString(helloWorldDigest)
	if !bytes.Equal(det.FileDigest(), wantDigest) {
		t.Fatalf("file digest = %x, want %s", det.FileDigest(), helloWorldDigest)
	}

	// The original file must hash to the proof digest.
	f, err := os.Open("testdata/hello-world.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	wantRoot, _ := hex.DecodeString(helloWorldMerkleRoot)
	headers := staticHeaders{
		height: helloWorldHeight,
		header: &bitcoin.BlockHeader{
			Height:     helloWorldHeight,
			Hash:       helloWorldBlockHash,
			MerkleRoot: wantRoot,
			Time:       time.Unix(helloWorldBlockTime, 0).UTC(),
		},
	}
	result, err := VerifyDetached(context.Background(), Options{Headers: headers}, f, det.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.Status != StatusConfirmed {
		t.Fatalf("known-good mainnet proof did not verify: %+v", result)
	}
	if result.BlockHeight != helloWorldHeight {
		t.Fatalf("height = %d, want %d", result.BlockHeight, helloWorldHeight)
	}
	if result.VerifiedAt == nil || result.VerifiedAt.Unix() != helloWorldBlockTime {
		t.Fatalf("verified_at = %v, want unix %d", result.VerifiedAt, helloWorldBlockTime)
	}

	// Round-trip: re-serialize and compare parse equality.
	out, err := det.SerializeBytes()
	if err != nil {
		t.Fatal(err)
	}
	back, err := timestamp.DeserializeDetachedBytes(out)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(det) {
		t.Fatal("re-serialized proof differs")
	}
}

type staticHeaders struct {
	height uint64
	header *bitcoin.BlockHeader
}

func (s staticHeaders) BlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error) {
	if height != s.height {
		return nil, os.ErrNotExist
	}
	return s.header, nil
}
