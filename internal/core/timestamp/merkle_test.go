// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package timestamp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/thalestmm/ots/internal/core/notary"
)

func sha256d(b []byte) []byte {
	once := sha256.Sum256(b)
	twice := sha256.Sum256(once[:])
	return twice[:]
}

// Regression test: every leaf of a merkle tree — left and right branches —
// must reach the tip, and the whole tree must serialize. Before the
// CatThenUnaryOp fix, left-branch children dead-ended and serialization of
// any batch >= 2 failed with "an empty timestamp can't be serialized".
func TestMakeMerkleTreeAllLeavesReachTip(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13} {
		t.Run(fmt.Sprintf("leaves=%d", n), func(t *testing.T) {
			leaves := make([]*Timestamp, n)
			for i := range leaves {
				digest := sha256.Sum256([]byte{byte(i)})
				ts, err := New(digest[:])
				if err != nil {
					t.Fatal(err)
				}
				leaves[i] = ts
			}
			tip, err := MakeMerkleTree(leaves)
			if err != nil {
				t.Fatal(err)
			}
			att := &notary.BitcoinBlockHeaderAttestation{Height: 850000}
			tip.Attestations = append(tip.Attestations, att)

			for i, leaf := range leaves {
				data, err := leaf.SerializeBytes()
				if err != nil {
					t.Fatalf("leaf %d does not serialize: %v", i, err)
				}
				back, err := DeserializeBytes(data, leaf.Msg)
				if err != nil {
					t.Fatalf("leaf %d round trip: %v", i, err)
				}
				found := false
				for _, item := range back.AllAttestations() {
					if item.Att.Equal(att) {
						if !bytes.Equal(item.Msg, tip.Msg) {
							t.Fatalf("leaf %d attestation on wrong message", i)
						}
						found = true
					}
				}
				if !found {
					t.Fatalf("leaf %d does not reach the tip attestation", i)
				}
			}
		})
	}
}

func TestCatSHA256dMatchesReference(t *testing.T) {
	l := sha256.Sum256([]byte("left"))
	r := sha256.Sum256([]byte("right"))
	left, err := New(l[:])
	if err != nil {
		t.Fatal(err)
	}
	right, err := New(r[:])
	if err != nil {
		t.Fatal(err)
	}
	parent, err := CatSHA256d(left, right)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256d(append(append([]byte{}, l[:]...), r[:]...))
	if !bytes.Equal(parent.Msg, want) {
		t.Fatalf("CatSHA256d = %x, want %x", parent.Msg, want)
	}
}

// Satoshi odd-leaf duplication: cat_sha256d(x, x) on the same node must
// produce a serializable path (shared child via SetOpResult).
func TestCatSHA256dSelfPair(t *testing.T) {
	d := sha256.Sum256([]byte("lonely leaf"))
	x, err := New(d[:])
	if err != nil {
		t.Fatal(err)
	}
	parent, err := CatSHA256d(x, x)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256d(append(append([]byte{}, d[:]...), d[:]...))
	if !bytes.Equal(parent.Msg, want) {
		t.Fatalf("self-pair = %x, want %x", parent.Msg, want)
	}
	att := &notary.BitcoinBlockHeaderAttestation{Height: 1}
	parent.Attestations = append(parent.Attestations, att)
	if _, err := x.SerializeBytes(); err != nil {
		t.Fatalf("self-pair tree does not serialize: %v", err)
	}
}
