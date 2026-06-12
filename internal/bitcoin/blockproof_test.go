// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package bitcoin

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

func sha256d(b []byte) []byte {
	once := sha256.Sum256(b)
	twice := sha256.Sum256(once[:])
	return twice[:]
}

// satoshiMerkleRoot computes a block merkle root the way Bitcoin does,
// independently of the timestamp machinery under test.
func satoshiMerkleRoot(txids [][]byte) []byte {
	level := make([][]byte, len(txids))
	copy(level, txids)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, sha256d(append(append([]byte{}, level[i]...), level[i+1]...)))
		}
		level = next
	}
	return level[0]
}

// buildOpReturnTx builds a minimal valid transaction carrying data in an
// OP_RETURN output and returns its witness-stripped serialization.
func buildOpReturnTx(t *testing.T, data []byte) []byte {
	t.Helper()
	tx := wire.NewMsgTx(2)
	prev := chainhash.Hash{}
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prev, 0), []byte{0x51}, nil))
	script := append([]byte{0x6a, byte(len(data))}, data...)
	tx.AddTxOut(wire.NewTxOut(0, script))
	var buf bytes.Buffer
	if err := tx.SerializeNoWitness(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestMakeTimestampFromBlock(t *testing.T) {
	for _, txCount := range []int{1, 2, 3, 7} {
		for txIndex := 0; txIndex < txCount; txIndex++ {
			tipDigest := sha256.Sum256([]byte{byte(txCount), byte(txIndex)})
			tip, err := timestamp.New(tipDigest[:])
			if err != nil {
				t.Fatal(err)
			}
			rawTx := buildOpReturnTx(t, tip.Msg)
			ourTxid := sha256d(rawTx)

			txids := make([][]byte, txCount)
			for i := range txids {
				if i == txIndex {
					txids[i] = ourTxid
					continue
				}
				other := sha256.Sum256([]byte{0xff, byte(txCount), byte(i)})
				txids[i] = sha256d(other[:])
			}
			merkleRoot := satoshiMerkleRoot(txids)

			root, err := MakeTimestampFromBlock(tip, rawTx, txIndex, txids, merkleRoot)
			if err != nil {
				t.Fatalf("txCount=%d txIndex=%d: %v", txCount, txIndex, err)
			}
			if !bytes.Equal(root.Msg, merkleRoot) {
				t.Fatalf("txCount=%d txIndex=%d: root mismatch", txCount, txIndex)
			}

			// Attach the attestation the way the stamper does; the full
			// path from the tip must then serialize and round-trip.
			att := &notary.BitcoinBlockHeaderAttestation{Height: 850000}
			root.Attestations = append(root.Attestations, att)
			data, err := tip.SerializeBytes()
			if err != nil {
				t.Fatalf("txCount=%d txIndex=%d: tip path broken: %v", txCount, txIndex, err)
			}
			back, err := timestamp.DeserializeBytes(data, tip.Msg)
			if err != nil {
				t.Fatalf("txCount=%d txIndex=%d: round trip: %v", txCount, txIndex, err)
			}
			found := false
			for _, item := range back.AllAttestations() {
				if item.Att.Equal(att) && bytes.Equal(item.Msg, merkleRoot) {
					found = true
				}
			}
			if !found {
				t.Fatalf("txCount=%d txIndex=%d: attestation not reachable from tip", txCount, txIndex)
			}
		}
	}
}

func TestMakeTimestampFromBlockRejectsWrongRoot(t *testing.T) {
	tipDigest := sha256.Sum256([]byte("tip"))
	tip, err := timestamp.New(tipDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	rawTx := buildOpReturnTx(t, tip.Msg)
	txids := [][]byte{sha256d(rawTx)}
	bogus := sha256.Sum256([]byte("not the root"))
	if _, err := MakeTimestampFromBlock(tip, rawTx, 0, txids, bogus[:]); err == nil {
		t.Fatal("expected merkle root mismatch error")
	}
}

func TestMakeTimestampFromBlockRejectsWrongTxid(t *testing.T) {
	tipDigest := sha256.Sum256([]byte("tip2"))
	tip, err := timestamp.New(tipDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	rawTx := buildOpReturnTx(t, tip.Msg)
	wrong := sha256.Sum256([]byte("different tx"))
	txids := [][]byte{sha256d(wrong[:])}
	if _, err := MakeTimestampFromBlock(tip, rawTx, 0, txids, txids[0]); err == nil {
		t.Fatal("expected txid mismatch error")
	}
}
