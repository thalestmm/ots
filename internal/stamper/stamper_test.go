// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package stamper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/calendar"
	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

func sha256d(b []byte) []byte {
	once := sha256.Sum256(b)
	twice := sha256.Sum256(once[:])
	return twice[:]
}

// fakeBackend simulates a Bitcoin node + wallet: SendOpReturn fabricates a
// valid OP_RETURN transaction; the test then "mines" it and advances
// confirmations.
type fakeBackend struct {
	confirmations int64
	blockHash     chainhash.Hash
	blockHeight   int64
	blockTime     time.Time
	txids         [][]byte
	rawTx         []byte
	txid          *chainhash.Hash
	merkleRoot    []byte
	sendCalls     int
}

func (f *fakeBackend) SendOpReturn(data []byte, maxFee btcutil.Amount) (*chainhash.Hash, []byte, error) {
	f.sendCalls++
	tx := wire.NewMsgTx(2)
	prev := chainhash.Hash{}
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prev, 0), []byte{0x51}, nil))
	script := append([]byte{0x6a, byte(len(data))}, data...)
	tx.AddTxOut(wire.NewTxOut(0, script))
	var buf bytes.Buffer
	if err := tx.SerializeNoWitness(&buf); err != nil {
		return nil, nil, err
	}
	f.rawTx = buf.Bytes()
	txid, err := chainhash.NewHash(sha256d(f.rawTx))
	if err != nil {
		return nil, nil, err
	}
	f.txid = txid
	return txid, f.rawTx, nil
}

// mine puts the anchor tx in a block alongside a fake coinbase.
func (f *fakeBackend) mine() {
	coinbase := sha256d([]byte("coinbase"))
	f.txids = [][]byte{coinbase, f.txid[:]}
	f.merkleRoot = sha256d(append(append([]byte{}, coinbase...), f.txid[:]...))
	f.blockHeight = 850000
	f.blockTime = time.Date(2026, 6, 12, 14, 0, 0, 0, time.UTC)
	copy(f.blockHash[:], sha256d([]byte("block")))
}

func (f *fakeBackend) TxStatus(txid *chainhash.Hash) (*bitcoin.TxStatus, error) {
	st := &bitcoin.TxStatus{Confirmations: f.confirmations}
	if f.confirmations > 0 {
		h := f.blockHash
		st.BlockHash = &h
	}
	return st, nil
}

func (f *fakeBackend) BlockTxIDs(hash *chainhash.Hash) (int64, [][]byte, error) {
	return f.blockHeight, f.txids, nil
}

func (f *fakeBackend) BlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error) {
	return &bitcoin.BlockHeader{
		Height:     height,
		Hash:       f.blockHash.String(),
		MerkleRoot: f.merkleRoot,
		Time:       f.blockTime,
	}, nil
}

// TestStamperEndToEnd drives the full anchoring cycle without a real node:
// submit digests through the calendar (journal + store), let the stamper
// send an anchor tx, mine + confirm it, and verify the upgraded proof
// cryptographically against the (fake) block header.
func TestStamperEndToEnd(t *testing.T) {
	dir := t.TempDir()
	journal, err := calendar.OpenJournal(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	store, err := calendar.OpenBoltStore(filepath.Join(dir, "ots.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	hmacKey := make([]byte, 32)
	cal := calendar.NewService("http://cal.example.com", hmacKey, store).WithJournal(journal)

	// Submit two digests through the real calendar path.
	var commitments [][]byte
	var clientProofs []*timestamp.Timestamp
	for _, blob := range []string{"document one", "document two"} {
		digest := sha256.Sum256([]byte(blob))
		ts, err := timestamp.New(digest[:])
		if err != nil {
			t.Fatal(err)
		}
		macced, err := cal.Submit(ts)
		if err != nil {
			t.Fatal(err)
		}
		commitments = append(commitments, macced.Msg)
		clientProofs = append(clientProofs, ts)
	}
	if journal.Len() != 2 {
		t.Fatalf("journal entries = %d, want 2", journal.Len())
	}

	fake := &fakeBackend{}
	cfg := Config{MinConfirmations: 6, MinTxInterval: time.Nanosecond, MaxPending: 1000, Tick: time.Hour}
	st := New(journal, store, fake, cfg, nil)
	if err := st.Recover(); err != nil {
		t.Fatal(err)
	}

	// Step 1: pending commitments get anchored in one tx.
	st.step()
	if fake.sendCalls != 1 {
		t.Fatalf("sendCalls = %d, want 1", fake.sendCalls)
	}
	for _, c := range commitments {
		if !st.IsPending(c) {
			t.Fatal("commitment should still be pending while unconfirmed")
		}
	}

	// Step 2: not enough confirmations yet.
	fake.mine()
	fake.confirmations = 3
	st.step()
	if st.Status().UnconfirmedTxs != 1 {
		t.Fatal("tx should still be unconfirmed below min confirmations")
	}

	// Step 3: confirmed; proofs must be persisted with Bitcoin attestations.
	fake.confirmations = 6
	st.step()
	if st.Status().UnconfirmedTxs != 0 {
		t.Fatal("tx should be finalized at min confirmations")
	}
	for i, c := range commitments {
		if st.IsPending(c) {
			t.Fatalf("commitment %d still pending after confirmation", i)
		}
		stored, err := store.Get(c)
		if err != nil {
			t.Fatalf("commitment %d not in store: %v", i, err)
		}
		if !verify.IsComplete(stored) {
			t.Fatalf("commitment %d proof lacks bitcoin attestation", i)
		}

		// Full client-side verification: upgrade the original receipt and
		// check it against the fake header source.
		proof := clientProofs[i]
		opts := verify.Options{Upgrader: storeUpgrader{store}, Headers: fake}
		result, err := verify.VerifyProof(context.Background(), opts, proof, proof.Msg)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Valid || result.Status != verify.StatusConfirmed {
			t.Fatalf("commitment %d verify = %+v, want confirmed", i, result)
		}
		if result.BlockHeight != 850000 {
			t.Fatalf("block height = %d, want 850000", result.BlockHeight)
		}
		if result.VerifiedAt == nil || !result.VerifiedAt.Equal(fake.blockTime) {
			t.Fatalf("verified_at = %v, want %v", result.VerifiedAt, fake.blockTime)
		}
	}
}

// TestStamperRecovery simulates a restart between journal write and
// anchoring: a fresh stamper must re-queue unconfirmed commitments.
func TestStamperRecovery(t *testing.T) {
	dir := t.TempDir()
	journal, err := calendar.OpenJournal(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	store, err := calendar.OpenBoltStore(filepath.Join(dir, "ots.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	hmacKey := make([]byte, 32)
	cal := calendar.NewService("http://cal.example.com", hmacKey, store).WithJournal(journal)
	digest := sha256.Sum256([]byte("survives restart"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	macced, err := cal.Submit(ts)
	if err != nil {
		t.Fatal(err)
	}

	// "Restart": brand-new stamper over the same journal + store.
	st := New(journal, store, &fakeBackend{}, DefaultConfig(), nil)
	if err := st.Recover(); err != nil {
		t.Fatal(err)
	}
	if !st.IsPending(macced.Msg) {
		t.Fatal("commitment lost across restart")
	}
	if st.Status().Pending != 1 {
		t.Fatalf("pending = %d, want 1", st.Status().Pending)
	}
}

type storeUpgrader struct {
	store calendar.Storage
}

func (u storeUpgrader) GetTimestamp(ctx context.Context, commitment []byte) (*timestamp.Timestamp, error) {
	return u.store.Get(commitment)
}
