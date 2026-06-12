// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package stamper

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/calendar"
	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

// TestRegtestEndToEnd anchors a commitment in a real regtest chain and
// verifies the resulting proof cryptographically. It needs a running
// bitcoind with a funded wallet (see `just regtest-up`) and is skipped
// unless OTS_REGTEST_RPC_HOST is set, e.g.:
//
//	OTS_REGTEST_RPC_HOST=127.0.0.1:18443 \
//	OTS_REGTEST_RPC_USER=ots OTS_REGTEST_RPC_PASS=ots \
//	go test ./internal/stamper -run TestRegtestEndToEnd -v
func TestRegtestEndToEnd(t *testing.T) {
	host := os.Getenv("OTS_REGTEST_RPC_HOST")
	if host == "" {
		t.Skip("OTS_REGTEST_RPC_HOST not set; skipping regtest integration test")
	}
	btc, err := bitcoin.NewClient(bitcoin.Config{
		Host:    host,
		User:    os.Getenv("OTS_REGTEST_RPC_USER"),
		Pass:    os.Getenv("OTS_REGTEST_RPC_PASS"),
		Network: "regtest",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer btc.Close()
	if err := btc.CheckNetwork(); err != nil {
		t.Fatal(err)
	}

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
	digest := sha256.Sum256([]byte("regtest evidence " + time.Now().String()))
	clientProof, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cal.Submit(clientProof); err != nil {
		t.Fatal(err)
	}

	maxFee, _ := btcutil.NewAmount(0.01)
	cfg := Config{MinConfirmations: 2, MinTxInterval: time.Nanosecond, MaxFee: maxFee, MaxPending: 1000, Tick: time.Hour}
	st := New(journal, store, btc, cfg, nil)
	if err := st.Recover(); err != nil {
		t.Fatal(err)
	}

	// Send the anchor tx.
	st.step()
	status := st.Status()
	if status.UnconfirmedTxs != 1 {
		t.Fatalf("unconfirmed txs = %d, want 1 (is the wallet funded?)", status.UnconfirmedTxs)
	}

	// Mine blocks to confirm.
	mine(t, btc, 3)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st.step()
		if st.Status().UnconfirmedTxs == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if st.Status().UnconfirmedTxs != 0 {
		t.Fatal("anchor tx never confirmed")
	}

	// Verify the upgraded proof against the regtest chain; the verifier
	// resolves the pending attestation through the store upgrader.
	opts := verify.Options{Upgrader: storeUpgrader{store}, Headers: btc}
	result, err := verify.VerifyProof(context.Background(), opts, clientProof, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.Status != verify.StatusConfirmed {
		t.Fatalf("regtest proof did not verify: %+v", result)
	}
	t.Logf("confirmed at height %d, block %s, time %s", result.BlockHeight, result.BlockHash, result.VerifiedAt)
}

func mine(t *testing.T, btc *bitcoin.Client, n int) {
	t.Helper()
	res, err := btc.RawRequest("getnewaddress", nil)
	if err != nil {
		t.Fatal(err)
	}
	var addr string
	if err := json.Unmarshal(res, &addr); err != nil {
		t.Fatal(err)
	}
	addrJSON, _ := json.Marshal(addr)
	nJSON, _ := json.Marshal(n)
	if _, err := btc.RawRequest("generatetoaddress", []json.RawMessage{nJSON, addrJSON}); err != nil {
		t.Fatal(err)
	}
}
