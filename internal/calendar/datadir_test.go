// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package calendar

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/thalestmm/ots/internal/core/timestamp"
)

// Acceptance test for workstream 1: restart the server after a submission;
// the commitment tree must still be servable and the calendar identity
// (hmac-key, uri) must be stable.
func TestDataDirSurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	dd, err := OpenDataDir(dir, "http://cal.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cal := NewService(dd.URI, dd.HMACKey, dd.Store).WithJournal(dd.Journal)
	digest := sha256.Sum256([]byte("must survive restart"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	macced, err := cal.Submit(ts)
	if err != nil {
		t.Fatal(err)
	}
	commitment := macced.Msg
	firstKey := append([]byte{}, dd.HMACKey...)
	if err := dd.Close(); err != nil {
		t.Fatal(err)
	}

	// "Restart" with a different default URI: persisted values must win.
	dd2, err := OpenDataDir(dir, "http://other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer dd2.Close()
	if dd2.URI != "http://cal.example.com" {
		t.Fatalf("uri after restart = %q, want persisted value", dd2.URI)
	}
	if !bytes.Equal(dd2.HMACKey, firstKey) {
		t.Fatal("hmac key regenerated on restart — must persist")
	}
	if dd2.Journal.Len() != 1 {
		t.Fatalf("journal entries after restart = %d, want 1", dd2.Journal.Len())
	}
	got, err := dd2.Store.Get(commitment)
	if err != nil {
		t.Fatalf("commitment lost across restart: %v", err)
	}
	if !got.Equal(macced) {
		t.Fatal("commitment tree differs after restart")
	}
}
