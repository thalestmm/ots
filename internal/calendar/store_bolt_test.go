// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package calendar

import (
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

func newBoltStore(t *testing.T) *BoltStore {
	t.Helper()
	s, err := OpenBoltStore(filepath.Join(t.TempDir(), "ots.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testTimestamp(t *testing.T, uri string) *timestamp.Timestamp {
	t.Helper()
	digest := sha256.Sum256([]byte("commitment"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	child, err := ts.AddOp(op.NewSHA256())
	if err != nil {
		t.Fatal(err)
	}
	att, err := notary.NewPendingAttestation(uri)
	if err != nil {
		t.Fatal(err)
	}
	child.Attestations = append(child.Attestations, att)
	return ts
}

func TestBoltStorePutGet(t *testing.T) {
	s := newBoltStore(t)
	ts := testTimestamp(t, "http://cal.example.com")

	if err := s.Put(ts.Msg, ts); err != nil {
		t.Fatal(err)
	}
	if !s.Has(ts.Msg) {
		t.Fatal("Has = false after Put")
	}
	got, err := s.Get(ts.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ts) {
		t.Fatal("round-tripped timestamp differs")
	}
}

func TestBoltStoreMergesAttestations(t *testing.T) {
	s := newBoltStore(t)
	a := testTimestamp(t, "http://cal-a.example.com")
	b := testTimestamp(t, "http://cal-b.example.com")

	if err := s.Put(a.Msg, a); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(b.Msg, b); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(a.Msg)
	if err != nil {
		t.Fatal(err)
	}
	atts := got.AllAttestations()
	if len(atts) != 2 {
		t.Fatalf("attestations after merge = %d, want 2", len(atts))
	}
}

func TestBoltStoreMissing(t *testing.T) {
	s := newBoltStore(t)
	if s.Has([]byte("nope")) {
		t.Fatal("Has = true for missing key")
	}
	if _, err := s.Get([]byte("nope")); err == nil {
		t.Fatal("expected error for missing key")
	}
}
