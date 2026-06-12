// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package calendar

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func randomCommitment(t *testing.T) []byte {
	t.Helper()
	c := make([]byte, JournalRecordSize)
	if _, err := rand.Read(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestJournalRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	var records [][]byte
	for i := 0; i < 10; i++ {
		c := randomCommitment(t)
		idx, err := j.Append(c)
		if err != nil {
			t.Fatal(err)
		}
		if idx != uint64(i) {
			t.Fatalf("idx = %d, want %d", idx, i)
		}
		records = append(records, c)
	}
	if j.Len() != 10 {
		t.Fatalf("len = %d, want 10", j.Len())
	}
	for i, want := range records {
		got, err := j.Read(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("record %d mismatch", i)
		}
	}
}

func TestJournalRejectsWrongSize(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Append([]byte("short")); err == nil {
		t.Fatal("expected error for short record")
	}
}

func TestJournalSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	c := randomCommitment(t)
	if _, err := j.Append(c); err != nil {
		t.Fatal(err)
	}
	j.Close()

	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j2.Close()
	if j2.Len() != 1 {
		t.Fatalf("len after reopen = %d, want 1", j2.Len())
	}
	got, err := j2.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, c) {
		t.Fatal("record mismatch after reopen")
	}
}

func TestJournalRecoversPartialWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	c := randomCommitment(t)
	if _, err := j.Append(c); err != nil {
		t.Fatal(err)
	}
	j.Close()

	// Simulate a crash mid-write: append a torn partial record.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j2.Close()
	if j2.Len() != 1 {
		t.Fatalf("len after torn write = %d, want 1", j2.Len())
	}
	c2 := randomCommitment(t)
	idx, err := j2.Append(c2)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Fatalf("idx after recovery = %d, want 1", idx)
	}
	got, err := j2.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, c2) {
		t.Fatal("record written after recovery mismatch")
	}
}
