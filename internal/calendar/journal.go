// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-server/otsserver/calendar.py (LGPL-3.0+).

package calendar

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// JournalRecordSize is the fixed size of one journal record:
// 4-byte big-endian unix index + 32-byte merkle tip + 8-byte HMAC.
const JournalRecordSize = 44

// Journal is an append-only, fsync'd log of calendar commitments. It is the
// durable source of truth for the stamper's pending pool: a commitment that
// reached the journal survives restarts even if it never reached the
// commitment store.
type Journal struct {
	mu    sync.Mutex
	f     *os.File
	count uint64
}

// OpenJournal opens (or creates) the journal at path. A trailing partial
// record left by a crash mid-write is truncated away.
func OpenJournal(path string) (*Journal, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	size := info.Size()
	if rem := size % JournalRecordSize; rem != 0 {
		size -= rem
		if err := f.Truncate(size); err != nil {
			f.Close()
			return nil, fmt.Errorf("recover partial journal write: %w", err)
		}
	}
	if _, err := f.Seek(size, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return &Journal{f: f, count: uint64(size) / JournalRecordSize}, nil
}

// Append writes one commitment record and fsyncs before returning its index.
func (j *Journal) Append(commitment []byte) (uint64, error) {
	if len(commitment) != JournalRecordSize {
		return 0, fmt.Errorf("journal record must be %d bytes, got %d", JournalRecordSize, len(commitment))
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.f.Write(commitment); err != nil {
		return 0, err
	}
	if err := j.f.Sync(); err != nil {
		return 0, err
	}
	idx := j.count
	j.count++
	return idx, nil
}

// Read returns the record at idx.
func (j *Journal) Read(idx uint64) ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if idx >= j.count {
		return nil, fmt.Errorf("journal index %d out of range (len %d)", idx, j.count)
	}
	buf := make([]byte, JournalRecordSize)
	if _, err := j.f.ReadAt(buf, int64(idx)*JournalRecordSize); err != nil {
		return nil, err
	}
	return buf, nil
}

// Len returns the number of records.
func (j *Journal) Len() uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.count
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}
