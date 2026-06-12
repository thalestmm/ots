// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-server/otsserver/calendar.py (LGPL-3.0+).

package calendar

import (
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/thalestmm/ots/internal/core/timestamp"
)

var timestampsBucket = []byte("timestamps")

// BoltStore is a Storage backed by an embedded bbolt database. Keys are
// commitment messages; values are the serialized timestamp trees rooted at
// that commitment. Put merges with any existing tree so attestations
// accumulate (pending + bitcoin) instead of overwriting each other.
type BoltStore struct {
	db *bolt.DB
}

func OpenBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(timestampsBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) Put(commitment []byte, ts *timestamp.Timestamp) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(timestampsBucket)
		merged := ts
		if existing := b.Get(commitment); existing != nil {
			prev, err := timestamp.DeserializeBytes(existing, commitment)
			if err != nil {
				return fmt.Errorf("corrupt stored timestamp for %x: %w", commitment, err)
			}
			if err := prev.Merge(ts); err != nil {
				return err
			}
			merged = prev
		}
		data, err := merged.SerializeBytes()
		if err != nil {
			return err
		}
		return b.Put(commitment, data)
	})
}

func (s *BoltStore) Get(commitment []byte) (*timestamp.Timestamp, error) {
	var data []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(timestampsBucket).Get(commitment); v != nil {
			data = append([]byte{}, v...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("commitment not found")
	}
	return timestamp.DeserializeBytes(data, commitment)
}

func (s *BoltStore) Has(commitment []byte) bool {
	found := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket(timestampsBucket).Get(commitment) != nil
		return nil
	})
	return found
}

func (s *BoltStore) Close() error {
	return s.db.Close()
}
