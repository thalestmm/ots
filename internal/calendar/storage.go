// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-server/otsserver/calendar.py (LGPL-3.0+).

package calendar

import (
	"fmt"
	"sync"

	"github.com/thalestmm/ots/internal/core/timestamp"
)

type Storage interface {
	Put(commitment []byte, ts *timestamp.Timestamp) error
	Get(commitment []byte) (*timestamp.Timestamp, error)
	Has(commitment []byte) bool
}

type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]*timestamp.Timestamp
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: make(map[string]*timestamp.Timestamp)}
}

func key(commitment []byte) string {
	return string(commitment)
}

func (s *MemoryStore) Put(commitment []byte, ts *timestamp.Timestamp) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key(commitment)] = cloneTimestamp(ts)
	return nil
}

func (s *MemoryStore) Get(commitment []byte) (*timestamp.Timestamp, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.data[key(commitment)]
	if !ok {
		return nil, fmt.Errorf("commitment not found")
	}
	return cloneTimestamp(ts), nil
}

func (s *MemoryStore) Has(commitment []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[key(commitment)]
	return ok
}

func cloneTimestamp(ts *timestamp.Timestamp) *timestamp.Timestamp {
	data, err := ts.SerializeBytes()
	if err != nil {
		panic(err)
	}
	clone, err := timestamp.DeserializeBytes(data, append([]byte{}, ts.Msg...))
	if err != nil {
		panic(err)
	}
	return clone
}
