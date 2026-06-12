// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-server/otsserver/calendar.py (LGPL-3.0+).

package calendar

import (
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

const hmacSize = 8

type Service struct {
	uri     string
	hmacKey []byte
	store   Storage
	journal *Journal
	idx     atomic.Uint64
}

func NewService(uri string, hmacKey []byte, store Storage) *Service {
	if len(hmacKey) == 0 {
		panic("hmac key required")
	}
	return &Service{uri: uri, hmacKey: append([]byte{}, hmacKey...), store: store}
}

// WithJournal makes Submit durably append every commitment to the journal
// before it reaches the store. The journal feeds the Bitcoin stamper.
func (s *Service) WithJournal(j *Journal) *Service {
	s.journal = j
	return s
}

func deriveKeyForIdx(key []byte, idx uint32, bits int) []byte {
	if bits == 0 {
		return append([]byte{}, key...)
	}
	suffix := byte(0x00)
	if (idx>>(bits-1))&1 != 0 {
		suffix = 0xff
	}
	next := append(append([]byte{}, key...), suffix)
	hashed := sha256.Sum256(next)
	return deriveKeyForIdx(hashed[:], idx, bits-1)
}

func (s *Service) Submit(submitted *timestamp.Timestamp) (*timestamp.Timestamp, error) {
	idx := uint32(time.Now().Unix())
	s.idx.Store(uint64(idx))

	serializedIdx := make([]byte, 4)
	binary.BigEndian.PutUint32(serializedIdx, idx)

	prependOp, err := op.NewPrepend(serializedIdx)
	if err != nil {
		return nil, err
	}
	commitment, err := submitted.AddOp(prependOp)
	if err != nil {
		return nil, err
	}

	perIdxKey := deriveKeyForIdx(s.hmacKey, idx, 32)
	macFull := sha256.Sum256(append(append([]byte{}, commitment.Msg...), perIdxKey...))
	mac := macFull[:hmacSize]

	appendOp, err := op.NewAppend(mac)
	if err != nil {
		return nil, err
	}
	macced, err := commitment.AddOp(appendOp)
	if err != nil {
		return nil, err
	}

	pending, err := notary.NewPendingAttestation(s.uri)
	if err != nil {
		return nil, err
	}
	macced.Attestations = append(macced.Attestations, pending)

	if s.journal != nil {
		if _, err := s.journal.Append(macced.Msg); err != nil {
			return nil, err
		}
	}
	if err := s.store.Put(macced.Msg, macced); err != nil {
		return nil, err
	}
	return macced, nil
}

func (s *Service) Get(commitment []byte) (*timestamp.Timestamp, error) {
	return s.store.Get(commitment)
}

func (s *Service) Has(commitment []byte) bool {
	return s.store.Has(commitment)
}

func (s *Service) URI() string { return s.uri }
