// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-server/otsserver/stamper.py (LGPL-3.0+).

package stamper

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/calendar"
	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

type Config struct {
	MinConfirmations int64
	MinTxInterval    time.Duration
	MaxFee           btcutil.Amount
	MaxPending       int
	Tick             time.Duration
}

func DefaultConfig() Config {
	maxFee, _ := btcutil.NewAmount(0.001)
	return Config{
		MinConfirmations: 6,
		MinTxInterval:    6 * time.Hour,
		MaxFee:           maxFee,
		MaxPending:       100000,
		Tick:             5 * time.Second,
	}
}

// Backend is the subset of the Bitcoin RPC client the stamper needs;
// *bitcoin.Client satisfies it.
type Backend interface {
	TxStatus(txid *chainhash.Hash) (*bitcoin.TxStatus, error)
	BlockTxIDs(hash *chainhash.Hash) (int64, [][]byte, error)
	BlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error)
	SendOpReturn(data []byte, maxFee btcutil.Amount) (*chainhash.Hash, []byte, error)
}

// unconfirmedTx is an OP_RETURN anchor transaction waiting for confirmations.
type unconfirmedTx struct {
	txid   *chainhash.Hash
	rawTx  []byte // witness-stripped serialization
	tip    *timestamp.Timestamp
	leaves map[string]*timestamp.Timestamp // commitment → leaf timestamp
	sentAt time.Time
}

// Stamper batches journaled commitments into Bitcoin OP_RETURN transactions
// and, once confirmed, persists per-commitment proofs carrying a
// BitcoinBlockHeaderAttestation.
type Stamper struct {
	journal *calendar.Journal
	store   calendar.Storage
	btc     Backend
	cfg     Config
	log     *slog.Logger

	mu          sync.Mutex
	pending     map[string]struct{}
	unconfirmed []*unconfirmedTx
	cursor      uint64
	lastTxTime  time.Time
}

func New(journal *calendar.Journal, store calendar.Storage, btc Backend, cfg Config, log *slog.Logger) *Stamper {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Tick <= 0 {
		cfg.Tick = 5 * time.Second
	}
	return &Stamper{
		journal: journal,
		store:   store,
		btc:     btc,
		cfg:     cfg,
		log:     log,
		pending: make(map[string]struct{}),
	}
}

// Recover replays the journal, queueing every commitment whose stored proof
// does not yet carry a Bitcoin attestation. Call once before Run.
func (s *Stamper) Recover() error {
	n := s.journal.Len()
	requeued := 0
	for i := uint64(0); i < n; i++ {
		commitment, err := s.journal.Read(i)
		if err != nil {
			return err
		}
		if s.isConfirmed(commitment) {
			continue
		}
		s.pending[string(commitment)] = struct{}{}
		requeued++
	}
	s.cursor = n
	if requeued > 0 {
		s.log.Info("stamper recovery", "journal_entries", n, "requeued_pending", requeued)
	}
	return nil
}

func (s *Stamper) isConfirmed(commitment []byte) bool {
	ts, err := s.store.Get(commitment)
	if err != nil {
		return false
	}
	for _, item := range ts.AllAttestations() {
		if _, ok := item.Att.(*notary.BitcoinBlockHeaderAttestation); ok {
			return true
		}
	}
	return false
}

// Run drives the stamper loop until ctx is cancelled.
func (s *Stamper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.step()
		}
	}
}

// step runs one iteration: ingest journal, track confirmations, maybe anchor.
func (s *Stamper) step() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ingestJournal()
	s.trackConfirmations()
	s.maybeSendTx()
}

func (s *Stamper) ingestJournal() {
	n := s.journal.Len()
	for ; s.cursor < n; s.cursor++ {
		if len(s.pending) >= s.cfg.MaxPending {
			s.log.Warn("pending pool full, deferring journal ingestion",
				"pending", len(s.pending), "max", s.cfg.MaxPending)
			return
		}
		commitment, err := s.journal.Read(s.cursor)
		if err != nil {
			s.log.Error("journal read failed", "idx", s.cursor, "err", err)
			return
		}
		s.pending[string(commitment)] = struct{}{}
	}
}

func (s *Stamper) trackConfirmations() {
	remaining := s.unconfirmed[:0]
	for _, utx := range s.unconfirmed {
		st, err := s.btc.TxStatus(utx.txid)
		if err != nil {
			s.log.Error("tx status check failed", "txid", utx.txid, "err", err)
			remaining = append(remaining, utx)
			continue
		}
		switch {
		case st.Confirmations < 0:
			// Conflicted (double-spend or deep reorg): re-queue commitments.
			s.log.Warn("anchor tx conflicted, re-queueing commitments",
				"txid", utx.txid, "commitments", len(utx.leaves))
			for c := range utx.leaves {
				s.pending[c] = struct{}{}
			}
		case st.Confirmations >= s.cfg.MinConfirmations && st.BlockHash != nil:
			if err := s.finalize(utx, st.BlockHash); err != nil {
				s.log.Error("finalize anchor failed", "txid", utx.txid, "err", err)
				remaining = append(remaining, utx)
				continue
			}
		default:
			remaining = append(remaining, utx)
		}
	}
	s.unconfirmed = remaining
}

// finalize builds the block inclusion proof and persists every commitment's
// timestamp tree, now ending in a BitcoinBlockHeaderAttestation.
func (s *Stamper) finalize(utx *unconfirmedTx, blockHash *chainhash.Hash) error {
	height, txids, err := s.btc.BlockTxIDs(blockHash)
	if err != nil {
		return err
	}
	txIndex := -1
	for i, txid := range txids {
		if bytes.Equal(utx.txid[:], txid) {
			txIndex = i
			break
		}
	}
	if txIndex < 0 {
		return fmt.Errorf("tx %s not found in block %s", utx.txid, blockHash)
	}
	header, err := s.btc.BlockHeader(context.Background(), uint64(height))
	if err != nil {
		return err
	}
	root, err := bitcoin.MakeTimestampFromBlock(utx.tip, utx.rawTx, txIndex, txids, header.MerkleRoot)
	if err != nil {
		return err
	}
	att := &notary.BitcoinBlockHeaderAttestation{Height: uint64(height)}
	root.Attestations = append(root.Attestations, att)

	for c, leaf := range utx.leaves {
		if err := s.store.Put([]byte(c), leaf); err != nil {
			return err
		}
	}
	s.log.Info("anchor confirmed",
		"txid", utx.txid, "block_height", height, "block_hash", header.Hash,
		"block_time", header.Time, "commitments", len(utx.leaves))
	return nil
}

func (s *Stamper) maybeSendTx() {
	if len(s.pending) == 0 {
		return
	}
	if !s.lastTxTime.IsZero() && time.Since(s.lastTxTime) < s.cfg.MinTxInterval {
		return
	}

	leaves := make(map[string]*timestamp.Timestamp, len(s.pending))
	shaLeaves := make([]*timestamp.Timestamp, 0, len(s.pending))
	for c := range s.pending {
		leaf, err := timestamp.New([]byte(c))
		if err != nil {
			s.log.Error("bad pending commitment", "err", err)
			delete(s.pending, c)
			continue
		}
		sha, err := leaf.AddOp(op.NewSHA256())
		if err != nil {
			s.log.Error("hash pending commitment", "err", err)
			delete(s.pending, c)
			continue
		}
		leaves[c] = leaf
		shaLeaves = append(shaLeaves, sha)
	}
	if len(shaLeaves) == 0 {
		return
	}
	tip, err := timestamp.MakeMerkleTree(shaLeaves)
	if err != nil {
		s.log.Error("merkleize pending commitments", "err", err)
		return
	}

	txid, rawTx, err := s.btc.SendOpReturn(tip.Msg, s.cfg.MaxFee)
	if err != nil {
		s.log.Error("send anchor tx", "err", err, "commitments", len(leaves))
		return
	}
	stripped, err := bitcoin.StripWitness(rawTx)
	if err != nil {
		s.log.Error("strip witness", "err", err)
		return
	}

	for c := range leaves {
		delete(s.pending, c)
	}
	s.unconfirmed = append(s.unconfirmed, &unconfirmedTx{
		txid:   txid,
		rawTx:  stripped,
		tip:    tip,
		leaves: leaves,
		sentAt: time.Now(),
	})
	s.lastTxTime = time.Now()
	s.log.Info("anchor tx sent",
		"txid", txid, "merkle_tip", hex.EncodeToString(tip.Msg), "commitments", len(leaves))
}

// IsPending reports whether a commitment is queued or waiting for
// confirmations — i.e. known but not yet anchored.
func (s *Stamper) IsPending(commitment []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[string(commitment)]; ok {
		return true
	}
	for _, utx := range s.unconfirmed {
		if _, ok := utx.leaves[string(commitment)]; ok {
			return true
		}
	}
	return false
}

// Status is a snapshot for the status endpoint and health checks.
type Status struct {
	Pending        int        `json:"pending_commitments"`
	UnconfirmedTxs int        `json:"unconfirmed_txs"`
	LastTxTime     *time.Time `json:"last_tx_time,omitempty"`
}

func (s *Stamper) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Pending: len(s.pending), UnconfirmedTxs: len(s.unconfirmed)}
	if !s.lastTxTime.IsZero() {
		t := s.lastTxTime
		st.LastTxTime = &t
	}
	return st
}
