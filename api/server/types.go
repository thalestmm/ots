// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

type CreateTimestampRequest struct {
	Digest string `json:"digest" example:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
}

type CreateTimestampResponse struct {
	Proof      string `json:"proof"`
	Commitment string `json:"commitment"`
}

type VerifyRequest struct {
	Digest string `json:"digest" example:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
	Proof  string `json:"proof"`
}

type VerifyResponse struct {
	Valid        bool                  `json:"valid"`
	Status       string                `json:"status" example:"confirmed"`
	Reason       string                `json:"reason,omitempty"`
	VerifiedAt   string                `json:"verified_at,omitempty" example:"2026-06-12T14:00:00Z"`
	BlockHeight  uint64                `json:"block_height,omitempty" example:"850000"`
	BlockHash    string                `json:"block_hash,omitempty"`
	Attestations []AttestationInfoJSON `json:"attestations"`
}

type AttestationInfoJSON struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	Status string `json:"status"`
}

type UpgradeRequest struct {
	Digest string `json:"digest" example:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
	Proof  string `json:"proof"`
}

type UpgradeResponse struct {
	Proof    string `json:"proof"`
	Upgraded bool   `json:"upgraded"`
	Complete bool   `json:"complete"`
}

type StatusResponse struct {
	Version            string  `json:"version"`
	CalendarURI        string  `json:"calendar_uri"`
	StamperEnabled     bool    `json:"stamper_enabled"`
	PendingCommitments int     `json:"pending_commitments"`
	UnconfirmedTxs     int     `json:"unconfirmed_txs"`
	LastTxTime         string  `json:"last_tx_time,omitempty"`
	BestBlockHeight    int64   `json:"best_block_height,omitempty"`
	WalletBalanceBTC   float64 `json:"wallet_balance_btc,omitempty"`
	BitcoinNetwork     string  `json:"bitcoin_network,omitempty"`
}

type HealthResponse struct {
	Status  string `json:"status" example:"ok"`
	Bitcoin string `json:"bitcoin,omitempty" example:"ok"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
