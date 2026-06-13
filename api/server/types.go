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

type ParseProofRequest struct {
	Digest string `json:"digest" example:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
	Proof  string `json:"proof"`
}

type ParseProofResponse struct {
	Complete         bool     `json:"complete"`
	BlockHeight      uint64   `json:"block_height,omitempty" example:"850000"`
	BlockHeights     []uint64 `json:"block_heights,omitempty"`
	PendingCalendars []string `json:"pending_calendars,omitempty"`
}

type CalendarStatus struct {
	URL       string `json:"url"`
	Reachable bool   `json:"reachable"`
	Detail    string `json:"detail,omitempty"`
}

type StatusResponse struct {
	Version       string           `json:"version"`
	Calendars     []CalendarStatus `json:"calendars"`
	BitcoinVerify string           `json:"bitcoin_verify,omitempty" example:"enabled"`
}

type HealthResponse struct {
	Status    string           `json:"status" example:"ok"`
	Calendars []CalendarStatus `json:"calendars"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
