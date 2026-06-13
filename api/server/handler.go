// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

import (
	"context"
	"net/http"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

const (
	maxDigestLength = 64
	maxUploadBytes  = 128 << 20 // 128 MiB file uploads
	maxProofBytes   = 1 << 20
	otsAccept       = "application/vnd.opentimestamps.v1"
)

// Backend stamps and upgrades proofs via upstream OpenTimestamps calendars.
type Backend interface {
	Stamp(ctx context.Context, digest []byte) (*timestamp.Timestamp, error)
	GetTimestamp(ctx context.Context, calendarURI string, commitment []byte) (*timestamp.Timestamp, error)
	GetTimestampAny(ctx context.Context, commitment []byte) (*timestamp.Timestamp, error)
	Upgrade(ctx context.Context, ts *timestamp.Timestamp) (bool, error)
	URLs() []string
	Ping(ctx context.Context, url string) error
}

type Handler struct {
	backend Backend
	version string
	headers bitcoin.HeaderSource
}

func NewHandler(backend Backend, version string) *Handler {
	return &Handler{backend: backend, version: version}
}

// WithBitcoin enables Bitcoin-backed verification (optional; verify fails closed without it).
func (h *Handler) WithBitcoin(headers bitcoin.HeaderSource) *Handler {
	h.headers = headers
	return h
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /digest", h.postDigest)
	mux.HandleFunc("GET /timestamp/{commitment}", h.getTimestamp)
	mux.HandleFunc("POST /api/v1/timestamps", h.postCreateJSON)
	mux.HandleFunc("POST /api/v1/verify", h.postVerifyJSON)
	mux.HandleFunc("POST /api/v1/upgrade", h.postUpgradeJSON)
	mux.HandleFunc("POST /api/v1/parse-proof", h.postParseProofJSON)
	mux.HandleFunc("POST /api/v1/stamp-file", h.postStampFile)
	mux.HandleFunc("POST /api/v1/verify-file", h.postVerifyFile)
	mux.HandleFunc("GET /api/v1/status", h.getStatus)
	mux.HandleFunc("GET /api/v1/health", h.getHealth)
}

func (h *Handler) setOTSHeaders(w http.ResponseWriter) {
	w.Header().Set("Accept", otsAccept)
}
