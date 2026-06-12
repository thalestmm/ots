// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-server/otsserver/rpc.py (LGPL-3.0+).

package server

import (
	"net/http"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/calendar"
	"github.com/thalestmm/ots/internal/stamper"
)

const (
	maxDigestLength = 64
	maxUploadBytes  = 128 << 20 // 128 MiB file uploads
	maxProofBytes   = 1 << 20
	otsAccept       = "application/vnd.opentimestamps.v1"
)

type Handler struct {
	aggregator *calendar.Aggregator
	calendar   *calendar.Service
	version    string

	// Optional Bitcoin integration; nil when running calendar-only.
	headers bitcoin.HeaderSource
	btc     *bitcoin.Client
	stamper *stamper.Stamper
}

func NewHandler(aggregator *calendar.Aggregator, cal *calendar.Service, version string) *Handler {
	return &Handler{aggregator: aggregator, calendar: cal, version: version}
}

// WithBitcoin enables Bitcoin-backed verification and stamper status
// reporting. Any argument may be nil.
func (h *Handler) WithBitcoin(btc *bitcoin.Client, st *stamper.Stamper) *Handler {
	h.btc = btc
	if btc != nil {
		h.headers = btc
	}
	h.stamper = st
	return h
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /digest", h.postDigest)
	mux.HandleFunc("GET /timestamp/{commitment}", h.getTimestamp)
	mux.HandleFunc("POST /api/v1/timestamps", h.postCreateJSON)
	mux.HandleFunc("POST /api/v1/verify", h.postVerifyJSON)
	mux.HandleFunc("POST /api/v1/upgrade", h.postUpgradeJSON)
	mux.HandleFunc("POST /api/v1/stamp-file", h.postStampFile)
	mux.HandleFunc("POST /api/v1/verify-file", h.postVerifyFile)
	mux.HandleFunc("GET /api/v1/status", h.getStatus)
	mux.HandleFunc("GET /api/v1/health", h.getHealth)
}

func (h *Handler) setOTSHeaders(w http.ResponseWriter) {
	w.Header().Set("Accept", otsAccept)
}
