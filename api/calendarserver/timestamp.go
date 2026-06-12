// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package calendarserver

import (
	"encoding/hex"
	"net/http"
)

// getTimestamp godoc
func (h *Handler) getTimestamp(w http.ResponseWriter, r *http.Request) {
	h.setOTSHeaders(w)
	hexCommitment := r.PathValue("commitment")
	commitment, err := hex.DecodeString(hexCommitment)
	if err != nil {
		http.Error(w, "commitment must be hex-encoded bytes", http.StatusBadRequest)
		return
	}

	ts, err := h.calendar.Get(commitment)
	if err != nil {
		w.Header().Set("Cache-Control", "public, max-age=60")
		if h.stamper != nil && h.stamper.IsPending(commitment) {
			http.Error(w, "Pending confirmation in Bitcoin blockchain", http.StatusNotFound)
			return
		}
		http.Error(w, "Commitment not found", http.StatusNotFound)
		return
	}
	data, err := ts.SerializeBytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// getHealth godoc
func (h *Handler) getHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{Status: "ok"}
	if h.btc != nil {
		if _, err := h.btc.BlockCount(); err != nil {
			resp.Status = "degraded"
			resp.Bitcoin = "unreachable: " + err.Error()
			writeJSON(w, http.StatusServiceUnavailable, resp)
			return
		}
		resp.Bitcoin = "ok"
	}
	writeJSON(w, http.StatusOK, resp)
}

// getStatus godoc
func (h *Handler) getStatus(w http.ResponseWriter, r *http.Request) {
	resp := StatusResponse{
		Version:     h.version,
		CalendarURI: h.calendar.URI(),
	}
	if h.stamper != nil {
		resp.StamperEnabled = true
		st := h.stamper.Status()
		resp.PendingCommitments = st.Pending
		resp.UnconfirmedTxs = st.UnconfirmedTxs
		if st.LastTxTime != nil {
			resp.LastTxTime = st.LastTxTime.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
	}
	if h.btc != nil {
		resp.BitcoinNetwork = h.btc.Network()
		if height, err := h.btc.BlockCount(); err == nil {
			resp.BestBlockHeight = height
		}
		if bal, err := h.btc.WalletBalance(); err == nil {
			resp.WalletBalanceBTC = bal.ToBTC()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
