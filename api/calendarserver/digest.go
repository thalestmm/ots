// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package calendarserver

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
)

// postDigest godoc
func (h *Handler) postDigest(w http.ResponseWriter, r *http.Request) {
	h.setOTSHeaders(w)
	if r.ContentLength < 0 {
		http.Error(w, "invalid Content-Length", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDigestLength+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 || len(body) > maxDigestLength {
		http.Error(w, "digest too long", http.StatusBadRequest)
		return
	}

	ts, err := h.aggregator.Submit(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := ts.SerializeBytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// postCreateJSON godoc
func (h *Handler) postCreateJSON(w http.ResponseWriter, r *http.Request) {
	var req CreateTimestampRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	digest, err := hex.DecodeString(req.Digest)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "digest must be hex-encoded")
		return
	}
	if len(digest) == 0 || len(digest) > maxDigestLength {
		writeJSONError(w, http.StatusBadRequest, "invalid digest length")
		return
	}

	ts, err := h.aggregator.Submit(r.Context(), digest)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	proof, err := ts.SerializeBytes()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, CreateTimestampResponse{
		Proof:      hex.EncodeToString(proof),
		Commitment: hex.EncodeToString(ts.Msg),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}
