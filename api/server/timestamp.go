// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

import (
	"context"
	"encoding/hex"
	"net/http"
)

// getTimestamp godoc
// @Summary      Get upgraded timestamp proof
// @Description  OpenTimestamps-native upgrade endpoint. Commitment is hex-encoded bytes. Queries all upstream calendars in parallel.
// @Tags         timestamps
// @Produce      application/octet-stream
// @Param        commitment  path  string  true  "Hex-encoded commitment"
// @Success      200  {string}  string  "Serialized OTS timestamp"
// @Failure      400  {string}  string  "Invalid commitment"
// @Failure      404  {string}  string  "Not found on any calendar"
// @Router       /timestamp/{commitment} [get]
func (h *Handler) getTimestamp(w http.ResponseWriter, r *http.Request) {
	h.setOTSHeaders(w)
	hexCommitment := r.PathValue("commitment")
	commitment, err := hex.DecodeString(hexCommitment)
	if err != nil {
		http.Error(w, "commitment must be hex-encoded bytes", http.StatusBadRequest)
		return
	}

	ts, err := h.backend.GetTimestampAny(r.Context(), commitment)
	if err != nil {
		w.Header().Set("Cache-Control", "public, max-age=60")
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
// @Summary      Health check
// @Description  Reports relay health and upstream calendar reachability.
// @Tags         system
// @Produce      json
// @Success      200  {object}  HealthResponse
// @Failure      503  {object}  HealthResponse
// @Router       /api/v1/health [get]
func (h *Handler) getHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{Status: "ok", Calendars: h.calendarStatuses(r.Context())}
	for _, c := range resp.Calendars {
		if !c.Reachable {
			resp.Status = "degraded"
			writeJSON(w, http.StatusServiceUnavailable, resp)
			return
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// getStatus godoc
// @Summary      Relay status
// @Description  Operational snapshot: configured upstream calendars and optional Bitcoin verify backend.
// @Tags         system
// @Produce      json
// @Success      200  {object}  StatusResponse
// @Router       /api/v1/status [get]
func (h *Handler) getStatus(w http.ResponseWriter, r *http.Request) {
	resp := StatusResponse{
		Version:   h.version,
		Calendars: h.calendarStatuses(r.Context()),
	}
	if h.headers != nil {
		resp.BitcoinVerify = "enabled"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) calendarStatuses(ctx context.Context) []CalendarStatus {
	urls := h.backend.URLs()
	out := make([]CalendarStatus, 0, len(urls))
	for _, u := range urls {
		st := CalendarStatus{URL: u}
		if err := h.backend.Ping(ctx, u); err != nil {
			st.Reachable = false
			st.Detail = err.Error()
		} else {
			st.Reachable = true
		}
		out = append(out, st)
	}
	return out
}
