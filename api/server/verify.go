// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

type calendarUpgrader struct {
	h *Handler
}

func (u calendarUpgrader) GetTimestamp(ctx context.Context, commitment []byte) (*timestamp.Timestamp, error) {
	return u.h.calendar.Get(commitment)
}

func (h *Handler) verifyOptions() verify.Options {
	return verify.Options{Upgrader: calendarUpgrader{h: h}, Headers: h.headers}
}

func verifyResponseFrom(result *verify.Result) VerifyResponse {
	resp := VerifyResponse{
		Valid:       result.Valid,
		Status:      result.Status,
		Reason:      result.Reason,
		BlockHeight: result.BlockHeight,
		BlockHash:   result.BlockHash,
	}
	if result.VerifiedAt != nil {
		resp.VerifiedAt = result.VerifiedAt.UTC().Format(time.RFC3339)
	}
	for _, att := range result.Attestations {
		resp.Attestations = append(resp.Attestations, AttestationInfoJSON{
			Kind: att.Kind, Detail: att.Detail, Status: att.Status,
		})
	}
	return resp
}

// postVerifyJSON godoc
// @Summary      Verify timestamp proof
// @Description  Verifies digest binding, resolves pending attestations against this calendar, and checks Bitcoin attestations against block headers. valid=true only for cryptographically confirmed proofs.
// @Tags         timestamps
// @Accept       json
// @Produce      json
// @Param        request  body  VerifyRequest  true  "Digest and proof"
// @Success      200  {object}  VerifyResponse
// @Failure      400  {object}  ErrorResponse
// @Router       /api/v1/verify [post]
func (h *Handler) postVerifyJSON(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	digest, err := hex.DecodeString(req.Digest)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "digest must be hex-encoded")
		return
	}
	proofBytes, err := hex.DecodeString(req.Proof)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "proof must be hex-encoded")
		return
	}
	ts, err := timestamp.DeserializeBytes(proofBytes, digest)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid proof")
		return
	}

	result, err := verify.VerifyProof(r.Context(), h.verifyOptions(), ts, digest)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, verifyResponseFrom(result))
}

// postUpgradeJSON godoc
// @Summary      Upgrade timestamp proof
// @Description  Resolves pending attestations against this calendar and returns the (possibly) upgraded proof. complete=true once a Bitcoin attestation is present.
// @Tags         timestamps
// @Accept       json
// @Produce      json
// @Param        request  body  UpgradeRequest  true  "Digest and proof"
// @Success      200  {object}  UpgradeResponse
// @Failure      400  {object}  ErrorResponse
// @Router       /api/v1/upgrade [post]
func (h *Handler) postUpgradeJSON(w http.ResponseWriter, r *http.Request) {
	var req UpgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	digest, err := hex.DecodeString(req.Digest)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "digest must be hex-encoded")
		return
	}
	proofBytes, err := hex.DecodeString(req.Proof)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "proof must be hex-encoded")
		return
	}
	ts, err := timestamp.DeserializeBytes(proofBytes, digest)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid proof")
		return
	}

	upgraded, err := verify.Upgrade(r.Context(), calendarUpgrader{h: h}, ts)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, err := ts.SerializeBytes()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, UpgradeResponse{
		Proof:    hex.EncodeToString(data),
		Upgraded: upgraded,
		Complete: verify.IsComplete(ts),
	})
}
