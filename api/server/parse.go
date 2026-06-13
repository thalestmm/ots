// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

// postParseProofJSON godoc
// @Summary      Parse timestamp proof metadata
// @Description  Extracts embedded attestation metadata (Bitcoin block heights, pending calendars) from a proof without contacting upstream calendars or a Bitcoin node. Does not cryptographically verify the anchor.
// @Tags         timestamps
// @Accept       json
// @Produce      json
// @Param        request  body  ParseProofRequest  true  "Digest and proof"
// @Success      200  {object}  ParseProofResponse
// @Failure      400  {object}  ErrorResponse
// @Router       /api/v1/parse-proof [post]
func (h *Handler) postParseProofJSON(w http.ResponseWriter, r *http.Request) {
	var req ParseProofRequest
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

	result, err := verify.ParseProof(ts, digest)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ParseProofResponse{
		Complete:          result.Complete,
		BlockHeight:       result.BlockHeight,
		BlockHeights:      result.BlockHeights,
		PendingCalendars:  result.PendingURIs,
	})
}
