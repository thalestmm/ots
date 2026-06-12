// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package calendarserver

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

// postStampFile godoc
func (h *Handler) postStampFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, `multipart field "file" required`)
		return
	}
	defer file.Close()

	det, err := timestamp.FromReader(&op.SHA256Op{}, file)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("hash file: %v", err))
		return
	}
	proof, err := h.aggregator.Submit(r.Context(), det.FileDigest())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := det.Timestamp.Merge(proof); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, err := det.SerializeBytes()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	name := filepath.Base(header.Filename)
	if name == "" || name == "." || name == "/" {
		name = "file"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.ots"`, name))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// postVerifyFile godoc
func (h *Handler) postVerifyFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, `multipart field "file" required`)
		return
	}
	defer file.Close()
	otsFile, _, err := r.FormFile("ots")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, `multipart field "ots" required`)
		return
	}
	defer otsFile.Close()

	otsData := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for len(otsData) <= maxProofBytes {
		n, rerr := otsFile.Read(buf)
		otsData = append(otsData, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	if len(otsData) > maxProofBytes {
		writeJSONError(w, http.StatusBadRequest, "proof too large")
		return
	}
	det, err := timestamp.DeserializeDetachedBytes(otsData)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid .ots proof: %v", err))
		return
	}

	result, err := verify.VerifyDetached(r.Context(), h.verifyOptions(), file, det.Timestamp)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, verifyResponseFrom(result))
}
