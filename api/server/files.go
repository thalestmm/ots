// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

// postStampFile godoc
// @Summary      Stamp a file
// @Description  Multipart upload (field "file"). The file is hashed server-side with SHA-256 and submitted to the calendar. Returns a standard detached .ots proof as bytes. Only the hash is retained.
// @Tags         files
// @Accept       multipart/form-data
// @Produce      application/octet-stream
// @Param        file  formData  file  true  "File to timestamp"
// @Success      200  {string}  string  "Detached .ots proof bytes"
// @Failure      400  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /api/v1/stamp-file [post]
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
// @Summary      Verify a file against its .ots proof
// @Description  Multipart upload: field "file" (original content) and field "ots" (detached proof). Returns the full verification result.
// @Tags         files
// @Accept       multipart/form-data
// @Produce      json
// @Param        file  formData  file  true  "Original file"
// @Param        ots   formData  file  true  "Detached .ots proof"
// @Success      200  {object}  VerifyResponse
// @Failure      400  {object}  ErrorResponse
// @Router       /api/v1/verify-file [post]
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
