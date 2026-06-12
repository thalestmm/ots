// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thalestmm/ots/internal/calendar"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	hmacKey := make([]byte, 32)
	store := calendar.NewMemoryStore()
	cal := calendar.NewService("http://cal.example.com", hmacKey, store)
	agg := calendar.NewAggregator(cal, 10*time.Millisecond)
	t.Cleanup(agg.Close)

	h := NewHandler(agg, cal, "test")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestStampThenUpgradeThenVerify(t *testing.T) {
	srv := newTestServer(t)
	digest := sha256.Sum256([]byte("compliance evidence"))

	// 1. Stamp via the native endpoint.
	resp, err := http.Post(srv.URL+"/digest", "application/octet-stream", bytes.NewReader(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /digest = %d: %s", resp.StatusCode, proofBytes)
	}
	proof, err := timestamp.DeserializeBytes(proofBytes, digest[:])
	if err != nil {
		t.Fatalf("returned proof invalid: %v", err)
	}

	// 2. The pending attestation's commitment must be servable.
	var commitment []byte
	for _, item := range proof.AllAttestations() {
		commitment = item.Msg
	}
	if commitment == nil {
		t.Fatal("no attestation in proof")
	}
	resp, err = http.Get(srv.URL + "/timestamp/" + hex.EncodeToString(commitment))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /timestamp = %d: %s", resp.StatusCode, body)
	}

	// 3. Upgrade endpoint round-trips the proof.
	upgradeReq, _ := json.Marshal(UpgradeRequest{
		Digest: hex.EncodeToString(digest[:]),
		Proof:  hex.EncodeToString(proofBytes),
	})
	resp, err = http.Post(srv.URL+"/api/v1/upgrade", "application/json", bytes.NewReader(upgradeReq))
	if err != nil {
		t.Fatal(err)
	}
	var upgrade UpgradeResponse
	if err := json.NewDecoder(resp.Body).Decode(&upgrade); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if upgrade.Complete {
		t.Fatal("proof complete without a stamper — impossible")
	}

	// 4. Verify: pending-only proof must fail closed.
	verifyReq, _ := json.Marshal(VerifyRequest{
		Digest: hex.EncodeToString(digest[:]),
		Proof:  upgrade.Proof,
	})
	resp, err = http.Post(srv.URL+"/api/v1/verify", "application/json", bytes.NewReader(verifyReq))
	if err != nil {
		t.Fatal(err)
	}
	var verifyResp VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if verifyResp.Valid {
		t.Fatalf("pending proof verified as valid: %+v", verifyResp)
	}
	if verifyResp.Status != "pending" {
		t.Fatalf("status = %q, want pending", verifyResp.Status)
	}
	if len(verifyResp.Attestations) == 0 {
		t.Fatal("no attestations reported")
	}
}

func TestStampFileAndVerifyFile(t *testing.T) {
	srv := newTestServer(t)
	content := []byte("the quick brown fox signs a contract")

	// Stamp the file.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "contract.pdf")
	fw.Write(content)
	mw.Close()
	resp, err := http.Post(srv.URL+"/api/v1/stamp-file", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	otsBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stamp-file = %d: %s", resp.StatusCode, otsBytes)
	}
	det, err := timestamp.DeserializeDetachedBytes(otsBytes)
	if err != nil {
		t.Fatalf("returned .ots invalid: %v", err)
	}
	wantDigest := sha256.Sum256(content)
	if !bytes.Equal(det.FileDigest(), wantDigest[:]) {
		t.Fatal(".ots digest does not match file")
	}

	// Verify the matching file.
	var buf2 bytes.Buffer
	mw2 := multipart.NewWriter(&buf2)
	fw, _ = mw2.CreateFormFile("file", "contract.pdf")
	fw.Write(content)
	ow, _ := mw2.CreateFormFile("ots", "contract.pdf.ots")
	ow.Write(otsBytes)
	mw2.Close()
	resp, err = http.Post(srv.URL+"/api/v1/verify-file", mw2.FormDataContentType(), &buf2)
	if err != nil {
		t.Fatal(err)
	}
	var vr VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if vr.Status != "pending" {
		t.Fatalf("status = %q, want pending (no stamper in test)", vr.Status)
	}

	// Verify a tampered file: must be rejected outright.
	var buf3 bytes.Buffer
	mw3 := multipart.NewWriter(&buf3)
	fw, _ = mw3.CreateFormFile("file", "contract.pdf")
	fw.Write([]byte("tampered content"))
	ow, _ = mw3.CreateFormFile("ots", "contract.pdf.ots")
	ow.Write(otsBytes)
	mw3.Close()
	resp, err = http.Post(srv.URL+"/api/v1/verify-file", mw3.FormDataContentType(), &buf3)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if vr.Valid || vr.Status != "invalid" {
		t.Fatalf("tampered file: got %+v, want invalid", vr)
	}
}

func TestStatusAndHealth(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	var st StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if st.CalendarURI != "http://cal.example.com" || st.StamperEnabled {
		t.Fatalf("unexpected status: %+v", st)
	}

	resp, err = http.Get(srv.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", resp.StatusCode)
	}
}

func TestGetTimestampUnknownCommitment(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/timestamp/deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("not found")) {
		t.Fatalf("404 body = %q, want not-found message", body)
	}
}

// Aggregator batches multiple concurrent submissions into one merkle tree;
// every client must get a serializable proof (regression for the left-branch
// dead-end bug in CatThenUnaryOp).
func TestConcurrentSubmissionsShareBatch(t *testing.T) {
	srv := newTestServer(t)
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			digest := sha256.Sum256([]byte{byte(i)})
			resp, err := http.Post(srv.URL+"/digest", "application/octet-stream", bytes.NewReader(digest[:]))
			if err != nil {
				results <- err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				results <- &httpError{code: resp.StatusCode, body: string(body)}
				return
			}
			_, err = timestamp.DeserializeBytes(body, digest[:])
			results <- err
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string { return e.body }
