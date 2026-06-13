// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

import (
	"bytes"
	"context"
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
	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/pkg/ots"
)

func newMockUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	hmacKey := make([]byte, 32)
	store := calendar.NewMemoryStore()

	var cal *calendar.Service
	var agg *calendar.Aggregator

	mux := http.NewServeMux()
	mux.HandleFunc("POST /digest", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64))
		if len(body) == 0 {
			http.Error(w, "empty digest", http.StatusBadRequest)
			return
		}
		ts, err := agg.Submit(r.Context(), body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, _ := ts.SerializeBytes()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /timestamp/{commitment}", func(w http.ResponseWriter, r *http.Request) {
		hexCommitment := r.PathValue("commitment")
		commitment, err := hex.DecodeString(hexCommitment)
		if err != nil {
			http.Error(w, "invalid commitment", http.StatusBadRequest)
			return
		}
		ts, err := cal.Get(commitment)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		data, _ := ts.SerializeBytes()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	cal = calendar.NewService(srv.URL, hmacKey, store)
	agg = calendar.NewAggregator(cal, 10*time.Millisecond)
	t.Cleanup(func() {
		agg.Close()
		srv.Close()
	})
	return srv
}

func newTestRelay(t *testing.T, upstreams ...*httptest.Server) *httptest.Server {
	t.Helper()
	var urls []string
	for _, u := range upstreams {
		urls = append(urls, u.URL)
	}
	pool, err := ots.NewPool(urls)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(pool, "test")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestStampThenUpgradeThenVerify(t *testing.T) {
	upstream := newMockUpstream(t)
	srv := newTestRelay(t, upstream)
	digest := sha256.Sum256([]byte("compliance evidence"))

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
		t.Fatal("proof complete without Bitcoin anchoring — impossible")
	}

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
}

func TestStampFileAndVerifyFile(t *testing.T) {
	upstream := newMockUpstream(t)
	srv := newTestRelay(t, upstream)
	content := []byte("the quick brown fox signs a contract")

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
		t.Fatalf("status = %q, want pending", vr.Status)
	}

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
	upstream := newMockUpstream(t)
	srv := newTestRelay(t, upstream)

	resp, err := http.Get(srv.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	var st StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(st.Calendars) != 1 || st.Calendars[0].URL != upstream.URL {
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
	upstream := newMockUpstream(t)
	srv := newTestRelay(t, upstream)
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
		t.Fatalf("404 body = %q", body)
	}
}

func TestMultiUpstreamStamp(t *testing.T) {
	upA := newMockUpstream(t)
	upB := newMockUpstream(t)
	srv := newTestRelay(t, upA, upB)

	digest := sha256.Sum256([]byte("multi"))
	resp, err := http.Post(srv.URL+"/digest", "application/octet-stream", bytes.NewReader(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /digest = %d", resp.StatusCode)
	}
	proof, err := timestamp.DeserializeBytes(proofBytes, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	pending := 0
	for _, item := range proof.AllAttestations() {
		if _, ok := item.Att.(*notary.PendingAttestation); ok {
			pending++
		}
	}
	if pending != 2 {
		t.Fatalf("pending attestations = %d, want 2", pending)
	}
}

func TestParseProofEndpoint(t *testing.T) {
	upstream := newMockUpstream(t)
	srv := newTestRelay(t, upstream)
	digest := sha256.Sum256([]byte("compliance evidence"))

	resp, err := http.Post(srv.URL+"/digest", "application/octet-stream", bytes.NewReader(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	parseReq, _ := json.Marshal(ParseProofRequest{
		Digest: hex.EncodeToString(digest[:]),
		Proof:  hex.EncodeToString(proofBytes),
	})
	resp, err = http.Post(srv.URL+"/api/v1/parse-proof", "application/json", bytes.NewReader(parseReq))
	if err != nil {
		t.Fatal(err)
	}
	var parseResp ParseProofResponse
	if err := json.NewDecoder(resp.Body).Decode(&parseResp); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if parseResp.Complete {
		t.Fatal("pending proof should not be complete")
	}
	if parseResp.BlockHeight != 0 {
		t.Fatalf("block_height = %d, want 0", parseResp.BlockHeight)
	}
	if len(parseResp.PendingCalendars) != 1 {
		t.Fatalf("pending_calendars = %v", parseResp.PendingCalendars)
	}
}

func TestParseProofEndpointConfirmed(t *testing.T) {
	digest := sha256.Sum256([]byte("confirmed doc"))
	ts, err := timestamp.New(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	node, err := ts.AddOp(op.NewSHA256())
	if err != nil {
		t.Fatal(err)
	}
	node.Attestations = append(node.Attestations, &notary.BitcoinBlockHeaderAttestation{Height: 850000})
	proofBytes, err := ts.SerializeBytes()
	if err != nil {
		t.Fatal(err)
	}

	upstream := newMockUpstream(t)
	srv := newTestRelay(t, upstream)

	parseReq, _ := json.Marshal(ParseProofRequest{
		Digest: hex.EncodeToString(digest[:]),
		Proof:  hex.EncodeToString(proofBytes),
	})
	resp, err := http.Post(srv.URL+"/api/v1/parse-proof", "application/json", bytes.NewReader(parseReq))
	if err != nil {
		t.Fatal(err)
	}
	var parseResp ParseProofResponse
	if err := json.NewDecoder(resp.Body).Decode(&parseResp); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !parseResp.Complete || parseResp.BlockHeight != 850000 {
		t.Fatalf("got %+v, want complete with height 850000", parseResp)
	}
}

func TestBackendPing(t *testing.T) {
	upstream := newMockUpstream(t)
	pool, err := ots.NewPool([]string{upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.Ping(ctx, upstream.URL); err != nil {
		t.Fatal(err)
	}
}
