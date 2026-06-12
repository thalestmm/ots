// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package ots

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thalestmm/ots/internal/calendar"
	"github.com/thalestmm/ots/internal/core/notary"
)

func mockCalendarServer(t *testing.T, fail bool) *httptest.Server {
	t.Helper()
	hmacKey := make([]byte, 32)
	store := calendar.NewMemoryStore()

	var cal *calendar.Service
	var agg *calendar.Aggregator

	mux := http.NewServeMux()
	mux.HandleFunc("POST /digest", func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
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
		if fail {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
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
	agg = calendar.NewAggregator(cal, time.Millisecond)
	t.Cleanup(func() {
		agg.Close()
		srv.Close()
	})
	return srv
}

func TestPoolStampAllSucceed(t *testing.T) {
	srvA := mockCalendarServer(t, false)
	srvB := mockCalendarServer(t, false)

	pool, err := NewPool([]string{srvA.URL, srvB.URL})
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("pool test"))
	proof, err := pool.Stamp(context.Background(), digest[:])
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

func TestPoolStampPartialFailure(t *testing.T) {
	srvOK := mockCalendarServer(t, false)
	srvFail := mockCalendarServer(t, true)

	pool, err := NewPool([]string{srvOK.URL, srvFail.URL})
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("partial"))
	proof, err := pool.Stamp(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.AllAttestations()) == 0 {
		t.Fatal("expected at least one attestation from surviving calendar")
	}
}

func TestPoolStampAllFail(t *testing.T) {
	srvA := mockCalendarServer(t, true)
	srvB := mockCalendarServer(t, true)

	pool, err := NewPool([]string{srvA.URL, srvB.URL})
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("all fail"))
	_, err = pool.Stamp(context.Background(), digest[:])
	if err == nil {
		t.Fatal("expected error when all calendars fail")
	}
}

func TestPoolGetTimestampAny(t *testing.T) {
	srv := mockCalendarServer(t, false)
	pool, err := NewPool([]string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("route"))
	proof, err := pool.Stamp(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var commitment []byte
	for _, item := range proof.AllAttestations() {
		commitment = item.Msg
		break
	}
	if commitment == nil {
		t.Fatal("no commitment")
	}

	upgraded, err := pool.GetTimestampAny(context.Background(), commitment)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded == nil {
		t.Fatal("nil upgraded proof")
	}
}

func TestPoolUpgradePending(t *testing.T) {
	srv := mockCalendarServer(t, false)
	pool, err := NewPool([]string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("upgrade"))
	proof, err := pool.Stamp(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.Upgrade(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewPoolEmpty(t *testing.T) {
	_, err := NewPool(nil)
	if err == nil {
		t.Fatal("expected error for empty pool")
	}
}
