// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package calendarserver

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLogging(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	handler := RequestLogging(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad digest", http.StatusBadRequest)
	}))

	req := httptest.NewRequest(http.MethodPost, "/digest?verbose=1", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	out := buf.String()
	for _, want := range []string{
		"method=POST",
		"path=/digest",
		`query="verbose=1"`,
		"status=400",
		"remote_ip=203.0.113.7",
		`error="bad digest"`,
		"latency=",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log missing %q:\n%s", want, out)
		}
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "x-forwarded-for chain",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Forwarded-For", "198.51.100.2, 10.0.0.5")
				return r
			}(),
			want: "198.51.100.2",
		},
		{
			name: "x-real-ip",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Real-IP", "198.51.100.3")
				return r
			}(),
			want: "198.51.100.3",
		},
		{
			name: "remote addr",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = "192.0.2.1:54321"
				return r
			}(),
			want: "192.0.2.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientIP(tt.req); got != tt.want {
				t.Fatalf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
