// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxLoggedErrorBody = 512

// RequestLogging wraps an HTTP handler with structured request logs.
func RequestLogging(log *slog.Logger, next http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w}

		next.ServeHTTP(lw, r)

		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", lw.status,
			"latency", time.Since(start),
			"remote_ip", clientIP(r),
		}
		if r.URL.RawQuery != "" {
			attrs = append(attrs, "query", r.URL.RawQuery)
		}
		if lw.bytes > 0 {
			attrs = append(attrs, "bytes", lw.bytes)
		}
		if msg := lw.errorMessage(); msg != "" {
			attrs = append(attrs, "error", msg)
		}

		switch {
		case lw.status >= http.StatusInternalServerError:
			log.Error("request", attrs...)
		case lw.status >= http.StatusBadRequest:
			log.Warn("request", attrs...)
		default:
			log.Info("request", attrs...)
		}
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	body   []byte
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.status >= http.StatusBadRequest && len(w.body) < maxLoggedErrorBody {
		remain := maxLoggedErrorBody - len(w.body)
		if len(b) <= remain {
			w.body = append(w.body, b...)
		} else {
			w.body = append(w.body, b[:remain]...)
		}
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *loggingResponseWriter) errorMessage() string {
	return strings.TrimSpace(string(w.body))
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
