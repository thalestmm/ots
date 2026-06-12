// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package ots

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

// DefaultCalendars are public mainnet OpenTimestamps calendar servers.
var DefaultCalendars = []string{
	"https://alice.btc.calendar.opentimestamps.org",
	"https://bob.btc.calendar.opentimestamps.org",
	"https://finney.calendar.eternitywall.com",
}

// Pool fans out stamp and upgrade requests to multiple upstream calendars.
type Pool struct {
	calendars map[string]*Client
	urls      []string
}

// NewPool creates a multi-calendar client pool. URLs are normalized (no trailing slash).
func NewPool(urls []string) (*Pool, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("at least one calendar URL required")
	}
	p := &Pool{
		calendars: make(map[string]*Client, len(urls)),
		urls:      make([]string, 0, len(urls)),
	}
	seen := make(map[string]struct{}, len(urls))
	for _, raw := range urls {
		u := strings.TrimRight(strings.TrimSpace(raw), "/")
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		p.urls = append(p.urls, u)
		p.calendars[u] = NewClient(u)
	}
	if len(p.urls) == 0 {
		return nil, fmt.Errorf("no valid calendar URLs")
	}
	return p, nil
}

// NewPoolWithTimeout is like NewPool but sets the HTTP timeout on each client.
func NewPoolWithTimeout(urls []string, timeout time.Duration) (*Pool, error) {
	p, err := NewPool(urls)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: timeout}
	for _, u := range p.urls {
		p.calendars[u].WithHTTPClient(hc)
	}
	return p, nil
}

// URLs returns the configured calendar base URLs in stamp order.
func (p *Pool) URLs() []string {
	out := make([]string, len(p.urls))
	copy(out, p.urls)
	return out
}

// Client returns the client for a calendar base URL, if configured.
func (p *Pool) Client(calendarURI string) (*Client, bool) {
	u := strings.TrimRight(strings.TrimSpace(calendarURI), "/")
	c, ok := p.calendars[u]
	return c, ok
}

type stampResult struct {
	proof *timestamp.Timestamp
	err   error
}

// Stamp submits digest to all calendars in parallel and merges successful proofs.
// It fails only when every calendar fails.
func (p *Pool) Stamp(ctx context.Context, digest []byte) (*timestamp.Timestamp, error) {
	root, err := timestamp.New(digest)
	if err != nil {
		return nil, err
	}

	results := make(chan stampResult, len(p.urls))
	var wg sync.WaitGroup
	for _, u := range p.urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			proof, err := p.calendars[url].Submit(ctx, digest)
			results <- stampResult{proof: proof, err: err}
		}(u)
	}
	wg.Wait()
	close(results)

	var merged *timestamp.Timestamp
	var errs []error
	for r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		if merged == nil {
			merged = root
		}
		if err := merged.Merge(r.proof); err != nil {
			errs = append(errs, err)
		}
	}
	if merged == nil {
		return nil, fmt.Errorf("all calendars failed: %v", errs)
	}
	return merged, nil
}

// GetTimestamp fetches an upgraded proof from the calendar identified by calendarURI.
func (p *Pool) GetTimestamp(ctx context.Context, calendarURI string, commitment []byte) (*timestamp.Timestamp, error) {
	c, ok := p.Client(calendarURI)
	if !ok {
		return nil, fmt.Errorf("unknown calendar %q", calendarURI)
	}
	return c.GetTimestamp(ctx, calendarURI, commitment)
}

// GetTimestampAny queries all configured calendars in parallel and returns the
// first successful upgraded proof (for native GET /timestamp/{hex}).
func (p *Pool) GetTimestampAny(ctx context.Context, commitment []byte) (*timestamp.Timestamp, error) {
	type result struct {
		proof *timestamp.Timestamp
		err   error
	}
	ch := make(chan result, len(p.urls))
	var wg sync.WaitGroup
	for _, u := range p.urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			proof, err := p.calendars[url].GetTimestamp(ctx, url, commitment)
			ch <- result{proof: proof, err: err}
		}(u)
	}
	wg.Wait()
	close(ch)

	var errs []error
	for r := range ch {
		if r.err == nil {
			return r.proof, nil
		}
		errs = append(errs, r.err)
	}
	return nil, fmt.Errorf("commitment not found on any calendar: %v", errs)
}

// Upgrade resolves pending attestations against upstream calendars.
func (p *Pool) Upgrade(ctx context.Context, ts *timestamp.Timestamp) (bool, error) {
	return verify.Upgrade(ctx, p, ts)
}

// Ping checks that a calendar responds to HTTP. Any non-connection error counts as reachable.
func (p *Pool) Ping(ctx context.Context, url string) error {
	c, ok := p.calendars[url]
	if !ok {
		return fmt.Errorf("unknown calendar %q", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.baseURL+"/", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Some calendars may not support HEAD; try GET on digest with empty body expectation.
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/", nil)
		if err2 != nil {
			return err
		}
		resp2, err2 := c.httpClient.Do(req2)
		if err2 != nil {
			return err
		}
		resp2.Body.Close()
		return nil
	}
	resp.Body.Close()
	return nil
}
