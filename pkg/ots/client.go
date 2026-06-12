// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from python-opentimestamps/opentimestamps/calendar.py (LGPL-3.0+).

package ots

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/thalestmm/ots/internal/core/timestamp"
)

const (
	acceptHeader = "application/vnd.opentimestamps.v1"
	maxResponse  = 10000
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

func NewClient(calendarURL string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(calendarURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  "ots-go/0.1.0",
	}
}

func (c *Client) WithHTTPClient(hc *http.Client) *Client {
	c.httpClient = hc
	return c
}

func (c *Client) Submit(ctx context.Context, digest []byte) (*timestamp.Timestamp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/digest", bytes.NewReader(digest))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("submit failed: %s", string(body))
	}
	return timestamp.DeserializeBytes(body, digest)
}

func (c *Client) GetTimestamp(ctx context.Context, commitment []byte) (*timestamp.Timestamp, error) {
	url := fmt.Sprintf("%s/timestamp/%x", c.baseURL, commitment)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get timestamp failed: %s", string(body))
	}
	return timestamp.DeserializeBytes(body, commitment)
}
