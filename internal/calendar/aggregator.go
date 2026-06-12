// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-server/otsserver/calendar.py (LGPL-3.0+).

package calendar

import (
	"context"
	"sync"
	"time"

	"github.com/thalestmm/ots/internal/core/timestamp"
)

type submitRequest struct {
	digest *timestamp.Timestamp
	done   chan struct{}
}

type Aggregator struct {
	calendar *Service
	interval time.Duration
	queue    chan submitRequest
	wg       sync.WaitGroup
}

func NewAggregator(calendar *Service, interval time.Duration) *Aggregator {
	if interval <= 0 {
		interval = time.Second
	}
	a := &Aggregator{
		calendar: calendar,
		interval: interval,
		queue:    make(chan submitRequest, 1024),
	}
	a.wg.Add(1)
	go a.loop()
	return a
}

func (a *Aggregator) Close() {
	close(a.queue)
	a.wg.Wait()
}

func (a *Aggregator) loop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	var batch []submitRequest

	flush := func() {
		if len(batch) == 0 {
			return
		}
		digests := make([]*timestamp.Timestamp, len(batch))
		for i, req := range batch {
			digests[i] = req.digest
		}
		commitment, err := timestamp.MakeMerkleTree(digests)
		if err == nil {
			_, _ = a.calendar.Submit(commitment)
		}
		for _, req := range batch {
			close(req.done)
		}
		batch = batch[:0]
	}

	for {
		select {
		case req, ok := <-a.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, req)
		case <-ticker.C:
			flush()
		}
	}
}

func (a *Aggregator) Submit(ctx context.Context, msg []byte) (*timestamp.Timestamp, error) {
	ts, err := timestamp.New(msg)
	if err != nil {
		return nil, err
	}
	nonced, err := timestamp.NonceTimestamp(ts, 16)
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	req := submitRequest{digest: nonced, done: done}
	select {
	case a.queue <- req:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case <-done:
		return ts, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
