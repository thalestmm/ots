// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-client/otsclient/cmds.py (LGPL-3.0+).

package ots

import (
	"context"
	"time"

	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

// Upgrade asks the calendar for newer attestations and merges them into the
// proof in place. Returns whether the proof changed.
func Upgrade(ctx context.Context, c *Client, ts *timestamp.Timestamp) (bool, error) {
	return verify.Upgrade(ctx, c, ts)
}

// IsComplete reports whether the proof already carries a Bitcoin attestation.
func IsComplete(ts *timestamp.Timestamp) bool {
	return verify.IsComplete(ts)
}

// UpgradeUntilConfirmed polls the calendar until the proof contains a
// confirmed Bitcoin attestation or ctx expires. pollInterval defaults to 30s.
// Bound the wait with context.WithTimeout.
func UpgradeUntilConfirmed(ctx context.Context, c *Client, ts *timestamp.Timestamp, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}
	for {
		if _, err := Upgrade(ctx, c, ts); err != nil {
			return err
		}
		if IsComplete(ts) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
