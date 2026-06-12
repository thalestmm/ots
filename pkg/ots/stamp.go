// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package ots

import (
	"context"
	"io"

	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

func StampDigest(ctx context.Context, c *Client, digest []byte) (*timestamp.DetachedTimestampFile, error) {
	root, err := timestamp.New(digest)
	if err != nil {
		return nil, err
	}
	det, err := timestamp.NewDetached(&op.SHA256Op{}, root)
	if err != nil {
		return nil, err
	}
	proof, err := c.Submit(ctx, digest)
	if err != nil {
		return nil, err
	}
	if err := det.Timestamp.Merge(proof); err != nil {
		return nil, err
	}
	return det, nil
}

func StampFile(ctx context.Context, c *Client, r io.Reader) (*timestamp.DetachedTimestampFile, error) {
	det, err := timestamp.FromReader(&op.SHA256Op{}, r)
	if err != nil {
		return nil, err
	}
	proof, err := c.Submit(ctx, det.FileDigest())
	if err != nil {
		return nil, err
	}
	if err := det.Timestamp.Merge(proof); err != nil {
		return nil, err
	}
	return det, nil
}
