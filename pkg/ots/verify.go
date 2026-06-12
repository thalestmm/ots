// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package ots

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

type VerifyResult = verify.Result

// BlockHeader mirrors the fields of a Bitcoin block header needed for
// trust-minimized verification. MerkleRoot is internal byte order.
type BlockHeader struct {
	Height     uint64
	Hash       string
	MerkleRoot []byte
	Time       time.Time
}

// HeaderSource supplies Bitcoin block headers, e.g. from a local Bitcoin
// Core node. Verification without a HeaderSource cannot confirm Bitcoin
// attestations and fails closed (valid=false, status=pending/unverified).
type HeaderSource interface {
	BlockHeader(ctx context.Context, height uint64) (*BlockHeader, error)
}

// BitcoinRPCHeaderSource connects to a Bitcoin Core node for headers.
func BitcoinRPCHeaderSource(host, user, pass, network string) (HeaderSource, error) {
	c, err := bitcoin.NewClient(bitcoin.Config{Host: host, User: user, Pass: pass, Network: network})
	if err != nil {
		return nil, err
	}
	return clientHeaderSource{c}, nil
}

type clientHeaderSource struct{ c *bitcoin.Client }

func (s clientHeaderSource) BlockHeader(ctx context.Context, height uint64) (*BlockHeader, error) {
	h, err := s.c.BlockHeader(ctx, height)
	if err != nil {
		return nil, err
	}
	return &BlockHeader{Height: h.Height, Hash: h.Hash, MerkleRoot: h.MerkleRoot, Time: h.Time}, nil
}

type headerAdapter struct{ src HeaderSource }

func (a headerAdapter) BlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error) {
	h, err := a.src.BlockHeader(ctx, height)
	if err != nil {
		return nil, err
	}
	return &bitcoin.BlockHeader{Height: h.Height, Hash: h.Hash, MerkleRoot: h.MerkleRoot, Time: h.Time}, nil
}

func options(c *Client, headers HeaderSource) verify.Options {
	opts := verify.Options{}
	if c != nil {
		opts.Upgrader = c
	}
	if headers != nil {
		opts.Headers = headerAdapter{src: headers}
	}
	return opts
}

// VerifyDetached verifies a detached .ots proof against the original file
// content. headers may be nil; the result then reports pending/unverified.
func VerifyDetached(ctx context.Context, c *Client, headers HeaderSource, file io.Reader, det *timestamp.DetachedTimestampFile) (*VerifyResult, error) {
	return verify.VerifyDetached(ctx, options(c, headers), file, det.Timestamp)
}

// VerifyProof verifies a bare timestamp proof against a digest.
func VerifyProof(ctx context.Context, c *Client, headers HeaderSource, proof *timestamp.Timestamp, digest []byte) (*VerifyResult, error) {
	return verify.VerifyProof(ctx, options(c, headers), proof, digest)
}

// VerifyFile reads the original file and its detached .ots proof from disk
// and verifies them together.
func VerifyFile(ctx context.Context, c *Client, headers HeaderSource, filePath, otsPath string) (*VerifyResult, error) {
	otsData, err := os.ReadFile(otsPath)
	if err != nil {
		return nil, err
	}
	det, err := timestamp.DeserializeDetachedBytes(otsData)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return VerifyDetached(ctx, c, headers, f, det)
}
