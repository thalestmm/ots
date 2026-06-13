// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package ots

import (
	"github.com/thalestmm/ots/internal/core/timestamp"
	"github.com/thalestmm/ots/internal/verify"
)

type ParseResult = verify.ParseResult

// ParseProof extracts embedded attestation metadata without calendar or Bitcoin lookups.
func ParseProof(proof *timestamp.Timestamp, digest []byte) (*ParseResult, error) {
	return verify.ParseProof(proof, digest)
}
