// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package verify

import (
	"sort"

	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

// ParseResult reports facts embedded in a proof without contacting calendars
// or Bitcoin nodes. Block heights come from BitcoinBlockHeaderAttestation
// records in the proof tree.
type ParseResult struct {
	Complete     bool     `json:"complete"`
	BlockHeight  uint64   `json:"block_height,omitempty"`
	BlockHeights []uint64 `json:"block_heights,omitempty"`
	PendingURIs  []string `json:"pending_calendars,omitempty"`
}

// ParseProof checks digest binding and extracts embedded attestation metadata.
// It does not upgrade pending proofs or verify against the blockchain.
func ParseProof(proof *timestamp.Timestamp, digest []byte) (*ParseResult, error) {
	if err := VerifyDigest(proof, digest); err != nil {
		return nil, err
	}
	result := &ParseResult{}
	var heights []uint64
	for _, item := range proof.AllAttestations() {
		switch att := item.Att.(type) {
		case *notary.PendingAttestation:
			result.PendingURIs = append(result.PendingURIs, att.URI)
		case *notary.BitcoinBlockHeaderAttestation:
			heights = append(heights, att.Height)
		}
	}
	if len(heights) > 0 {
		sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })
		result.Complete = true
		result.BlockHeights = heights
		result.BlockHeight = heights[0]
	}
	return result, nil
}
