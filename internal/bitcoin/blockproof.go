// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from python-opentimestamps/opentimestamps/bitcoin.py and
// opentimestamps-server/otsserver/stamper.py (LGPL-3.0+).

package bitcoin

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/wire"

	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/timestamp"
)

// StripWitness re-serializes a raw transaction without witness data, the
// form whose double-SHA256 is the txid committed in the block merkle tree.
func StripWitness(rawTx []byte) ([]byte, error) {
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(rawTx)); err != nil {
		return nil, fmt.Errorf("deserialize tx: %w", err)
	}
	var out bytes.Buffer
	if err := tx.SerializeNoWitness(&out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// MakeTimestampFromBlock extends tip — the merkle-tip timestamp whose Msg is
// embedded in the transaction's OP_RETURN output — with the ops proving
// inclusion in a block: tx serialization → txid → block merkle path → block
// merkle root. It returns the root node (Msg == header merkle root, internal
// byte order), to which the caller attaches the BitcoinBlockHeaderAttestation.
//
// rawTxNoWitness must be the witness-stripped serialization; txids are the
// block's ordered txids in internal byte order; merkleRoot is the block
// header's hashMerkleRoot in internal byte order.
func MakeTimestampFromBlock(tip *timestamp.Timestamp, rawTxNoWitness []byte, txIndex int, txids [][]byte, merkleRoot []byte) (*timestamp.Timestamp, error) {
	i := bytes.Index(rawTxNoWitness, tip.Msg)
	if i < 0 {
		return nil, fmt.Errorf("merkle tip not found in transaction")
	}
	if bytes.Index(rawTxNoWitness[i+1:], tip.Msg) >= 0 {
		return nil, fmt.Errorf("merkle tip appears more than once in transaction")
	}

	node := tip
	if prefix := rawTxNoWitness[:i]; len(prefix) > 0 {
		prependOp, err := op.NewPrepend(prefix)
		if err != nil {
			return nil, err
		}
		if node, err = node.AddOp(prependOp); err != nil {
			return nil, err
		}
	}
	if suffix := rawTxNoWitness[i+len(tip.Msg):]; len(suffix) > 0 {
		appendOp, err := op.NewAppend(suffix)
		if err != nil {
			return nil, err
		}
		var err2 error
		if node, err2 = node.AddOp(appendOp); err2 != nil {
			return nil, err2
		}
	}
	var err error
	if node, err = node.AddOp(op.NewSHA256()); err != nil {
		return nil, err
	}
	if node, err = node.AddOp(op.NewSHA256()); err != nil {
		return nil, err
	}

	if txIndex < 0 || txIndex >= len(txids) {
		return nil, fmt.Errorf("tx index %d out of range (%d txs)", txIndex, len(txids))
	}
	if !bytes.Equal(node.Msg, txids[txIndex]) {
		return nil, fmt.Errorf("computed txid does not match block txid at index %d", txIndex)
	}

	// Build the block merkle tree with Satoshi's odd-leaf duplication,
	// keeping our txid node linked so its ops chain reaches the root.
	level := make([]*timestamp.Timestamp, len(txids))
	for j, txid := range txids {
		if j == txIndex {
			level[j] = node
			continue
		}
		ts, err := timestamp.New(txid)
		if err != nil {
			return nil, err
		}
		level[j] = ts
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]*timestamp.Timestamp, 0, len(level)/2)
		for j := 0; j < len(level); j += 2 {
			parent, err := timestamp.CatSHA256d(level[j], level[j+1])
			if err != nil {
				return nil, err
			}
			next = append(next, parent)
		}
		level = next
	}
	root := level[0]
	if !bytes.Equal(root.Msg, merkleRoot) {
		return nil, fmt.Errorf("computed merkle root does not match block header")
	}
	return root, nil
}
