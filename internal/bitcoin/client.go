// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from opentimestamps/opentimestamps-server/otsserver/stamper.py (LGPL-3.0+).

package bitcoin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
)

// Config holds Bitcoin Core JSON-RPC connection settings.
type Config struct {
	Host    string // host:port, no scheme
	User    string
	Pass    string
	Network string // mainnet | testnet | regtest
}

func (c Config) Validate() error {
	switch c.Network {
	case "mainnet", "testnet", "regtest":
		return nil
	default:
		return fmt.Errorf("unknown bitcoin network %q (want mainnet, testnet, or regtest)", c.Network)
	}
}

// BlockHeader is the subset of a Bitcoin block header that timestamp
// verification needs. MerkleRoot is in internal byte order, matching the
// message bytes committed by OTS proofs.
type BlockHeader struct {
	Height     uint64
	Hash       string
	MerkleRoot []byte
	Time       time.Time
}

// HeaderSource provides independently verifiable block headers. The verifier
// only trusts this source for headers, never for timestamp claims.
type HeaderSource interface {
	BlockHeader(ctx context.Context, height uint64) (*BlockHeader, error)
}

// Client wraps a Bitcoin Core JSON-RPC connection (wallet enabled).
type Client struct {
	rpc     *rpcclient.Client
	network string
}

func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	rpc, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:         cfg.Host,
		User:         cfg.User,
		Pass:         cfg.Pass,
		HTTPPostMode: true,
		DisableTLS:   true,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &Client{rpc: rpc, network: cfg.Network}, nil
}

func (c *Client) Network() string { return c.network }

func (c *Client) Close() { c.rpc.Shutdown() }

// RawRequest passes a JSON-RPC call through to the node (used by regtest
// test harnesses for wallet setup and block generation).
func (c *Client) RawRequest(method string, params []json.RawMessage) (json.RawMessage, error) {
	return c.rpc.RawRequest(method, params)
}

// CheckNetwork verifies the connected node runs the configured chain,
// guarding against mixing testnet proofs into a mainnet calendar.
func (c *Client) CheckNetwork() error {
	res, err := c.rpc.RawRequest("getblockchaininfo", nil)
	if err != nil {
		return err
	}
	var info struct {
		Chain string `json:"chain"`
	}
	if err := json.Unmarshal(res, &info); err != nil {
		return err
	}
	want := map[string]string{"mainnet": "main", "testnet": "test", "regtest": "regtest"}[c.network]
	if info.Chain != want {
		return fmt.Errorf("bitcoin node runs chain %q but server configured for %s", info.Chain, c.network)
	}
	return nil
}

func (c *Client) BlockCount() (int64, error) {
	return c.rpc.GetBlockCount()
}

func (c *Client) BestBlockHash() (*chainhash.Hash, error) {
	return c.rpc.GetBestBlockHash()
}

func (c *Client) BlockHashByHeight(height int64) (*chainhash.Hash, error) {
	return c.rpc.GetBlockHash(height)
}

// BlockHeader implements HeaderSource against the connected node.
func (c *Client) BlockHeader(ctx context.Context, height uint64) (*BlockHeader, error) {
	hash, err := c.rpc.GetBlockHash(int64(height))
	if err != nil {
		return nil, fmt.Errorf("getblockhash %d: %w", height, err)
	}
	header, err := c.rpc.GetBlockHeader(hash)
	if err != nil {
		return nil, fmt.Errorf("getblockheader %s: %w", hash, err)
	}
	root := header.MerkleRoot
	return &BlockHeader{
		Height:     height,
		Hash:       hash.String(),
		MerkleRoot: append([]byte{}, root[:]...),
		Time:       header.Timestamp.UTC(),
	}, nil
}

// BlockTxIDs returns the height and ordered txids (internal byte order) of a block.
func (c *Client) BlockTxIDs(hash *chainhash.Hash) (int64, [][]byte, error) {
	block, err := c.rpc.GetBlockVerbose(hash)
	if err != nil {
		return 0, nil, err
	}
	txids := make([][]byte, len(block.Tx))
	for i, s := range block.Tx {
		h, err := chainhash.NewHashFromStr(s)
		if err != nil {
			return 0, nil, err
		}
		txids[i] = append([]byte{}, h[:]...)
	}
	return block.Height, txids, nil
}

// TxStatus reports wallet-tracked confirmation state of a transaction.
type TxStatus struct {
	Confirmations int64
	BlockHash     *chainhash.Hash
}

func (c *Client) TxStatus(txid *chainhash.Hash) (*TxStatus, error) {
	res, err := c.rpc.GetTransaction(txid)
	if err != nil {
		return nil, err
	}
	st := &TxStatus{Confirmations: res.Confirmations}
	if res.BlockHash != "" {
		h, err := chainhash.NewHashFromStr(res.BlockHash)
		if err != nil {
			return nil, err
		}
		st.BlockHash = h
	}
	return st, nil
}

func (c *Client) WalletBalance() (btcutil.Amount, error) {
	return c.rpc.GetBalance("*")
}

// SendOpReturn builds, funds, signs, and broadcasts a transaction with a
// single OP_RETURN output carrying data. Returns the txid and the raw
// serialized transaction (needed to build the inclusion proof).
func (c *Client) SendOpReturn(data []byte, maxFee btcutil.Amount) (*chainhash.Hash, []byte, error) {
	mustJSON := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return b
	}

	// createrawtransaction [] [{"data": "<hex>"}]
	res, err := c.rpc.RawRequest("createrawtransaction", []json.RawMessage{
		mustJSON([]any{}),
		mustJSON([]map[string]string{{"data": hex.EncodeToString(data)}}),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("createrawtransaction: %w", err)
	}
	var rawHex string
	if err := json.Unmarshal(res, &rawHex); err != nil {
		return nil, nil, err
	}

	// fundrawtransaction (opt in to RBF so stuck txs can be fee-bumped)
	res, err = c.rpc.RawRequest("fundrawtransaction", []json.RawMessage{
		mustJSON(rawHex),
		mustJSON(map[string]any{"replaceable": true}),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("fundrawtransaction: %w", err)
	}
	var funded struct {
		Hex string  `json:"hex"`
		Fee float64 `json:"fee"`
	}
	if err := json.Unmarshal(res, &funded); err != nil {
		return nil, nil, err
	}
	fee, err := btcutil.NewAmount(funded.Fee)
	if err != nil {
		return nil, nil, err
	}
	if maxFee > 0 && fee > maxFee {
		return nil, nil, fmt.Errorf("tx fee %v exceeds --btc-max-fee %v", fee, maxFee)
	}

	// signrawtransactionwithwallet
	res, err = c.rpc.RawRequest("signrawtransactionwithwallet", []json.RawMessage{mustJSON(funded.Hex)})
	if err != nil {
		return nil, nil, fmt.Errorf("signrawtransactionwithwallet: %w", err)
	}
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if err := json.Unmarshal(res, &signed); err != nil {
		return nil, nil, err
	}
	if !signed.Complete {
		return nil, nil, fmt.Errorf("wallet could not fully sign transaction")
	}
	rawTx, err := hex.DecodeString(signed.Hex)
	if err != nil {
		return nil, nil, err
	}

	// sendrawtransaction
	res, err = c.rpc.RawRequest("sendrawtransaction", []json.RawMessage{mustJSON(signed.Hex)})
	if err != nil {
		return nil, nil, fmt.Errorf("sendrawtransaction: %w", err)
	}
	var txidStr string
	if err := json.Unmarshal(res, &txidStr); err != nil {
		return nil, nil, err
	}
	txid, err := chainhash.NewHashFromStr(txidStr)
	if err != nil {
		return nil, nil, err
	}
	return txid, rawTx, nil
}
