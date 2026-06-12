// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// It is subject to the license terms in the LICENSE file found in the top-level
// directory of this distribution.
//
// Portions derived from python-opentimestamps/opentimestamps/core/notary.py (LGPL-3.0+).

package notary

import (
	"bytes"
	"fmt"

	"github.com/thalestmm/ots/internal/core/serialize"
)

const (
	TagSize        = 8
	MaxPayloadSize = 8192
	MaxURILength   = 1000
)

var allowedURIChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")

var (
	pendingTag  = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	bitcoinTag  = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	litecoinTag = []byte{0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45}
)

type Attestation interface {
	Tag() []byte
	Serialize(ctx *serialize.Context) error
	Less(other Attestation) bool
	Equal(other Attestation) bool
	Kind() string
}

func CheckURI(uri []byte) error {
	if len(uri) > MaxURILength {
		return fmt.Errorf("URI exceeds maximum length")
	}
	for _, c := range uri {
		if bytes.IndexByte(allowedURIChars, c) < 0 {
			return fmt.Errorf("URI contains invalid character %q", c)
		}
	}
	return nil
}

type PendingAttestation struct {
	URI string
}

func (a *PendingAttestation) Tag() []byte  { return pendingTag }
func (a *PendingAttestation) Kind() string { return "pending" }

func NewPendingAttestation(uri string) (*PendingAttestation, error) {
	if err := CheckURI([]byte(uri)); err != nil {
		return nil, err
	}
	return &PendingAttestation{URI: uri}, nil
}

func (a *PendingAttestation) Serialize(ctx *serialize.Context) error {
	if err := ctx.WriteBytes(a.Tag()); err != nil {
		return err
	}
	payload := serialize.NewWriteContext()
	if err := payload.WriteVarBytes([]byte(a.URI)); err != nil {
		return err
	}
	return ctx.WriteVarBytes(payload.Bytes())
}

func (a *PendingAttestation) Less(other Attestation) bool {
	if bytes.Equal(a.Tag(), other.Tag()) {
		if o, ok := other.(*PendingAttestation); ok {
			return a.URI < o.URI
		}
	}
	return bytes.Compare(a.Tag(), other.Tag()) < 0
}

func (a *PendingAttestation) Equal(other Attestation) bool {
	o, ok := other.(*PendingAttestation)
	return ok && a.URI == o.URI
}

func deserializePending(ctx *serialize.Context) (*PendingAttestation, error) {
	uri, err := ctx.ReadVarBytes(MaxURILength)
	if err != nil {
		return nil, err
	}
	if err := CheckURI(uri); err != nil {
		return nil, serialize.DeserializationError{Msg: fmt.Sprintf("invalid URI: %v", err)}
	}
	return &PendingAttestation{URI: string(uri)}, nil
}

type BitcoinBlockHeaderAttestation struct {
	Height uint64
}

func (a *BitcoinBlockHeaderAttestation) Tag() []byte  { return bitcoinTag }
func (a *BitcoinBlockHeaderAttestation) Kind() string { return "bitcoin" }

func (a *BitcoinBlockHeaderAttestation) Serialize(ctx *serialize.Context) error {
	if err := ctx.WriteBytes(a.Tag()); err != nil {
		return err
	}
	payload := serialize.NewWriteContext()
	if err := payload.WriteVarUint(a.Height); err != nil {
		return err
	}
	return ctx.WriteVarBytes(payload.Bytes())
}

func (a *BitcoinBlockHeaderAttestation) Less(other Attestation) bool {
	if bytes.Equal(a.Tag(), other.Tag()) {
		if o, ok := other.(*BitcoinBlockHeaderAttestation); ok {
			return a.Height < o.Height
		}
	}
	return bytes.Compare(a.Tag(), other.Tag()) < 0
}

func (a *BitcoinBlockHeaderAttestation) Equal(other Attestation) bool {
	o, ok := other.(*BitcoinBlockHeaderAttestation)
	return ok && a.Height == o.Height
}

func deserializeBitcoin(ctx *serialize.Context) (*BitcoinBlockHeaderAttestation, error) {
	height, err := ctx.ReadVarUint()
	if err != nil {
		return nil, err
	}
	return &BitcoinBlockHeaderAttestation{Height: height}, nil
}

type LitecoinBlockHeaderAttestation struct {
	Height uint64
}

func (a *LitecoinBlockHeaderAttestation) Tag() []byte  { return litecoinTag }
func (a *LitecoinBlockHeaderAttestation) Kind() string { return "litecoin" }

func (a *LitecoinBlockHeaderAttestation) Serialize(ctx *serialize.Context) error {
	if err := ctx.WriteBytes(a.Tag()); err != nil {
		return err
	}
	payload := serialize.NewWriteContext()
	if err := payload.WriteVarUint(a.Height); err != nil {
		return err
	}
	return ctx.WriteVarBytes(payload.Bytes())
}

func (a *LitecoinBlockHeaderAttestation) Less(other Attestation) bool {
	if bytes.Equal(a.Tag(), other.Tag()) {
		if o, ok := other.(*LitecoinBlockHeaderAttestation); ok {
			return a.Height < o.Height
		}
	}
	return bytes.Compare(a.Tag(), other.Tag()) < 0
}

func (a *LitecoinBlockHeaderAttestation) Equal(other Attestation) bool {
	o, ok := other.(*LitecoinBlockHeaderAttestation)
	return ok && a.Height == o.Height
}

func deserializeLitecoin(ctx *serialize.Context) (*LitecoinBlockHeaderAttestation, error) {
	height, err := ctx.ReadVarUint()
	if err != nil {
		return nil, err
	}
	return &LitecoinBlockHeaderAttestation{Height: height}, nil
}

type UnknownAttestation struct {
	TagBytes []byte
	Payload  []byte
}

func (a *UnknownAttestation) Tag() []byte  { return a.TagBytes }
func (a *UnknownAttestation) Kind() string { return "unknown" }

func (a *UnknownAttestation) Serialize(ctx *serialize.Context) error {
	if err := ctx.WriteBytes(a.TagBytes); err != nil {
		return err
	}
	return ctx.WriteVarBytes(a.Payload)
}

func (a *UnknownAttestation) Less(other Attestation) bool {
	if bytes.Equal(a.Tag(), other.Tag()) {
		if o, ok := other.(*UnknownAttestation); ok {
			return bytes.Compare(a.Payload, o.Payload) < 0
		}
	}
	return bytes.Compare(a.Tag(), other.Tag()) < 0
}

func (a *UnknownAttestation) Equal(other Attestation) bool {
	o, ok := other.(*UnknownAttestation)
	return ok && bytes.Equal(a.TagBytes, o.TagBytes) && bytes.Equal(a.Payload, o.Payload)
}

func Deserialize(ctx *serialize.Context) (Attestation, error) {
	tag, err := ctx.ReadBytes(TagSize)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := ctx.ReadVarBytes(MaxPayloadSize)
	if err != nil {
		return nil, err
	}
	payload := serialize.NewContext(payloadBytes)

	var att Attestation
	switch {
	case bytes.Equal(tag, pendingTag):
		att, err = deserializePending(payload)
	case bytes.Equal(tag, bitcoinTag):
		att, err = deserializeBitcoin(payload)
	case bytes.Equal(tag, litecoinTag):
		att, err = deserializeLitecoin(payload)
	default:
		att = &UnknownAttestation{TagBytes: tag, Payload: payloadBytes}
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if err := payload.AssertEOF(); err != nil {
		return nil, err
	}
	return att, nil
}

func SortAttestations(atts []Attestation) {
	for i := 0; i < len(atts); i++ {
		for j := i + 1; j < len(atts); j++ {
			if atts[j].Less(atts[i]) {
				atts[i], atts[j] = atts[j], atts[i]
			}
		}
	}
}
