// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// It is subject to the license terms in the LICENSE file found in the top-level
// directory of this distribution.
//
// Portions derived from python-opentimestamps/opentimestamps/core/op.py (LGPL-3.0+).

package op

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/thalestmm/ots/internal/core/serialize"
)

const (
	MaxResultLength = 4096
	MaxMsgLength    = 4096
)

type MsgValueError struct {
	Msg string
}

func (e MsgValueError) Error() string { return e.Msg }

type OpArgValueError struct {
	Msg string
}

func (e OpArgValueError) Error() string { return e.Msg }

type Op interface {
	Tag() byte
	TagName() string
	Apply(msg []byte) ([]byte, error)
	Serialize(ctx *serialize.Context) error
	Less(other Op) bool
	Equal(other Op) bool
}

var tagRegistry = map[byte]func(*serialize.Context, byte) (Op, error){}

func Register(tag byte, deser func(*serialize.Context, byte) (Op, error)) {
	tagRegistry[tag] = deser
}

func Deserialize(ctx *serialize.Context) (Op, error) {
	tag, err := ctx.ReadUint8()
	if err != nil {
		return nil, err
	}
	return DeserializeFromTag(ctx, tag)
}

func DeserializeFromTag(ctx *serialize.Context, tag byte) (Op, error) {
	f, ok := tagRegistry[tag]
	if !ok {
		return nil, serialize.DeserializationError{Msg: fmt.Sprintf("unknown operation tag 0x%02x", tag)}
	}
	return f(ctx, tag)
}

func applyUnary(msg []byte, fn func([]byte) []byte) ([]byte, error) {
	if len(msg) > MaxMsgLength {
		return nil, MsgValueError{Msg: fmt.Sprintf("message too long; %d > %d", len(msg), MaxMsgLength)}
	}
	r := fn(msg)
	if len(r) == 0 {
		return nil, MsgValueError{Msg: "empty result"}
	}
	if len(r) > MaxResultLength {
		return nil, MsgValueError{Msg: fmt.Sprintf("result too long; %d > %d", len(r), MaxResultLength)}
	}
	return r, nil
}

type appendOp struct {
	arg []byte
}

func (o *appendOp) Tag() byte       { return 0xf0 }
func (o *appendOp) TagName() string { return "append" }

func (o *appendOp) Apply(msg []byte) ([]byte, error) {
	return applyUnary(msg, func(m []byte) []byte { return append(append([]byte{}, m...), o.arg...) })
}

func (o *appendOp) Serialize(ctx *serialize.Context) error {
	if err := ctx.WriteBytes([]byte{o.Tag()}); err != nil {
		return err
	}
	return ctx.WriteVarBytes(o.arg)
}

func (o *appendOp) Less(other Op) bool {
	if o.Tag() != other.Tag() {
		return o.Tag() < other.Tag()
	}
	return bytes.Compare(o.arg, other.(*appendOp).arg) < 0
}

func (o *appendOp) Equal(other Op) bool {
	oo, ok := other.(*appendOp)
	return ok && bytes.Equal(o.arg, oo.arg)
}

func NewAppend(arg []byte) (Op, error) {
	if len(arg) == 0 {
		return nil, OpArgValueError{Msg: "OpAppend arg can't be empty"}
	}
	if len(arg) > MaxResultLength {
		return nil, OpArgValueError{Msg: fmt.Sprintf("OpAppend arg too long: %d > %d", len(arg), MaxResultLength)}
	}
	return &appendOp{arg: append([]byte{}, arg...)}, nil
}

type prependOp struct {
	arg []byte
}

func (o *prependOp) Tag() byte       { return 0xf1 }
func (o *prependOp) TagName() string { return "prepend" }

func (o *prependOp) Apply(msg []byte) ([]byte, error) {
	return applyUnary(msg, func(m []byte) []byte { return append(append([]byte{}, o.arg...), m...) })
}

func (o *prependOp) Serialize(ctx *serialize.Context) error {
	if err := ctx.WriteBytes([]byte{o.Tag()}); err != nil {
		return err
	}
	return ctx.WriteVarBytes(o.arg)
}

func (o *prependOp) Less(other Op) bool {
	if o.Tag() != other.Tag() {
		return o.Tag() < other.Tag()
	}
	return bytes.Compare(o.arg, other.(*prependOp).arg) < 0
}

func (o *prependOp) Equal(other Op) bool {
	oo, ok := other.(*prependOp)
	return ok && bytes.Equal(o.arg, oo.arg)
}

func NewPrepend(arg []byte) (Op, error) {
	if len(arg) == 0 {
		return nil, OpArgValueError{Msg: "OpPrepend arg can't be empty"}
	}
	if len(arg) > MaxResultLength {
		return nil, OpArgValueError{Msg: fmt.Sprintf("OpPrepend arg too long: %d > %d", len(arg), MaxResultLength)}
	}
	return &prependOp{arg: append([]byte{}, arg...)}, nil
}

type SHA256Op struct{}

func (o *SHA256Op) Tag() byte         { return 0x08 }
func (o *SHA256Op) TagName() string   { return "sha256" }
func (o *SHA256Op) DigestLength() int { return 32 }

func (o *SHA256Op) Apply(msg []byte) ([]byte, error) {
	return applyUnary(msg, func(m []byte) []byte {
		sum := sha256.Sum256(m)
		return sum[:]
	})
}

func (o *SHA256Op) Serialize(ctx *serialize.Context) error {
	return ctx.WriteBytes([]byte{o.Tag()})
}

func (o *SHA256Op) Less(other Op) bool  { return o.Tag() < other.Tag() }
func (o *SHA256Op) Equal(other Op) bool { _, ok := other.(*SHA256Op); return ok }

func (o *SHA256Op) HashReader(r io.Reader) ([]byte, error) {
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func NewSHA256() Op { return &SHA256Op{} }

type sha1Op struct{}

func (o *sha1Op) Tag() byte       { return 0x02 }
func (o *sha1Op) TagName() string { return "sha1" }

func (o *sha1Op) Apply(msg []byte) ([]byte, error) {
	return applyUnary(msg, func(m []byte) []byte {
		sum := sha1.Sum(m)
		return sum[:]
	})
}

func (o *sha1Op) Serialize(ctx *serialize.Context) error {
	return ctx.WriteBytes([]byte{o.Tag()})
}

func (o *sha1Op) Less(other Op) bool  { return o.Tag() < other.Tag() }
func (o *sha1Op) Equal(other Op) bool { _, ok := other.(*sha1Op); return ok }

type cryptOp struct {
	tag          byte
	name         string
	digestLength int
	newHash      func() hash.Hash
}

func (o *cryptOp) Tag() byte       { return o.tag }
func (o *cryptOp) TagName() string { return o.name }

func (o *cryptOp) Apply(msg []byte) ([]byte, error) {
	return applyUnary(msg, func(m []byte) []byte {
		h := o.newHash()
		h.Write(m)
		return h.Sum(nil)
	})
}

func (o *cryptOp) Serialize(ctx *serialize.Context) error {
	return ctx.WriteBytes([]byte{o.tag})
}

func (o *cryptOp) Less(other Op) bool {
	if o.tag != other.Tag() {
		return o.tag < other.Tag()
	}
	return false
}

func (o *cryptOp) Equal(other Op) bool {
	co, ok := other.(*cryptOp)
	return ok && co.tag == o.tag
}

func (o *cryptOp) DigestLength() int { return o.digestLength }

func (o *cryptOp) HashReader(r io.Reader) ([]byte, error) {
	h := o.newHash()
	buf := make([]byte, 1<<20)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// NewRIPEMD160 and NewKeccak256 cover the remaining hash ops in the
// OpenTimestamps spec; older proofs in the wild (pre-2016) start with
// ripemd160, and Ethereum-era tooling emits keccak256.
func NewRIPEMD160() Op {
	return &cryptOp{tag: 0x03, name: "ripemd160", digestLength: 20, newHash: ripemd160.New}
}

func NewKeccak256() Op {
	return &cryptOp{tag: 0x67, name: "keccak256", digestLength: 32, newHash: sha3.NewLegacyKeccak256}
}

func OpString(o Op) string {
	switch v := o.(type) {
	case *appendOp:
		return fmt.Sprintf("append %s", hex.EncodeToString(v.arg))
	case *prependOp:
		return fmt.Sprintf("prepend %s", hex.EncodeToString(v.arg))
	default:
		return o.TagName()
	}
}

func init() {
	Register(0xf0, func(ctx *serialize.Context, tag byte) (Op, error) {
		arg, err := ctx.ReadVarBytesMinMax(1, MaxResultLength)
		if err != nil {
			return nil, err
		}
		return NewAppend(arg)
	})
	Register(0xf1, func(ctx *serialize.Context, tag byte) (Op, error) {
		arg, err := ctx.ReadVarBytesMinMax(1, MaxResultLength)
		if err != nil {
			return nil, err
		}
		return NewPrepend(arg)
	})
	Register(0x08, func(ctx *serialize.Context, tag byte) (Op, error) {
		return &SHA256Op{}, nil
	})
	Register(0x02, func(ctx *serialize.Context, tag byte) (Op, error) {
		return &sha1Op{}, nil
	})
	Register(0x03, func(ctx *serialize.Context, tag byte) (Op, error) {
		return NewRIPEMD160(), nil
	})
	Register(0x67, func(ctx *serialize.Context, tag byte) (Op, error) {
		return NewKeccak256(), nil
	})
}
