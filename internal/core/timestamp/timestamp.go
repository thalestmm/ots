// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// It is subject to the license terms in the LICENSE file found in the top-level
// directory of this distribution.
//
// Portions derived from python-opentimestamps/opentimestamps/core/timestamp.py (LGPL-3.0+).

package timestamp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sort"

	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/serialize"
)

const (
	HeaderMagic         = "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
	MajorVersion        = 1
	MinFileDigestLength = 20
	MaxFileDigestLength = 32
	recursionLimit      = 256
)

var headerMagicBytes = []byte(HeaderMagic)

type Timestamp struct {
	Msg          []byte
	Attestations []notary.Attestation
	Ops          []OpStamp
}

type OpStamp struct {
	Op    op.Op
	Stamp *Timestamp
}

func New(msg []byte) (*Timestamp, error) {
	if len(msg) > op.MaxMsgLength {
		return nil, fmt.Errorf("message exceeds op length limit; %d > %d", len(msg), op.MaxMsgLength)
	}
	return &Timestamp{Msg: append([]byte{}, msg...)}, nil
}

func (t *Timestamp) AddOp(o op.Op) (*Timestamp, error) {
	result, err := o.Apply(t.Msg)
	if err != nil {
		return nil, err
	}
	child, err := New(result)
	if err != nil {
		return nil, err
	}
	for i := range t.Ops {
		if t.Ops[i].Op.Equal(o) {
			return t.Ops[i].Stamp, nil
		}
	}
	t.Ops = append(t.Ops, OpStamp{Op: o, Stamp: child})
	return child, nil
}

func (t *Timestamp) SetOpResult(o op.Op, stamp *Timestamp) error {
	for i := range t.Ops {
		if t.Ops[i].Op.Equal(o) {
			if !bytes.Equal(t.Ops[i].Stamp.Msg, stamp.Msg) {
				return fmt.Errorf("can't change existing result timestamp: timestamps are for different messages")
			}
			t.Ops[i].Stamp = stamp
			return nil
		}
	}
	return fmt.Errorf("operation not found")
}

func (t *Timestamp) Merge(other *Timestamp) error {
	if !bytes.Equal(t.Msg, other.Msg) {
		return fmt.Errorf("can't merge timestamps for different messages")
	}
	for _, att := range other.Attestations {
		if !t.hasAttestation(att) {
			t.Attestations = append(t.Attestations, att)
		}
	}
	for _, otherOp := range other.Ops {
		var child *Timestamp
		for i := range t.Ops {
			if t.Ops[i].Op.Equal(otherOp.Op) {
				child = t.Ops[i].Stamp
				break
			}
		}
		if child == nil {
			var err error
			child, err = t.AddOp(otherOp.Op)
			if err != nil {
				return err
			}
		}
		if err := child.Merge(otherOp.Stamp); err != nil {
			return err
		}
	}
	return nil
}

func (t *Timestamp) hasAttestation(att notary.Attestation) bool {
	for _, a := range t.Attestations {
		if a.Equal(att) {
			return true
		}
	}
	return false
}

func (t *Timestamp) Equal(other *Timestamp) bool {
	if other == nil || !bytes.Equal(t.Msg, other.Msg) || len(t.Attestations) != len(other.Attestations) || len(t.Ops) != len(other.Ops) {
		return false
	}
	for _, a := range t.Attestations {
		if !other.hasAttestation(a) {
			return false
		}
	}
	for _, o := range t.Ops {
		found := false
		for _, oo := range other.Ops {
			if o.Op.Equal(oo.Op) {
				found = o.Stamp.Equal(oo.Stamp)
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (t *Timestamp) Serialize(ctx *serialize.Context) error {
	if len(t.Attestations) == 0 && len(t.Ops) == 0 {
		return fmt.Errorf("an empty timestamp can't be serialized")
	}
	atts := append([]notary.Attestation{}, t.Attestations...)
	notary.SortAttestations(atts)
	ops := append([]OpStamp{}, t.Ops...)
	sort.Slice(ops, func(i, j int) bool { return ops[i].Op.Less(ops[j].Op) })

	if len(atts) > 1 {
		for i := 0; i < len(atts)-1; i++ {
			if err := ctx.WriteBytes([]byte{0xff, 0x00}); err != nil {
				return err
			}
			if err := atts[i].Serialize(ctx); err != nil {
				return err
			}
		}
	}

	if len(ops) == 0 {
		if err := ctx.WriteBytes([]byte{0x00}); err != nil {
			return err
		}
		return atts[len(atts)-1].Serialize(ctx)
	}

	if len(atts) > 0 {
		if err := ctx.WriteBytes([]byte{0xff, 0x00}); err != nil {
			return err
		}
		if err := atts[len(atts)-1].Serialize(ctx); err != nil {
			return err
		}
	}

	for i := 0; i < len(ops)-1; i++ {
		if err := ctx.WriteBytes([]byte{0xff}); err != nil {
			return err
		}
		if err := ops[i].Op.Serialize(ctx); err != nil {
			return err
		}
		if err := ops[i].Stamp.Serialize(ctx); err != nil {
			return err
		}
	}
	last := ops[len(ops)-1]
	if err := last.Op.Serialize(ctx); err != nil {
		return err
	}
	return last.Stamp.Serialize(ctx)
}

func Deserialize(ctx *serialize.Context, initialMsg []byte, depth int) (*Timestamp, error) {
	if depth <= 0 {
		return nil, serialize.RecursionLimitError{}
	}
	t, err := New(initialMsg)
	if err != nil {
		return nil, err
	}

	var readItem func(tag byte) error
	readItem = func(tag byte) error {
		if tag == 0x00 {
			att, err := notary.Deserialize(ctx)
			if err != nil {
				return err
			}
			t.Attestations = append(t.Attestations, att)
			return nil
		}
		o, err := op.DeserializeFromTag(ctx, tag)
		if err != nil {
			return err
		}
		result, err := o.Apply(initialMsg)
		if err != nil {
			return serialize.DeserializationError{Msg: fmt.Sprintf("invalid timestamp; message invalid for op: %v", err)}
		}
		child, err := Deserialize(ctx, result, depth-1)
		if err != nil {
			return err
		}
		t.Ops = append(t.Ops, OpStamp{Op: o, Stamp: child})
		return nil
	}

	tag, err := ctx.ReadUint8()
	if err != nil {
		return nil, err
	}
	for tag == 0xff {
		next, err := ctx.ReadUint8()
		if err != nil {
			return nil, err
		}
		if err := readItem(next); err != nil {
			return nil, err
		}
		tag, err = ctx.ReadUint8()
		if err != nil {
			return nil, err
		}
	}
	if err := readItem(tag); err != nil {
		return nil, err
	}
	return t, nil
}

func DeserializeBytes(data []byte, initialMsg []byte) (*Timestamp, error) {
	return Deserialize(serialize.NewContext(data), initialMsg, recursionLimit)
}

func (t *Timestamp) SerializeBytes() ([]byte, error) {
	ctx := serialize.NewWriteContext()
	if err := t.Serialize(ctx); err != nil {
		return nil, err
	}
	return ctx.Bytes(), nil
}

func NonceTimestamp(private *Timestamp, nonceLen int) (*Timestamp, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	appendOp, err := op.NewAppend(nonce)
	if err != nil {
		return nil, err
	}
	stamp2, err := private.AddOp(appendOp)
	if err != nil {
		return nil, err
	}
	return stamp2.AddOp(op.NewSHA256())
}

func CatThenUnaryOp(unary op.Op, left, right *Timestamp) (*Timestamp, error) {
	if left == nil {
		var err error
		left, err = New([]byte{})
		if err != nil {
			return nil, err
		}
	}
	if right == nil {
		var err error
		right, err = New([]byte{})
		if err != nil {
			return nil, err
		}
	}
	appendOp, err := op.NewAppend(right.Msg)
	if err != nil {
		return nil, err
	}
	leftAppend, err := left.AddOp(appendOp)
	if err != nil {
		return nil, err
	}
	prependOp, err := op.NewPrepend(left.Msg)
	if err != nil {
		return nil, err
	}
	rightPrepend, err := right.AddOp(prependOp)
	if err != nil {
		return nil, err
	}
	if !leftAppend.Equal(rightPrepend) {
		return nil, fmt.Errorf("append/prepend paths diverged")
	}
	// Both paths produce the same message, so point the left branch at the
	// right's stamp; otherwise left-side leaves dead-end below the unary op.
	if err := left.SetOpResult(appendOp, rightPrepend); err != nil {
		return nil, err
	}
	return rightPrepend.AddOp(unary)
}

func CatSHA256(left, right *Timestamp) (*Timestamp, error) {
	return CatThenUnaryOp(op.NewSHA256(), left, right)
}

// CatSHA256d concatenates left and right and applies SHA-256 twice — the
// merkle step used inside Bitcoin blocks and transactions.
func CatSHA256d(left, right *Timestamp) (*Timestamp, error) {
	once, err := CatSHA256(left, right)
	if err != nil {
		return nil, err
	}
	return once.AddOp(op.NewSHA256())
}

func MakeMerkleTree(stamps []*Timestamp) (*Timestamp, error) {
	if len(stamps) == 0 {
		return nil, fmt.Errorf("need at least one timestamp")
	}
	current := stamps
	for {
		it := 0
		var prev *Timestamp
		var next []*Timestamp
		for it < len(current) {
			if prev == nil {
				prev = current[it]
				it++
				continue
			}
			pair, err := CatSHA256(prev, current[it])
			if err != nil {
				return nil, err
			}
			next = append(next, pair)
			prev = nil
			it++
		}
		if len(next) == 0 {
			return prev, nil
		}
		if prev != nil {
			next = append(next, prev)
		}
		current = next
	}
}

type DetachedTimestampFile struct {
	FileHashOp *op.SHA256Op
	Timestamp  *Timestamp
}

func (d *DetachedTimestampFile) FileDigest() []byte {
	return d.Timestamp.Msg
}

func NewDetached(fileHashOp *op.SHA256Op, ts *Timestamp) (*DetachedTimestampFile, error) {
	if len(ts.Msg) != fileHashOp.DigestLength() {
		return nil, fmt.Errorf("timestamp message length and file_hash_op digest length differ")
	}
	return &DetachedTimestampFile{FileHashOp: fileHashOp, Timestamp: ts}, nil
}

func FromReader(fileHashOp *op.SHA256Op, r io.Reader) (*DetachedTimestampFile, error) {
	digest, err := fileHashOp.HashReader(r)
	if err != nil {
		return nil, err
	}
	ts, err := New(digest)
	if err != nil {
		return nil, err
	}
	return NewDetached(fileHashOp, ts)
}

func (d *DetachedTimestampFile) Serialize(ctx *serialize.Context) error {
	if err := ctx.WriteBytes(headerMagicBytes); err != nil {
		return err
	}
	if err := ctx.WriteUint8(MajorVersion); err != nil {
		return err
	}
	if err := d.FileHashOp.Serialize(ctx); err != nil {
		return err
	}
	if err := ctx.WriteBytes(d.Timestamp.Msg); err != nil {
		return err
	}
	return d.Timestamp.Serialize(ctx)
}

func DeserializeDetached(ctx *serialize.Context) (*DetachedTimestampFile, error) {
	if err := ctx.AssertMagic(headerMagicBytes); err != nil {
		return nil, err
	}
	major, err := ctx.ReadUint8()
	if err != nil {
		return nil, err
	}
	if major != MajorVersion {
		return nil, serialize.UnsupportedMajorVersion{Version: int(major)}
	}
	fileHashOp, err := op.Deserialize(ctx)
	if err != nil {
		return nil, err
	}
	sha, ok := fileHashOp.(*op.SHA256Op)
	if !ok {
		return nil, serialize.DeserializationError{Msg: "unsupported file hash op"}
	}
	digest, err := ctx.ReadBytes(sha.DigestLength())
	if err != nil {
		return nil, err
	}
	ts, err := Deserialize(ctx, digest, recursionLimit)
	if err != nil {
		return nil, err
	}
	if err := ctx.AssertEOF(); err != nil {
		return nil, err
	}
	return NewDetached(sha, ts)
}

func DeserializeDetachedBytes(data []byte) (*DetachedTimestampFile, error) {
	return DeserializeDetached(serialize.NewContext(data))
}

func (d *DetachedTimestampFile) SerializeBytes() ([]byte, error) {
	ctx := serialize.NewWriteContext()
	if err := d.Serialize(ctx); err != nil {
		return nil, err
	}
	return ctx.Bytes(), nil
}

func (d *DetachedTimestampFile) Equal(other *DetachedTimestampFile) bool {
	return d.FileHashOp.Equal(other.FileHashOp) && d.Timestamp.Equal(other.Timestamp)
}

func (t *Timestamp) AllAttestations() []struct {
	Msg []byte
	Att notary.Attestation
} {
	var out []struct {
		Msg []byte
		Att notary.Attestation
	}
	var walk func(*Timestamp)
	walk = func(ts *Timestamp) {
		for _, att := range ts.Attestations {
			out = append(out, struct {
				Msg []byte
				Att notary.Attestation
			}{Msg: ts.Msg, Att: att})
		}
		for _, opStamp := range ts.Ops {
			walk(opStamp.Stamp)
		}
	}
	walk(t)
	return out
}

func CommitmentHex(msg []byte) string {
	return hex.EncodeToString(msg)
}
