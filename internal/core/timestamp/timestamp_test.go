// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// Portions derived from python-opentimestamps/opentimestamps/tests/core/test_timestamp.py (LGPL-3.0+).

package timestamp

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/thalestmm/ots/internal/core/notary"
	"github.com/thalestmm/ots/internal/core/op"
	"github.com/thalestmm/ots/internal/core/serialize"
)

func mustPending(t *testing.T, uri string) notary.Attestation {
	t.Helper()
	att, err := notary.NewPendingAttestation(uri)
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func roundTrip(t *testing.T, ts *Timestamp, expected []byte) {
	t.Helper()
	ctx := serialize.NewWriteContext()
	if err := ts.Serialize(ctx); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got := ctx.Bytes()
	if !bytes.Equal(expected, got) {
		t.Fatalf("serialized mismatch:\nwant %x\ngot  %x", expected, got)
	}
	back, err := Deserialize(serialize.NewContext(expected), ts.Msg, recursionLimit)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !ts.Equal(back) {
		t.Fatalf("round-trip equality failed")
	}
}

func TestTimestampSerialization(t *testing.T) {
	stamp, err := New([]byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	stamp.Attestations = append(stamp.Attestations, mustPending(t, "foobar"))
	roundTrip(t, stamp, mustHex(t, "00"+pendingHex("foobar")))

	stamp.Attestations = append(stamp.Attestations, mustPending(t, "barfoo"))
	roundTrip(t, stamp, mustHex(t, "ff00"+pendingHex("barfoo")+"00"+pendingHex("foobar")))

	stamp.Attestations = append(stamp.Attestations, mustPending(t, "foobaz"))
	roundTrip(t, stamp, mustHex(t, "ff00"+pendingHex("barfoo")+"ff00"+pendingHex("foobar")+"00"+pendingHex("foobaz")))

	shaChild, err := stamp.AddOp(op.NewSHA256())
	if err != nil {
		t.Fatal(err)
	}
	shaChild.Attestations = append(shaChild.Attestations, mustPending(t, "deeper"))
	roundTrip(t, stamp, mustHex(t, "ff00"+pendingHex("barfoo")+"ff00"+pendingHex("foobar")+"ff00"+pendingHex("foobaz")+"08"+"00"+pendingHex("deeper")))
}

func TestDetachedTimestampFile(t *testing.T) {
	emptyHash := mustHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	fileStamp, err := FromReader(&op.SHA256Op{}, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileStamp.FileDigest(), emptyHash) {
		t.Fatalf("unexpected digest %x", fileStamp.FileDigest())
	}
	fileStamp.Timestamp.Attestations = append(fileStamp.Timestamp.Attestations, mustPending(t, "foobar"))

	expected := append([]byte(HeaderMagic), 0x01, 0x08)
	expected = append(expected, emptyHash...)
	expected = append(expected, mustHex(t, "00"+pendingHex("foobar"))...)

	ctx := serialize.NewWriteContext()
	if err := fileStamp.Serialize(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, ctx.Bytes()) {
		t.Fatalf("detached serialization mismatch")
	}
	back, err := DeserializeDetached(serialize.NewContext(ctx.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !fileStamp.Equal(back) {
		t.Fatal("detached round-trip failed")
	}
}

func TestMakeMerkleTree(t *testing.T) {
	cases := map[int]string{
		1: "00",
		2: "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
		3: "e6aa639123d8aac95d13d365ec3779dade4b49c083a8fed97d7bfc0d89bb6a5e",
		4: "7699a4fdd6b8b6908a344f73b8f05c8e1400f7253f544602c442ff5c65504b24",
		5: "aaa9609d0c949fee22c1c941a4432f32dc1c2de939e4af25207f0dc62df0dbd8",
		6: "ebdb4245f648b7e77b60f4f8a99a6d0529d1d372f98f35478b3284f16da93c06",
		7: "ba4603a311279dea32e8958bfb660c86237157bf79e6bfee857803e811d91b8f",
	}
	for n, rootHex := range cases {
		roots := make([]*Timestamp, n)
		for i := 0; i < n; i++ {
			roots[i], _ = New([]byte{byte(i)})
		}
		tip, err := MakeMerkleTree(roots)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		want, _ := hex.DecodeString(rootHex)
		if !bytes.Equal(tip.Msg, want) {
			t.Fatalf("n=%d: got %x want %x", n, tip.Msg, want)
		}
	}
}

func TestCatSHA256(t *testing.T) {
	left, _ := New([]byte("foo"))
	right, _ := New([]byte("bar"))
	stamp, err := CatSHA256(left, right)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2")
	if !bytes.Equal(stamp.Msg, want) {
		t.Fatalf("got %x", stamp.Msg)
	}
}

func pendingHex(uri string) string {
	inner := append([]byte{byte(len(uri))}, []byte(uri)...)
	outer := append([]byte{byte(len(inner))}, inner...)
	return "83dfe30d2ef90c8e" + hex.EncodeToString(outer)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHashReaderEmpty(t *testing.T) {
	h, err := (&op.SHA256Op{}).HashReader(bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if !bytes.Equal(h, want) {
		t.Fatalf("got %x", h)
	}
	_ = io.EOF
}
