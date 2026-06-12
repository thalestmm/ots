// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.
//
// It is subject to the license terms in the LICENSE file found in the top-level
// directory of this distribution.
//
// Portions derived from python-opentimestamps/opentimestamps/core/serialize.py (LGPL-3.0+).

package serialize

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

type DeserializationError struct {
	Msg string
}

func (e DeserializationError) Error() string { return e.Msg }

type BadMagicError struct {
	Expected []byte
	Actual   []byte
}

func (e BadMagicError) Error() string {
	return fmt.Sprintf("expected magic bytes 0x%s, but got 0x%s instead",
		hex.EncodeToString(e.Expected), hex.EncodeToString(e.Actual))
}

type UnsupportedMajorVersion struct {
	Version int
}

func (e UnsupportedMajorVersion) Error() string {
	return fmt.Sprintf("unsupported major version %d", e.Version)
}

type TruncationError struct {
	Msg string
}

func (e TruncationError) Error() string { return e.Msg }

type TrailingGarbageError struct{}

func (e TrailingGarbageError) Error() string {
	return "trailing garbage found after end of deserialized data"
}

type RecursionLimitError struct{}

func (e RecursionLimitError) Error() string {
	return "reached timestamp recursion depth limit while deserializing"
}

type Context struct {
	buf *bytes.Buffer
}

func NewContext(data []byte) *Context {
	return &Context{buf: bytes.NewBuffer(data)}
}

func NewWriteContext() *Context {
	return &Context{buf: &bytes.Buffer{}}
}

func (c *Context) Bytes() []byte {
	return c.buf.Bytes()
}

func (c *Context) WriteBool(v bool) error {
	if v {
		return c.writeByte(0xff)
	}
	return c.writeByte(0x00)
}

func (c *Context) ReadBool() (bool, error) {
	b, err := c.readByte()
	if err != nil {
		return false, err
	}
	switch b {
	case 0xff:
		return true, nil
	case 0x00:
		return false, nil
	default:
		return false, DeserializationError{Msg: fmt.Sprintf("read_bool() expected 0xff or 0x00; got %d", b)}
	}
}

func (c *Context) WriteVarUint(v uint64) error {
	if v == 0 {
		return c.writeByte(0x00)
	}
	for v != 0 {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		if err := c.writeByte(b); err != nil {
			return err
		}
	}
	return nil
}

func (c *Context) ReadVarUint() (uint64, error) {
	var value uint64
	var shift uint
	for {
		b, err := c.readByte()
		if err != nil {
			return 0, err
		}
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return value, nil
}

func (c *Context) WriteUint8(v byte) error {
	return c.writeByte(v)
}

func (c *Context) ReadUint8() (byte, error) {
	return c.readByte()
}

func (c *Context) WriteBytes(v []byte) error {
	_, err := c.buf.Write(v)
	return err
}

func (c *Context) ReadBytes(n int) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	out := make([]byte, n)
	_, err := c.buf.Read(out)
	if err != nil {
		return nil, TruncationError{Msg: fmt.Sprintf("tried to read %d bytes: %v", n, err)}
	}
	return out, nil
}

func (c *Context) WriteVarBytes(v []byte) error {
	if err := c.WriteVarUint(uint64(len(v))); err != nil {
		return err
	}
	return c.WriteBytes(v)
}

func (c *Context) ReadVarBytes(maxLen int) ([]byte, error) {
	l, err := c.ReadVarUint()
	if err != nil {
		return nil, err
	}
	if maxLen >= 0 && int(l) > maxLen {
		return nil, DeserializationError{Msg: fmt.Sprintf("varbytes max length exceeded; %d > %d", l, maxLen)}
	}
	return c.ReadBytes(int(l))
}

func (c *Context) ReadVarBytesMinMax(minLen, maxLen int) ([]byte, error) {
	l, err := c.ReadVarUint()
	if err != nil {
		return nil, err
	}
	if int(l) > maxLen {
		return nil, DeserializationError{Msg: fmt.Sprintf("varbytes max length exceeded; %d > %d", l, maxLen)}
	}
	if int(l) < minLen {
		return nil, DeserializationError{Msg: fmt.Sprintf("varbytes min length not met; %d < %d", l, minLen)}
	}
	return c.ReadBytes(int(l))
}

func (c *Context) AssertMagic(expected []byte) error {
	actual, err := c.ReadBytes(len(expected))
	if err != nil {
		return BadMagicError{Expected: expected, Actual: actual}
	}
	if !bytes.Equal(expected, actual) {
		return BadMagicError{Expected: expected, Actual: actual}
	}
	return nil
}

func (c *Context) AssertEOF() error {
	if c.buf.Len() > 0 {
		return TrailingGarbageError{}
	}
	return nil
}

func (c *Context) writeByte(b byte) error {
	return c.buf.WriteByte(b)
}

func (c *Context) readByte() (byte, error) {
	b, err := c.buf.ReadByte()
	if err != nil {
		return 0, TruncationError{Msg: err.Error()}
	}
	return b, nil
}
