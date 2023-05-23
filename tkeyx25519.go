// Copyright (C) 2022, 2023 - Tillitis AB
// Copyright (C) 2023 - Daniel Lublin
// SPDX-License-Identifier: GPL-2.0-only

package tkeyx25519

import (
	"bytes"
	"fmt"

	"github.com/tillitis/tkeyclient"
)

var (
	cmdGetNameVersion = appCmd{0x01, "cmdGetNameVersion", tkeyclient.CmdLen1}
	rspGetNameVersion = appCmd{0x02, "rspGetNameVersion", tkeyclient.CmdLen32}
	cmdGetPubKey      = appCmd{0x03, "cmdGetPubKey", tkeyclient.CmdLen128}
	rspGetPubKey      = appCmd{0x04, "rspGetPubKey", tkeyclient.CmdLen128}
	cmdComputeShared  = appCmd{0x05, "cmdComputeShared", tkeyclient.CmdLen128}
	rspComputeShared  = appCmd{0x06, "rspComputeShared", tkeyclient.CmdLen128}
)

type appCmd struct {
	code   byte
	name   string
	cmdLen tkeyclient.CmdLen
}

func (c appCmd) Code() byte {
	return c.code
}

func (c appCmd) CmdLen() tkeyclient.CmdLen {
	return c.cmdLen
}

func (c appCmd) Endpoint() tkeyclient.Endpoint {
	return tkeyclient.DestApp
}

func (c appCmd) String() string {
	return c.name
}

type X25519 struct {
	tk *tkeyclient.TillitisKey // A connection to a TKey
}

func New(tk *tkeyclient.TillitisKey) X25519 {
	var x25519 X25519

	x25519.tk = tk

	return x25519
}

// Close closes the connection to the TKey
func (x X25519) Close() error {
	if err := x.tk.Close(); err != nil {
		return fmt.Errorf("tk.Close: %w", err)
	}
	return nil
}

// GetAppNameVersion gets the name and version of the running app in
// the same style as the stick itself.
func (x X25519) GetAppNameVersion() (*tkeyclient.NameVersion, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdGetNameVersion, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	tkeyclient.Dump("GetAppNameVersion tx", tx)
	if err = x.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	err = x.tk.SetReadTimeout(2)
	if err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	rx, _, err := x.tk.ReadFrame(rspGetNameVersion, id)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	err = x.tk.SetReadTimeout(0)
	if err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	nameVer := &tkeyclient.NameVersion{}
	nameVer.Unpack(rx[2:])

	return nameVer, nil
}

// GetPubKey talks to the device app running on the TKey, getting a
// X25519 public key. This public key is derived from a secret =
// blake2s(domain, userSecret, require_touch, TKey CDI). requireTouch
// is part of the secret, but only the ComputeShared command actually
// requests it.
func (x X25519) GetPubKey(domain [78]byte, userSecret [16]byte, requireTouch bool) ([]byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdGetPubKey, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(domain[:])
	buf.Write(userSecret[:])
	if requireTouch {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	copy(tx[2:], buf.Bytes())

	tkeyclient.Dump("GetPubKey tx", tx)
	if err = x.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := x.tk.ReadFrame(rspGetPubKey, id)
	tkeyclient.Dump("GetPubKey rx", rx)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[2] != tkeyclient.StatusOK {
		return nil, fmt.Errorf("GetPubKey NOK")
	}

	// Skipping frame header, app header, and status
	return rx[3 : 3+32], nil
}

// GetPubKey talks to the device app running on the TKey, establishing
// a shared secret between theirPubKey and a TKey public key. This
// public key is derived as for GetPubKey. requireTouch is part of the
// secret, and only this ComputeShared command actually requests it.
func (x X25519) ComputeShared(domain [78]byte, userSecret [16]byte, requireTouch bool, theirPubKey [32]byte) ([]byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdComputeShared, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(domain[:])
	buf.Write(userSecret[:])
	if requireTouch {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.Write(theirPubKey[:])
	copy(tx[2:], buf.Bytes())

	tkeyclient.Dump("ComputeShared tx", tx)
	if err = x.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := x.tk.ReadFrame(rspComputeShared, id)
	tkeyclient.Dump("ComputeShared rx", rx)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[2] != tkeyclient.StatusOK {
		return nil, fmt.Errorf("ComputeShared NOK")
	}

	// Skipping frame header, app header, and status
	return rx[3 : 3+32], nil
}
