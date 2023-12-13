// Copyright (C) 2022, 2023 - Tillitis AB
// Copyright (C) 2023 - Daniel Lublin
// SPDX-License-Identifier: GPL-2.0-only

package tkeyx25519

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/tillitis/tkeyclient"
	"golang.org/x/crypto/blake2s"
)

const UserSecretSize = 32

type ResponseStatusNotOKError struct {
	code byte
}

func (e *ResponseStatusNotOKError) Error() string {
	return fmt.Sprintf("response status not OK, code: %d", e.code)
}

func (e *ResponseStatusNotOKError) Code() byte {
	return e.code
}

const (
	StatusOK           = byte(0)
	StatusWrongCmdLen  = byte(1)
	StatusTouchTimeout = byte(2)
)

var (
	cmdGetNameVersion = appCmd{0x01, "cmdGetNameVersion", tkeyclient.CmdLen1}
	rspGetNameVersion = appCmd{0x02, "rspGetNameVersion", tkeyclient.CmdLen32}
	cmdGetPubKey      = appCmd{0x03, "cmdGetPubKey", tkeyclient.CmdLen128}
	rspGetPubKey      = appCmd{0x04, "rspGetPubKey", tkeyclient.CmdLen128}
	cmdDoECDH         = appCmd{0x05, "cmdDoECDH", tkeyclient.CmdLen128}
	rspDoECDH         = appCmd{0x06, "rspDoECDH", tkeyclient.CmdLen128}
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

// GetAppNameVersion talks to the device app running on the TKey,
// getting its name and version. A timeout is used to avoid hanging if
// the device is running an app which does not handle the command, or
// is in firmware mode.
func (x X25519) GetAppNameVersion() (*tkeyclient.NameVersion, error) {
	if err := x.tk.SetReadTimeout(2); err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	rx, err := x.sendCommand(cmdGetNameVersion, bytes.Buffer{}, rspGetNameVersion)
	if err != nil {
		return nil, err
	}

	if err = x.tk.SetReadTimeout(0); err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	nameVer := &tkeyclient.NameVersion{}
	nameVer.Unpack(rx[:12])

	return nameVer, nil
}

// GetPubKey talks to the X25519 device app running on the TKey to
// retrieve a X25519 public key. The public key is derived by the
// device app after hashing "private_key = blake2s(CDI, domain,
// userSecret, requireTouch)". "CDI" is a base secret for use by the
// app, see https://dev.tillitis.se/intro/. "domain" comes from
// domainString, which is hashed using blake2s if the string was
// longer than 32 bytes. "userSecret" is for identity/personalization
// and must be high-entropy random. "requireTouch" indicates whether
// the TKey should require physical touch when doing ECDH to create
// the shared secret.
func (x X25519) GetPubKey(domainString string, userSecret [UserSecretSize]byte, requireTouch bool) ([]byte, error) {
	data := keyParameters(domainString, userSecret, requireTouch)

	rx, err := x.sendCommand(cmdGetPubKey, data, rspGetPubKey)
	if err != nil {
		return nil, err
	}

	return rx[:32], nil
}

// DoECDH talks to the X25519 device app running on the TKey to run
// the ECDH (Elliptic-Curve Diffie-Hellman) function for establishing
// a shared secret between theirPubKey and a private key. The private
// key is hashed using the arguments in the same way as is done for
// GetPubKey.
func (x X25519) DoECDH(domainString string, userSecret [UserSecretSize]byte, requireTouch bool, theirPubKey [32]byte) ([]byte, error) {
	data := keyParameters(domainString, userSecret, requireTouch)
	data.Write(theirPubKey[:])

	rx, err := x.sendCommand(cmdDoECDH, data, rspDoECDH)
	if err != nil {
		return nil, err
	}

	sharedSecret := rx[:32]

	if isAllZero(sharedSecret) {
		return nil, errors.New("result is all-zero due to small order point in input")
	}

	return sharedSecret, nil
}

func (x X25519) sendCommand(cmd appCmd, data bytes.Buffer, rsp appCmd) ([]byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmd, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	// Place data after frame header byte and cmd code byte
	if data.Len() > (len(tx) - 2) {
		return nil, fmt.Errorf("data too large (%d > %d-2)", data.Len(), len(tx))
	}
	copy(tx[2:], data.Bytes())

	if err = x.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := x.tk.ReadFrame(rsp, id)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	// This response contains no status code
	if rsp.code == rspGetNameVersion.code {
		// Skipping over frame header byte, and rsp code byte
		return rx[2:], nil
	}

	if rx[2] != StatusOK {
		return nil, &ResponseStatusNotOKError{code: rx[2]}
	}

	// Skipping over frame header byte, rsp code byte, and status byte
	return rx[3:], nil
}

func keyParameters(domainString string, userSecret [UserSecretSize]byte, requireTouch bool) bytes.Buffer {
	var buf bytes.Buffer

	var domain [32]byte
	if len(domainString) > 32 {
		domain = blake2s.Sum256([]byte(domainString))
	} else {
		copy(domain[:], []byte(domainString))
	}
	buf.Write(domain[:])

	buf.Write(userSecret[:])

	if requireTouch {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	return buf
}

func isAllZero(bytes []byte) bool {
	var accu byte
	for _, b := range bytes {
		accu |= b
	}
	return accu == 0
}
