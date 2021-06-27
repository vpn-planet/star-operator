// Original source code license is following.

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.

package wireguard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	PublicKeySize    = 32
	PrivateKeySize   = 32
	PresharedKeySize = 32
)

type (
	PublicKey    [PublicKeySize]byte
	PrivateKey   [PrivateKeySize]byte
	PresharedKey [PresharedKeySize]byte
	Nonce        uint64 // padded to 12-bytes
)

func (sk *PrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

func NewPrivateKey() (sk PrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

func (sk *PrivateKey) PublicKey() (pk PublicKey) {
	apk := (*[PublicKeySize]byte)(&pk)
	ask := (*[PrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func (sk PrivateKey) SharedSecret(pk PublicKey) (ss PresharedKey, err error) {
	apk := pk[:]
	ask := sk[:]
	var sss []byte
	sss, err = curve25519.X25519(ask, apk)
	if err != nil {
		return
	}

	if len(sss) != PresharedKeySize {
		panic(fmt.Sprintf("Length of shared secret calculated is %d, while expecting %d", len(sss), PresharedKeySize))
	}

	copy(ss[:], sss[:PublicKeySize])
	return
}

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func (key PrivateKey) IsZero() bool {
	var zero PrivateKey
	return key.Equals(zero)
}

func (key PrivateKey) Equals(tar PrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *PrivateKey) FromHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	key.clamp()
	return
}

func (key *PrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	if key.IsZero() {
		return
	}
	key.clamp()
	return
}

func (key *PublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key PublicKey) IsZero() bool {
	var zero PublicKey
	return key.Equals(zero)
}

func (key PublicKey) Equals(tar PublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *PresharedKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}
