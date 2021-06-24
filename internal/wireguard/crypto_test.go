// Original source code license is following.

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.

package wireguard

import (
	"testing"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := NewPrivateKey()
	assertNil(t, err)

	sk2, err := NewPrivateKey()
	assertNil(t, err)

	pk1 := sk1.PublicKey()
	pk2 := sk2.PublicKey()

	ss1, err := sk1.SharedSecret(pk2)
	if err != nil {
		t.Fatal(err)
	}

	ss2, err := sk2.SharedSecret(pk1)
	if err != nil {
		t.Fatal(err)
	}

	if ss1 != ss2 {
		t.Fatal("Failed to compute shared secret")
	}
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
