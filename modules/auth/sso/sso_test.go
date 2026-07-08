// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func TestEncryptPassword_Base64PKCS1(t *testing.T) {
	priv := newTestKey(t)
	pubBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	pubStr := base64.StdEncoding.EncodeToString(pubBytes)

	encrypted, err := EncryptPassword(pubStr, "p@ssw0rd")
	require.NoError(t, err)

	cipher, err := hex.DecodeString(encrypted)
	require.NoError(t, err)
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cipher)
	require.NoError(t, err)
	assert.Equal(t, "p@ssw0rd", string(plain))
}

func TestEncryptPassword_Base64PKIX(t *testing.T) {
	priv := newTestKey(t)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubStr := base64.StdEncoding.EncodeToString(pubBytes)

	encrypted, err := EncryptPassword(pubStr, "secret")
	require.NoError(t, err)

	cipher, err := hex.DecodeString(encrypted)
	require.NoError(t, err)
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cipher)
	require.NoError(t, err)
	assert.Equal(t, "secret", string(plain))
}

func TestEncryptPassword_PEM(t *testing.T) {
	priv := newTestKey(t)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pubStr := string(pem.EncodeToMemory(pemBlock))

	encrypted, err := EncryptPassword(pubStr, "p@ssw0rd")
	require.NoError(t, err)

	cipher, err := hex.DecodeString(encrypted)
	require.NoError(t, err)
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cipher)
	require.NoError(t, err)
	assert.Equal(t, "p@ssw0rd", string(plain))
}

func TestEncryptPassword_RejectsBadInput(t *testing.T) {
	_, err := EncryptPassword("", "p@ss")
	assert.Error(t, err)
	_, err = EncryptPassword("not-base64-or-pem", "p@ss")
	assert.Error(t, err)
	// valid base64 but not a key
	_, err = EncryptPassword(base64.StdEncoding.EncodeToString([]byte("hello world")), "p@ss")
	assert.Error(t, err)
}

func TestResponse_Success(t *testing.T) {
	r := &Response{Code: "3000", Content: &Content{LoginName: "alice"}}
	assert.True(t, r.Success("3000"))
	assert.False(t, r.Success("200"))
	assert.False(t, (&Response{Code: "3000"}).Success("3000"))
	assert.False(t, ((*Response)(nil)).Success("3000"))
}
