// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package sso provides primitives to authenticate users against an external
// custom SSO service. The flow is:
//
//  1. The browser posts a username / password pair to Gitea.
//  2. Gitea RSA-encrypts the password with the configured public key.
//  3. Gitea forwards the encrypted password to the SSO service.
//  4. If the SSO service replies with the configured success code, the user is
//     authenticated and (optionally) created locally with `login_source = -2`.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitea.dev/modules/httplib"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
)

// EncryptPassword encrypts the given password with the provided RSA public
// key using PKCS#1 v1.5 and returns the ciphertext as a hex-encoded string.
//
// The public key is accepted in two formats:
//
//   - A PKCS#1 or PKIX DER blob that has been base64-encoded (the format used
//     by Python's `Crypto.PublicKey.RSA.exportKey()` and by JSEncrypt by
//     default).
//   - A PEM encoded block, which is the standard Go format.
//
// The output is compatible with the typical JSEncrypt / Python
// `PKCS1_v1_5.encrypt` round-trip on the SSO server side.
func EncryptPassword(publicKey, password string) (string, error) {
	keyBytes, err := parsePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	rsaPub, err := parseRSAKey(keyBytes)
	if err != nil {
		return "", err
	}
	// PKCS#1 v1.5 is intentionally required here: the SSO service decrypts with
	// JSEncrypt / Python PyCryptodome's PKCS1_v1_5, which do not support OAEP.
	//nolint:staticcheck // SA1019: deprecated RSA encryption required for SSO server compatibility
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(password))
	if err != nil {
		return "", fmt.Errorf("rsa encrypt: %w", err)
	}
	return hex.EncodeToString(encrypted), nil
}

func parsePublicKey(publicKey string) ([]byte, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return nil, errors.New("empty public key")
	}
	// try PEM first when it looks like PEM
	if strings.HasPrefix(publicKey, "-----BEGIN") {
		block, _ := pem.Decode([]byte(publicKey))
		if block == nil {
			return nil, errors.New("failed to parse PEM public key")
		}
		return block.Bytes, nil
	}
	// otherwise try base64 (handles PKCS#1 "MIGfMA0GCSq..." and PKIX)
	keyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("decode base64 public key: %w", err)
	}
	return keyBytes, nil
}

func parseRSAKey(der []byte) (*rsa.PublicKey, error) {
	// try PKCS#1 first (the typical Python "exportKey" output starts with MIGf)
	pub, err := x509.ParsePKCS1PublicKey(der)
	if err == nil {
		return pub, nil
	}
	// fall back to PKIX (SubjectPublicKeyInfo)
	parsed, parseErr := x509.ParsePKIXPublicKey(der)
	if parseErr != nil {
		return nil, fmt.Errorf("parse public key (pkcs1=%v, pkix=%v)", err, parseErr)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an RSA key")
	}
	return rsaPub, nil
}

// Request is the JSON payload posted to the external SSO service.
type Request struct {
	LoginName string `json:"loginName"`
	Password  string `json:"password"`
}

// Content mirrors the user profile fields the SSO service is expected to
// return. Any field may be empty; the caller decides which ones to sync.
type Content struct {
	ID          int64  `json:"id"`
	LoginName   string `json:"loginName"`
	UserName    string `json:"userName"`
	IDCardName  string `json:"idCardName"`
	MobileNo    string `json:"mobileNo"`
	Email       string `json:"email"`
	DeptNo      string `json:"deptNo"`
	WorkID      string `json:"workId"`
	Gender      string `json:"gender"`
	OfficePhone string `json:"officePhone"`
}

// Response is the JSON envelope returned by the SSO service.
type Response struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Content *Content `json:"content"`
}

// Success reports whether the SSO response represents a successful login.
func (r *Response) Success(successCode string) bool {
	return r != nil && r.Code == successCode && r.Content != nil
}

// Authenticate posts the credentials to the configured SSO service and
// returns the parsed response. The caller is responsible for interpreting the
// response and for user provisioning.
func Authenticate(ctx context.Context, loginName, password string) (*Response, error) {
	if !setting.SSO.Enabled {
		return nil, errors.New("sso is not enabled")
	}
	encrypted, err := EncryptPassword(setting.SSO.PublicKey, password)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(Request{LoginName: loginName, Password: encrypted})
	if err != nil {
		return nil, fmt.Errorf("marshal sso request: %w", err)
	}
	timeout := time.Duration(setting.SSO.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	resp, err := httplib.NewRequest(setting.SSO.URL, "POST").
		SetContext(ctx).
		SetReadWriteTimeout(timeout).
		Header("Content-Type", "application/json").
		Body(payload).
		Response()
	if err != nil {
		return nil, fmt.Errorf("call sso service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sso service returned status %d", resp.StatusCode)
	}

	var ssoResp Response
	if err := json.NewDecoder(resp.Body).Decode(&ssoResp); err != nil {
		return nil, fmt.Errorf("decode sso response: %w", err)
	}
	return &ssoResp, nil
}
