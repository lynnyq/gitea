// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/auth/sso"
	"gitea.dev/modules/json"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ssoTestLoginName = "sso-user"
	ssoTestPassword  = "sso-password"
)

// mockSSOService starts a local SSO endpoint that accepts only the fixed
// credentials above, mirroring the wire protocol of the real service, and
// points the global SSO setting at it for the duration of the test.
func mockSSOService(t *testing.T) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sso.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cipher, err := hex.DecodeString(req.Password)
		if err != nil {
			http.Error(w, "invalid ciphertext", http.StatusBadRequest)
			return
		}
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cipher)
		if err != nil {
			http.Error(w, "decrypt failed", http.StatusBadRequest)
			return
		}

		resp := sso.Response{Code: "200", Message: "invalid credentials"}
		if string(plain) == ssoTestPassword {
			// derive a per-account email so multiple auto-created users in
			// one test run do not collide on the unique email constraint
			email := strings.ReplaceAll(req.LoginName, " ", ".") + "@sso.example.com"
			resp = sso.Response{
				Code:    "3000",
				Message: "ok",
				Content: &sso.Content{LoginName: req.LoginName, UserName: "SSO User", Email: email},
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)

	t.Cleanup(test.MockVariableValue(&setting.SSO.Enabled, true))
	t.Cleanup(test.MockVariableValue(&setting.SSO.URL, server.URL))
	t.Cleanup(test.MockVariableValue(&setting.SSO.PublicKey, pubKey))
	t.Cleanup(test.MockVariableValue(&setting.SSO.SuccessCode, "3000"))
	t.Cleanup(test.MockVariableValue(&setting.SSO.AutoCreateUser, true))
}

func deleteSSOUser(t *testing.T, userID int64) {
	t.Helper()
	ctx := context.Background()
	_, err := db.DeleteByID[user_model.User](ctx, userID)
	require.NoError(t, err)
	// also remove the email_address rows, otherwise the unique email
	// constraint breaks later auto-creation in the same test run
	_, err = db.GetEngine(ctx).Where("uid = ?", userID).Delete(&user_model.EmailAddress{})
	require.NoError(t, err)
}

func TestSignInSSO(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	mockSSOService(t)

	t.Run("Disabled", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SSO.Enabled, false)()
		u, err := SignInSSO(t.Context(), ssoTestLoginName, ssoTestPassword, "127.0.0.1:1", "test")
		assert.Error(t, err)
		assert.Nil(t, u)
	})

	t.Run("AutoCreateAndSync", func(t *testing.T) {
		u, err := SignInSSO(t.Context(), ssoTestLoginName, ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.Equal(t, ssoTestLoginName, u.Name)
		assert.Equal(t, user_model.LoginSourceSSO, u.LoginSource)
		assert.True(t, u.IsActive)
		assert.Equal(t, "sso-user@sso.example.com", u.Email)
		assert.Equal(t, "SSO User", u.FullName)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })

		// a second sign-in must reuse the existing user and keep it bound to SSO
		u2, err := SignInSSO(t.Context(), ssoTestLoginName, ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		assert.Equal(t, u.ID, u2.ID)
		assert.Equal(t, user_model.LoginSourceSSO, u2.LoginSource)
		assert.Equal(t, "SSO User", u2.FullName)
	})

	t.Run("SpacedLoginNameNormalized", func(t *testing.T) {
		// "san zhang" is not a valid Gitea username (spaces are not allowed),
		// so the account must be provisioned as "san-zhang" and found again
		// via the login_name binding on subsequent sign-ins
		u, err := SignInSSO(t.Context(), "san zhang", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.Equal(t, "san-zhang", u.Name)
		assert.Equal(t, "san zhang", u.LoginName)
		assert.Equal(t, user_model.LoginSourceSSO, u.LoginSource)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })

		u2, err := SignInSSO(t.Context(), "san zhang", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		assert.Equal(t, u.ID, u2.ID)
		assert.Equal(t, "san-zhang", u2.Name)
	})

	t.Run("SpacedLoginNameNotHijacked", func(t *testing.T) {
		// provision "san zhang" (gitea name "san-zhang"), then sign in with a
		// different SSO account literally called "san-zhang": it must not be
		// attached to the account bound to "san zhang"
		u, err := SignInSSO(t.Context(), "san zhang", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })

		u2, err := SignInSSO(t.Context(), "san-zhang", ssoTestPassword, "127.0.0.1:1", "test-agent")
		assert.Error(t, err)
		assert.Nil(t, u2)
	})

	t.Run("UnmappableLoginNameRejected", func(t *testing.T) {
		// a login name that cannot be mapped to a valid Gitea username must
		// fail with an explicit error instead of a broken half-created user
		u, err := SignInSSO(t.Context(), "张三", ssoTestPassword, "127.0.0.1:1", "test-agent")
		assert.Error(t, err)
		assert.Nil(t, u)
	})

	t.Run("RejectWrongPassword", func(t *testing.T) {
		u, err := SignInSSO(t.Context(), ssoTestLoginName, "wrong", "127.0.0.1:1", "test")
		assert.Error(t, err)
		assert.True(t, user_model.IsErrUserNotExist(err))
		assert.Nil(t, u)
	})

	t.Run("RejectEmptyCredentials", func(t *testing.T) {
		u, err := SignInSSO(t.Context(), " ", "", "127.0.0.1:1", "test")
		assert.Error(t, err)
		assert.Nil(t, u)
	})

	t.Run("NoAutoCreateWhenDisabled", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SSO.AutoCreateUser, false)()
		u, err := SignInSSO(t.Context(), ssoTestLoginName, ssoTestPassword, "127.0.0.1:1", "test")
		assert.Error(t, err)
		assert.True(t, user_model.IsErrUserNotExist(err))
		assert.Nil(t, u)
	})
}

func TestBasicVerifySSOFallback(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	mockSSOService(t)
	defer test.MockVariableValue(&setting.Service.EnableBasicAuth, true)()

	// provision the SSO user the same way a prior web SSO login would have
	u, err := SignInSSO(t.Context(), ssoTestLoginName, ssoTestPassword, "127.0.0.1:1", "test-agent")
	require.NoError(t, err)
	t.Cleanup(func() { deleteSSOUser(t, u.ID) })

	t.Run("SignInViaSSO", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/some-user/some-repo/info/refs", nil)
		req.SetBasicAuth(ssoTestLoginName, ssoTestPassword)
		store := reqctx.NewRequestContextForTest(req.Context())
		u2, err := (&Basic{}).Verify(req, httptest.NewRecorder(), store, nil)
		require.NoError(t, err)
		require.NotNil(t, u2)
		assert.Equal(t, u.ID, u2.ID)
		assert.Equal(t, BasicMethodName, store.GetData()["LoginMethod"])
	})

	t.Run("SpacedLoginNameViaBasicAuth", func(t *testing.T) {
		// an SSO account "san zhang" is provisioned as gitea user "san-zhang";
		// git sends the original spaced login in basic auth, which must land
		// on the same user through the login_name binding
		u, err := SignInSSO(t.Context(), "san zhang", ssoTestPassword, "127.0.0.1:1", "git/2.43")
		require.NoError(t, err)
		assert.Equal(t, "san-zhang", u.Name)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })

		req := httptest.NewRequest(http.MethodGet, "/san-zhang/some-repo/info/refs", nil)
		req.SetBasicAuth("san zhang", ssoTestPassword)
		store := reqctx.NewRequestContextForTest(req.Context())
		u2, err := (&Basic{}).Verify(req, httptest.NewRecorder(), store, nil)
		require.NoError(t, err)
		require.NotNil(t, u2)
		assert.Equal(t, u.ID, u2.ID)
		assert.Equal(t, BasicMethodName, store.GetData()["LoginMethod"])
	})

	t.Run("SSOUserRejectedWhenSSODisabled", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SSO.Enabled, false)()
		req := httptest.NewRequest(http.MethodGet, "/some-user/some-repo/info/refs", nil)
		req.SetBasicAuth(ssoTestLoginName, ssoTestPassword)
		store := reqctx.NewRequestContextForTest(req.Context())
		u2, err := (&Basic{}).Verify(req, httptest.NewRecorder(), store, nil)
		assert.Error(t, err)
		assert.Nil(t, u2)
	})

	t.Run("WrongPasswordRejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/some-user/some-repo/info/refs", nil)
		req.SetBasicAuth(ssoTestLoginName, "wrong")
		store := reqctx.NewRequestContextForTest(req.Context())
		u2, err := (&Basic{}).Verify(req, httptest.NewRecorder(), store, nil)
		assert.Error(t, err)
		assert.Nil(t, u2)
	})
}
