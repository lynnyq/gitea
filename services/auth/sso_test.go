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

	"gitea.dev/models/auth"
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

	// the mock SSO service only knows a fixed set of account names, like a
	// real SSO directory: normalized names ("zhang-san") and email-like
	// logins are unknown, so they exercise the alias fallback against the
	// bound SSO login
	knownLogins := map[string]bool{
		ssoTestLoginName: true,
		"san zhang":      true,
		"zhang san":      true,
	}

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
		if knownLogins[req.LoginName] && string(plain) == ssoTestPassword {
			email := strings.ReplaceAll(req.LoginName, " ", ".") + "@sso.example.com"
			canonicalLoginName := strings.Join(strings.Fields(req.LoginName), "")
			resp = sso.Response{
				Code:    "3000",
				Message: "ok",
				Content: &sso.Content{LoginName: canonicalLoginName, UserName: "SSO User", Email: email},
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

// renameUser simulates an account provisioned by an older version that
// normalized the SSO login "zhang san" to the username "zhang-san".
func renameUser(t *testing.T, userID int64, newName string) {
	t.Helper()
	_, err := db.GetEngine(context.Background()).Exec(
		"UPDATE `user` SET name = ?, lower_name = ? WHERE id = ?",
		newName, strings.ToLower(newName), userID,
	)
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

	t.Run("SpacedLoginNameAsIs", func(t *testing.T) {
		// username rules now allow inner spaces, so the SSO login "san zhang"
		// is provisioned verbatim and found again by the exact name on
		// subsequent sign-ins
		u, err := SignInSSO(t.Context(), "san zhang", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.Equal(t, "san zhang", u.Name)
		assert.Equal(t, "san zhang", u.LoginName)
		assert.Equal(t, user_model.LoginSourceSSO, u.LoginSource)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })

		// a second sign-in with the same spaced name must reuse the account
		u2, err := SignInSSO(t.Context(), "san zhang", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		assert.Equal(t, u.ID, u2.ID)
		assert.Equal(t, "san zhang", u2.Name)
	})

	t.Run("LegacyNormalizedAccountViaAlias", func(t *testing.T) {
		// simulate an account provisioned by older code that normalized the
		// SSO login "zhang san" to the username "zhang-san". The SSO service
		// does not know "zhang-san", so git clients that use the Gitea name
		// for basic auth must reach the account through the alias fallback
		// that retries with the bound SSO login.
		u, err := SignInSSO(t.Context(), "zhang san", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		assert.Equal(t, "zhang san", u.Name)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })
		renameUser(t, u.ID, "zhang-san")

		// the Gitea username "zhang-san" is unknown to SSO; the alias
		// fallback must retry with "zhang san" and land on the same account
		u2, err := SignInSSO(t.Context(), "zhang-san", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		require.NotNil(t, u2)
		assert.Equal(t, u.ID, u2.ID)
		assert.Equal(t, "zhang-san", u2.Name)
	})

	t.Run("LegacyWrongPasswordRejected", func(t *testing.T) {
		// the alias fallback re-sends the password to the SSO service, so a
		// wrong password must still be rejected for the legacy username too
		u, err := SignInSSO(t.Context(), "zhang san", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })
		renameUser(t, u.ID, "zhang-san")

		u2, err := SignInSSO(t.Context(), "zhang-san", "wrong", "127.0.0.1:1", "test-agent")
		assert.Error(t, err)
		assert.True(t, user_model.IsErrUserNotExist(err))
		assert.Nil(t, u2)
	})

	t.Run("SpacedLoginNameKeepsTypedBinding", func(t *testing.T) {
		// The mock SSO replies with a canonical login name that has internal
		// whitespace stripped ("zhang san" -> "zhangsan"). The local binding
		// must remain keyed on the typed spaced name, so the canonical form
		// cannot be used to look up the account.
		u, err := SignInSSO(t.Context(), "zhang san", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.Equal(t, "zhang san", u.Name)
		assert.Equal(t, "zhang san", u.LoginName)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })

		ctx := t.Context()
		// the canonical name reported by SSO must not match the binding
		_, has, err := user_model.GetIndividualUserByLoginSource(ctx, auth.NoType, user_model.LoginSourceSSO, "zhangsan")
		require.NoError(t, err)
		assert.False(t, has)
		// the typed spaced name must match the binding
		bound, has, err := user_model.GetIndividualUserByLoginSource(ctx, auth.NoType, user_model.LoginSourceSSO, "zhang san")
		require.NoError(t, err)
		require.True(t, has)
		assert.Equal(t, u.ID, bound.ID)

		// a second sign-in with the same spaced name reuses the account
		u2, err := SignInSSO(t.Context(), "zhang san", ssoTestPassword, "127.0.0.1:1", "test-agent")
		require.NoError(t, err)
		assert.Equal(t, u.ID, u2.ID)
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
		// the SSO account "san zhang" is provisioned verbatim; git sends the
		// spaced login in basic auth and the fallback finds the user by name
		u, err := SignInSSO(t.Context(), "san zhang", ssoTestPassword, "127.0.0.1:1", "git/2.43")
		require.NoError(t, err)
		assert.Equal(t, "san zhang", u.Name)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })

		req := httptest.NewRequest(http.MethodGet, "/san%20zhang/some-repo/info/refs", nil)
		req.SetBasicAuth("san zhang", ssoTestPassword)
		store := reqctx.NewRequestContextForTest(req.Context())
		u2, err := (&Basic{}).Verify(req, httptest.NewRecorder(), store, nil)
		require.NoError(t, err)
		require.NotNil(t, u2)
		assert.Equal(t, u.ID, u2.ID)
		assert.Equal(t, BasicMethodName, store.GetData()["LoginMethod"])
	})

	t.Run("LegacyNormalizedAccountViaBasicAuth", func(t *testing.T) {
		// older versions normalized "zhang san" to "zhang-san": git clients
		// that still use the normalized username must authenticate through
		// the alias fallback and land on the bound account
		u, err := SignInSSO(t.Context(), "zhang san", ssoTestPassword, "127.0.0.1:1", "git/2.43")
		require.NoError(t, err)
		assert.Equal(t, "zhang san", u.Name)
		t.Cleanup(func() { deleteSSOUser(t, u.ID) })
		renameUser(t, u.ID, "zhang-san")

		req := httptest.NewRequest(http.MethodGet, "/zhang-san/some-repo/info/refs", nil)
		req.SetBasicAuth("zhang-san", ssoTestPassword)
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
