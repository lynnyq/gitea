// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadSSOFrom(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, err := NewConfigProviderFromData("")
		assert.NoError(t, err)
		// reset global state
		SSO = SSOConfig{Timeout: 10, SuccessCode: "3000", AutoCreateUser: true}
		loadSSOFrom(cfg)
		assert.False(t, SSO.Enabled)
	})

	t.Run("enabled with custom values", func(t *testing.T) {
		cfg, err := NewConfigProviderFromData(`[sso]
ENABLED = true
URL = https://sso.example.com/auth
PUBLIC_KEY = MIGfMA0GCSq...
TIMEOUT = 30
SUCCESS_CODE = 200
AUTO_CREATE_USER = false`)
		assert.NoError(t, err)
		SSO = SSOConfig{Timeout: 10, SuccessCode: "3000", AutoCreateUser: true}
		loadSSOFrom(cfg)
		assert.True(t, SSO.Enabled)
		assert.Equal(t, "https://sso.example.com/auth", SSO.URL)
		assert.Equal(t, "MIGfMA0GCSq...", SSO.PublicKey)
		assert.Equal(t, 30, SSO.Timeout)
		assert.Equal(t, "200", SSO.SuccessCode)
		assert.False(t, SSO.AutoCreateUser)
	})

	t.Run("applies defaults for unset fields", func(t *testing.T) {
		cfg, err := NewConfigProviderFromData(`[sso]
ENABLED = true
URL = https://sso.example.com/auth
PUBLIC_KEY = MIGfMA0GCSq...`)
		assert.NoError(t, err)
		SSO = SSOConfig{Timeout: 10, SuccessCode: "3000", AutoCreateUser: true}
		loadSSOFrom(cfg)
		assert.Equal(t, 10, SSO.Timeout)
		assert.Equal(t, "3000", SSO.SuccessCode)
		assert.True(t, SSO.AutoCreateUser)
	})
}
