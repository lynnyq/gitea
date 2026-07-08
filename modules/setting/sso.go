// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import "gitea.dev/modules/log"

// SSOConfig defines the custom SSO (Single Sign-On) configuration.
//
// When SSO.Enabled is true, Gitea delegates password authentication to the
// configured external SSO service. Users that originate from SSO are marked
// in the database by `user.login_source = -2`.
type SSOConfig struct {
	Enabled        bool
	URL            string // SSO service auth endpoint (POST {loginName, password})
	PublicKey      string // RSA public key (Base64 or PEM, PKCS#1 or PKIX) used to encrypt the password before sending
	Timeout        int    // seconds, defaults to 10
	SuccessCode    string // SSO response `code` value that indicates success, defaults to "3000"
	AutoCreateUser bool   // automatically create a local user on first SSO login
}

// SSO is the global SSO configuration, populated from the `[sso]` section of
// `app.ini`. The struct is kept package-private in spirit; callers should
// reference it as `setting.SSO`.
var SSO = SSOConfig{
	Enabled:        false,
	Timeout:        10,
	SuccessCode:    "3000",
	AutoCreateUser: true,
}

func loadSSOFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("sso")
	if !sec.HasKey("ENABLED") {
		return
	}
	SSO.Enabled = sec.Key("ENABLED").MustBool(false)
	SSO.URL = sec.Key("URL").String()
	SSO.PublicKey = sec.Key("PUBLIC_KEY").String()
	SSO.Timeout = sec.Key("TIMEOUT").MustInt(10)
	SSO.SuccessCode = sec.Key("SUCCESS_CODE").MustString("3000")
	SSO.AutoCreateUser = sec.Key("AUTO_CREATE_USER").MustBool(true)

	if SSO.Enabled {
		if SSO.URL == "" {
			log.Fatal("[sso] URL must be set when SSO is enabled")
		}
		if SSO.PublicKey == "" {
			log.Fatal("[sso] PUBLIC_KEY must be set when SSO is enabled")
		}
		if SSO.Timeout <= 0 {
			SSO.Timeout = 10
		}
		if SSO.SuccessCode == "" {
			SSO.SuccessCode = "3000"
		}
	}
}
