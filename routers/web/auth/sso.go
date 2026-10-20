// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"strings"

	user_model "gitea.dev/models/user"
	auth_service "gitea.dev/services/auth"
	"gitea.dev/services/context"
)

// IsSSOMode reports whether the request was submitted via the SSO login form
// (i.e. the `?mode=sso` query parameter is set on `/user/login`).
func IsSSOMode(ctx *context.Context) bool {
	return strings.EqualFold(ctx.FormString("mode"), "sso")
}

// signInSSO authenticates the user against the configured SSO service via
// the shared service-layer entry point (which also serves the HTTP basic auth
// fallback used by git/API/LFS clients).
//
// The caller is expected to use `handleSignInFull` to complete the session
// establishment once this function returns a non-nil user.
func signInSSO(ctx *context.Context, loginName, password string) (*user_model.User, error) {
	return auth_service.SignInSSO(ctx, loginName, password, ctx.RemoteAddr(), ctx.Req.UserAgent())
}
