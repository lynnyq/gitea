// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"fmt"
	"strings"

	user_model "gitea.dev/models/user"
	"gitea.dev/modules/auth/sso"
	"gitea.dev/modules/log"
	"gitea.dev/modules/optional"
	"gitea.dev/modules/setting"
	"gitea.dev/services/context"
	user_service "gitea.dev/services/user"
)

// IsSSOMode reports whether the request was submitted via the SSO login form
// (i.e. the `?mode=sso` query parameter is set on `/user/login`).
func IsSSOMode(ctx *context.Context) bool {
	return strings.EqualFold(ctx.FormString("mode"), "sso")
}

// signInSSO authenticates the user against the configured SSO service and
// either returns the matching local user, creates one on the fly when
// `setting.SSO.AutoCreateUser` is true, or returns an error.
//
// The caller is expected to use `handleSignInFull` to complete the session
// establishment once this function returns a non-nil user.
func signInSSO(ctx *context.Context, loginName, password string) (*user_model.User, error) {
	if !setting.SSO.Enabled {
		return nil, errors.New("sso is not enabled")
	}
	loginName = strings.TrimSpace(loginName)
	if loginName == "" || password == "" {
		return nil, user_model.ErrUserNotExist{Name: loginName}
	}

	resp, err := sso.Authenticate(ctx, loginName, password)
	if err != nil {
		log.Warn("SSO authentication request failed for %s from %s: %v", loginName, ctx.RemoteAddr(), err)
		return nil, user_model.ErrUserNotExist{Name: loginName}
	}
	if !resp.Success(setting.SSO.SuccessCode) {
		log.Warn("SSO authentication rejected for %s: code=%s message=%s", loginName, resp.Code, resp.Message)
		return nil, user_model.ErrUserNotExist{Name: loginName}
	}
	content := resp.Content

	// Look up the local user. SSO users are matched by their local login name.
	user, err := user_model.GetIndividualUserByName(ctx, loginName)
	if err != nil && !user_model.IsErrUserNotExist(err) {
		return nil, err
	}

	if user == nil {
		if !setting.SSO.AutoCreateUser {
			return nil, user_model.ErrUserNotExist{Name: loginName}
		}
		user, err = createSSOUser(ctx, loginName, content)
		if err != nil {
			return nil, fmt.Errorf("create sso user: %w", err)
		}
		log.Trace("SSO auto-created user: %s", user.Name)
		return user, nil
	}

	if err := syncSSOUser(ctx, user, content); err != nil {
		return nil, fmt.Errorf("sync sso user: %w", err)
	}
	return user, nil
}

// createSSOUser creates a brand new local user that is bound to the SSO
// service. The user's `LoginSource` is set to the magic value
// `user_model.LoginSourceSSO` so that subsequent logins skip the password
// check on Gitea and always go through the SSO service.
func createSSOUser(ctx *context.Context, loginName string, content *sso.Content) (*user_model.User, error) {
	email := strings.TrimSpace(content.Email)
	if email == "" {
		// fall back to a placeholder email so the user can be created; admins
		// may update it later through the profile settings.
		email = loginName + "@sso.local"
	}
	displayName := content.UserName
	if displayName == "" {
		displayName = content.IDCardName
	}

	u := &user_model.User{
		Name:     loginName,
		Email:    email,
		FullName: displayName,
		// Leave Passwd empty so the row in `user.passwd` is empty / unhashable.
		// SSO users never authenticate locally.
		LoginType:   0,
		LoginSource: user_model.LoginSourceSSO,
		LoginName:   loginName,
	}
	overwrite := &user_model.CreateUserOverwriteOptions{
		IsActive: optional.Some(true),
	}
	meta := &user_model.Meta{
		InitialIP:        ctx.RemoteAddr(),
		InitialUserAgent: ctx.Req.UserAgent(),
	}
	if err := user_model.CreateUser(ctx, u, meta, overwrite); err != nil {
		return nil, err
	}
	return u, nil
}

// syncSSOUser refreshes the profile fields of an existing local user that is
// bound to the SSO service. The `LoginSource` is always re-asserted to
// `LoginSourceSSO` so the user keeps using the SSO login flow even if an
// admin previously changed it.
func syncSSOUser(ctx *context.Context, u *user_model.User, content *sso.Content) error {
	displayName := content.UserName
	if displayName == "" {
		displayName = content.IDCardName
	}
	opts := &user_service.UpdateOptions{}
	if displayName != "" {
		opts.FullName = optional.Some(displayName)
	}
	if err := user_service.UpdateUser(ctx, u, opts); err != nil {
		return err
	}
	if u.LoginSource != user_model.LoginSourceSSO {
		u.LoginSource = user_model.LoginSourceSSO
		if err := user_model.UpdateUserCols(ctx, u, "login_source"); err != nil {
			return err
		}
	}
	return nil
}
