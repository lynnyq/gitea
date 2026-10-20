// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gitea.dev/models/auth"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/auth/sso"
	"gitea.dev/modules/log"
	"gitea.dev/modules/optional"
	"gitea.dev/modules/setting"
	user_service "gitea.dev/services/user"
)

// SignInSSO authenticates the user against the configured SSO service and
// either returns the matching local user, creates one on the fly when
// `setting.SSO.AutoCreateUser` is true, or returns an error.
//
// It is the single entry point shared by the web SSO login form and the HTTP
// basic auth fallback (git clone/push, API, LFS), so both entry points apply
// identical user provisioning and profile syncing rules.
func SignInSSO(ctx context.Context, loginName, password, initialIP, initialUserAgent string) (*user_model.User, error) {
	if !setting.SSO.Enabled {
		return nil, errors.New("sso is not enabled")
	}
	loginName = strings.TrimSpace(loginName)
	if loginName == "" || password == "" {
		return nil, user_model.ErrUserNotExist{Name: loginName}
	}

	resp, err := sso.Authenticate(ctx, loginName, password)
	if err != nil {
		log.Warn("SSO authentication request failed for %s from %s: %v", loginName, initialIP, err)
		return nil, user_model.ErrUserNotExist{Name: loginName}
	}
	if !resp.Success(setting.SSO.SuccessCode) {
		log.Warn("SSO authentication rejected for %s: code=%s message=%s", loginName, resp.Code, resp.Message)
		return nil, user_model.ErrUserNotExist{Name: loginName}
	}
	content := resp.Content

	// prefer the canonical login name reported by the SSO service so that
	// casing/whitespace drift in the typed name cannot split one account
	// into multiple local users
	if content.LoginName != "" {
		loginName = strings.TrimSpace(content.LoginName)
	}

	// Look up the local user, first by the exact name (covers accounts whose
	// SSO login name is a valid Gitea username), then by the SSO binding
	// (login_name) for users whose Gitea name had to be normalized, e.g.
	// "san zhang" -> "san-zhang".
	user, err := user_model.GetIndividualUserByName(ctx, loginName)
	if err != nil && !user_model.IsErrUserNotExist(err) {
		return nil, err
	}
	if user == nil {
		boundUser, has, err2 := user_model.GetIndividualUserByLoginSource(ctx, auth.NoType, user_model.LoginSourceSSO, loginName)
		if err2 != nil {
			return nil, err2
		}
		if has {
			user = boundUser
		}
	}
	if user != nil && user.LoginSource == user_model.LoginSourceSSO && user.LoginName != "" && user.LoginName != loginName {
		// the matched local account is bound to a different SSO login, e.g.
		// "san-zhang" typed literally must not land on the account that was
		// provisioned for the SSO login "san zhang"
		log.Warn("SSO login name conflict: gitea user %q is bound to sso login %q, refusing login as %q", user.Name, user.LoginName, loginName)
		return nil, fmt.Errorf("sso login name %q conflicts with existing user %q", loginName, user.Name)
	}

	if user == nil {
		if !setting.SSO.AutoCreateUser {
			return nil, user_model.ErrUserNotExist{Name: loginName}
		}
		user, err = createSSOUser(ctx, loginName, content, initialIP, initialUserAgent)
		if err != nil {
			return nil, fmt.Errorf("create sso user: %w", err)
		}
		log.Trace("SSO auto-created user: %s (sso login: %s)", user.Name, loginName)
		return user, nil
	}

	if err := syncSSOUser(ctx, user, loginName, content); err != nil {
		return nil, fmt.Errorf("sync sso user: %w", err)
	}
	return user, nil
}

// normalizeSSOUserName maps an SSO login name to a valid Gitea username using
// the same normalization as the OAuth2 login: whitespace is replaced with "-"
// ("san zhang" -> "san-zhang"), diacritics are folded to ASCII and email-like
// inputs are cut at "@". The original login name is kept in `login_name`.
func normalizeSSOUserName(loginName string) (string, error) {
	// collapse whitespace runs first, otherwise "a  b" would normalize to
	// "a--b" which is rejected by the username pattern
	name, err := user_model.NormalizeUserName(strings.Join(strings.Fields(loginName), " "))
	if err != nil {
		return "", err
	}
	if err := user_model.IsUsableUsername(name); err != nil {
		return "", fmt.Errorf("cannot map sso login name %q to a valid username (got %q): %w", loginName, name, err)
	}
	return name, nil
}

// createSSOUser creates a brand new local user that is bound to the SSO
// service. The user's `LoginSource` is set to the magic value
// `user_model.LoginSourceSSO` so that subsequent logins skip the password
// check on Gitea and always go through the SSO service.
func createSSOUser(ctx context.Context, loginName string, content *sso.Content, initialIP, initialUserAgent string) (*user_model.User, error) {
	name, err := normalizeSSOUserName(loginName)
	if err != nil {
		return nil, err
	}
	email := strings.TrimSpace(content.Email)
	if email == "" {
		// fall back to a placeholder email so the user can be created; admins
		// may update it later through the profile settings.
		email = name + "@sso.local"
	}
	displayName := content.UserName
	if displayName == "" {
		displayName = content.IDCardName
	}

	u := &user_model.User{
		Name:     name,
		Email:    email,
		FullName: displayName,
		// Leave Passwd empty so the row in `user.passwd` is empty / unhashable.
		// SSO users never authenticate locally.
		LoginType:   auth.NoType,
		LoginSource: user_model.LoginSourceSSO,
		LoginName:   loginName,
	}
	overwrite := &user_model.CreateUserOverwriteOptions{
		IsActive: optional.Some(true),
	}
	meta := &user_model.Meta{
		InitialIP:        initialIP,
		InitialUserAgent: initialUserAgent,
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
func syncSSOUser(ctx context.Context, u *user_model.User, loginName string, content *sso.Content) error {
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
	if u.LoginSource != user_model.LoginSourceSSO || u.LoginName != loginName {
		u.LoginSource = user_model.LoginSourceSSO
		u.LoginName = loginName
		if err := user_model.UpdateUserCols(ctx, u, "login_source", "login_name"); err != nil {
			return err
		}
	}
	return nil
}
