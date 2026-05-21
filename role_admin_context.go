package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type adminAccountContext struct {
	AccountID    string
	IsSuperAdmin bool
	RoleIDs      []string
	ScopeRoleIDs []string
}

type accountMeResponse struct {
	Status int `json:"status"`
	Code   int `json:"code"`
	Data   struct {
		AccountID    string `json:"account_id"`
		ID           any    `json:"id"`
		Username     string `json:"username"`
		Role         string `json:"role"`
		RoleDisplay  string `json:"role_display"`
		IsSuperAdmin bool   `json:"is_super_admin"`
		Roles        []struct {
			RoleID     string `json:"role_id"`
			RoleStatus string `json:"role_status"`
		} `json:"roles"`
	} `json:"data"`
}

type accountDetailResponse = accountMeResponse

func (p *RolePlugin) currentAdminAccountContext(r *http.Request) (adminAccountContext, bool, error) {
	token := strings.TrimSpace(r.URL.Query().Get("session_token"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Admin-Session-Token"))
	}
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Admin-Token"))
	}
	if token == "" {
		token = bearerToken(r)
	}
	if token == "" {
		return adminAccountContext{}, false, nil
	}
	ctx, ok, err := p.fetchAdminAccountContext(r, token)
	if err == nil && ok {
		return ctx, true, nil
	}
	if fallback, fallbackOK, fallbackErr := p.fetchProjectAdminContext(r, token); fallbackErr != nil {
		if err != nil {
			return adminAccountContext{}, false, err
		}
		return adminAccountContext{}, false, fallbackErr
	} else if fallbackOK {
		return fallback, true, nil
	}
	return ctx, ok, err
}

func (p *RolePlugin) fetchAdminAccountContext(r *http.Request, token string) (adminAccountContext, bool, error) {
	if p == nil {
		return adminAccountContext{}, false, errors.New("role plugin is nil")
	}
	endpoint := p.runtimeURL(r, "/api/admin-account/me") + "?session_token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		return adminAccountContext{}, false, err
	}
	p.applyAdminAPIKey(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return adminAccountContext{}, false, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return adminAccountContext{}, false, errors.New("account me http status failed")
	}
	var out accountMeResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return adminAccountContext{}, false, err
	}
	if responseStatus(out.Status, out.Code) != 0 {
		return adminAccountContext{}, false, nil
	}
	ctx := adminAccountContext{AccountID: out.Data.AccountID, IsSuperAdmin: out.Data.IsSuperAdmin}
	for _, role := range out.Data.Roles {
		if role.RoleID != "" {
			ctx.RoleIDs = append(ctx.RoleIDs, role.RoleID)
			ctx.ScopeRoleIDs = append(ctx.ScopeRoleIDs, role.RoleID)
		}
	}
	if ctx.IsSuperAdmin && len(ctx.RoleIDs) == 0 && ctx.AccountID != "" {
		detailCtx, ok, err := p.fetchAdminAccountDetailContext(r, token, ctx.AccountID)
		if err != nil {
			return adminAccountContext{}, false, err
		}
		if !ok {
			return adminAccountContext{}, false, errors.New("account detail status failed")
		}
		ctx.RoleIDs = detailCtx.RoleIDs
		ctx.ScopeRoleIDs = detailCtx.ScopeRoleIDs
	}
	return ctx, true, nil
}

func (p *RolePlugin) fetchAdminAccountDetailContext(r *http.Request, token, accountID string) (adminAccountContext, bool, error) {
	endpoint := p.runtimeURL(r, "/api/admin-account/detail") + "?operator_session_token=" + url.QueryEscape(token) + "&account_id=" + url.QueryEscape(accountID)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		return adminAccountContext{}, false, err
	}
	p.applyAdminAPIKey(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return adminAccountContext{}, false, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return adminAccountContext{}, false, errors.New("account detail http status failed")
	}
	var out accountDetailResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return adminAccountContext{}, false, err
	}
	if responseStatus(out.Status, out.Code) != 0 {
		return adminAccountContext{}, false, nil
	}
	ctx := adminAccountContext{AccountID: out.Data.AccountID, IsSuperAdmin: out.Data.IsSuperAdmin}
	for _, role := range out.Data.Roles {
		if role.RoleID != "" {
			ctx.RoleIDs = append(ctx.RoleIDs, role.RoleID)
			ctx.ScopeRoleIDs = append(ctx.ScopeRoleIDs, role.RoleID)
		}
	}
	return ctx, true, nil
}

func (p *RolePlugin) applyAdminAPIKey(req *http.Request) {
	if p == nil || req == nil || p.adminAPIKey == "" {
		return
	}
	req.Header.Set("X-API-Key", p.adminAPIKey)
}

func (p *RolePlugin) fetchProjectAdminContext(r *http.Request, token string) (adminAccountContext, bool, error) {
	if ctx, ok, err := p.projectAdminContextByToken(r.Context(), token); err != nil || ok {
		return ctx, ok, err
	}
	endpoint := p.runtimeURL(r, "/me")
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		return adminAccountContext{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	p.applyAdminAPIKey(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return adminAccountContext{}, false, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return adminAccountContext{}, false, nil
	}
	var out accountMeResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return adminAccountContext{}, false, err
	}
	if responseStatus(out.Status, out.Code) != 0 {
		return adminAccountContext{}, false, nil
	}
	ctx := adminAccountContext{
		AccountID:    firstNonEmpty(out.Data.AccountID, anyString(out.Data.ID), out.Data.Username),
		IsSuperAdmin: isProjectAdminManageRole(firstNonEmpty(out.Data.Role, out.Data.RoleDisplay)),
	}
	for _, role := range out.Data.Roles {
		if role.RoleID != "" {
			ctx.RoleIDs = append(ctx.RoleIDs, role.RoleID)
			ctx.ScopeRoleIDs = append(ctx.ScopeRoleIDs, role.RoleID)
		}
	}
	return ctx, ctx.AccountID != "", nil
}

func (p *RolePlugin) projectAdminContextByToken(ctx context.Context, token string) (adminAccountContext, bool, error) {
	if p == nil || p.db == nil || strings.TrimSpace(token) == "" {
		return adminAccountContext{}, false, nil
	}
	var accountID, roleName string
	err := p.db.QueryRowContext(ctx, `
		SELECT COALESCE(account_id, ''), COALESCE(role_name, '')
		FROM rt_admin_sessions
		WHERE token = $1 AND expires_at > NOW()
	`, token).Scan(&accountID, &roleName)
	if errors.Is(err, sql.ErrNoRows) {
		return adminAccountContext{}, false, nil
	}
	if err != nil {
		return adminAccountContext{}, false, err
	}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return adminAccountContext{}, false, nil
	}
	return adminAccountContext{
		AccountID:    accountID,
		IsSuperAdmin: isProjectAdminManageRole(roleName),
	}, true, nil
}

func bearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

func responseStatus(status, code int) int {
	if status != 0 {
		return status
	}
	return code
}

func anyString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		if x == 0 {
			return ""
		}
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case json.Number:
		return strings.TrimSpace(x.String())
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isProjectAdminManageRole(role string) bool {
	switch strings.TrimSpace(role) {
	case "admin", "developer", "超级管理员", "开发者":
		return true
	default:
		return false
	}
}

func (c adminAccountContext) uniqueRoleID() (string, bool) {
	if len(c.RoleIDs) != 1 {
		return "", false
	}
	return c.RoleIDs[0], true
}

func (c adminAccountContext) canOperateRole(roleID string) bool {
	if c.IsSuperAdmin {
		return true
	}
	if roleID == "" {
		return false
	}
	scopeRoleIDs := c.ScopeRoleIDs
	if len(scopeRoleIDs) == 0 {
		scopeRoleIDs = c.RoleIDs
	}
	for _, id := range scopeRoleIDs {
		if id == roleID {
			return true
		}
	}
	return false
}

func cleanPermissionIDs(raw []string) ([]string, bool) {
	ids := map[string]bool{}
	for _, permissionID := range raw {
		permissionID = strings.TrimSpace(permissionID)
		if !validUUID(permissionID) {
			return nil, false
		}
		ids[permissionID] = true
	}
	return sortedKeys(ids), true
}

func boolSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

func permissionsAllowedByParent(ctx context.Context, p *RolePlugin, parentID string, permissionIDs []string) bool {
	parentSet, err := p.permissionSet(ctx, parentID)
	if err != nil {
		return false
	}
	return permissionSetWithin(parentSet, boolSet(permissionIDs))
}
