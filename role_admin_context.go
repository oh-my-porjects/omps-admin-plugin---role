package main

import (
	"context"
	"encoding/json"
	"errors"
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
	Data   struct {
		AccountID    string `json:"account_id"`
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
		return adminAccountContext{}, false, nil
	}
	return p.fetchAdminAccountContext(r, token)
}

func (p *RolePlugin) fetchAdminAccountContext(r *http.Request, token string) (adminAccountContext, bool, error) {
	if p == nil {
		return adminAccountContext{}, false, errors.New("role plugin is nil")
	}
	endpoint := p.runtimeURL(r, "/api/account/me") + "?session_token=" + url.QueryEscape(token)
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
	if out.Status != 0 {
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
	endpoint := p.runtimeURL(r, "/api/account/detail") + "?operator_session_token=" + url.QueryEscape(token) + "&account_id=" + url.QueryEscape(accountID)
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
	if out.Status != 0 {
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
		if !validRecordID(permissionID) {
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
