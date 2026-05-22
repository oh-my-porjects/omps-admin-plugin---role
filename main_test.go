package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginName(t *testing.T) {
	name := Plugin.Name()
	if name == "" {
		t.Fatal("Name() 不应为空")
	}
}

func TestPluginInit(t *testing.T) {
	ctx := PluginContext{
		Logger: slog.Default(),
	}
	if err := Plugin.Init(ctx); err != nil {
		t.Errorf("Init 失败: %v", err)
	}
}

func TestPluginShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1)
	defer cancel()
	if err := Plugin.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown(ctx) 失败: %v", err)
	}
}

func TestRuntimeURLFallsBackFromAdminProxyHost(t *testing.T) {
	p := &RolePlugin{}
	req := httptest.NewRequest(http.MethodGet, "/api/role/create", nil)
	req.Host = "omps-shan-admin.link-api.com"
	got := p.runtimeURL(req, "/api/account/me")
	want := "http://127.0.0.1:8080/api/account/me"
	if got != want {
		t.Fatalf("runtimeURL = %s, want %s", got, want)
	}
}

func TestHandleRoleCreateParentAndPermissions(t *testing.T) {
	p := testRolePlugin()
	req := httptest.NewRequest(http.MethodPost, "/api/role/create", jsonBody(map[string]any{
		"name":           "运营主管",
		"status":         "enabled",
		"parent_role_id": rootRoleID,
		"permission_ids": []string{rootPermID},
	}))
	withAdminSession(t, p, req, adminSessionContext{
		AccountID: "00000000-0000-0000-0000-000000000101",
		RoleIDs:   []string{rootRoleID},
	})

	rec := httptest.NewRecorder()
	p.handleRoleCreate(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 0 {
		t.Fatalf("status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
	data := resp.Data.(map[string]any)
	if data["parent_role_id"] != rootRoleID {
		t.Fatalf("parent_role_id = %v, want %s", data["parent_role_id"], rootRoleID)
	}
	if got := data["permission_ids"].([]any); len(got) != 1 || got[0] != rootPermID {
		t.Fatalf("permission_ids = %#v", got)
	}
}

func TestHandleRoleCreateUsesUniqueAccountRole(t *testing.T) {
	p := testRolePlugin()
	req := httptest.NewRequest(http.MethodPost, "/api/role/create", jsonBody(map[string]any{
		"name":   "客服组长",
		"status": "enabled",
	}))
	withAdminSession(t, p, req, adminSessionContext{
		AccountID: "00000000-0000-0000-0000-000000000102",
		RoleIDs:   []string{supportRoleID},
	})

	rec := httptest.NewRecorder()
	p.handleRoleCreate(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 0 {
		t.Fatalf("status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
	data := resp.Data.(map[string]any)
	if data["parent_role_id"] != supportRoleID {
		t.Fatalf("parent_role_id = %v, want %s", data["parent_role_id"], supportRoleID)
	}
}

func TestHandleRoleCreateSuperAdminTopRole(t *testing.T) {
	p := testRolePlugin()
	req := httptest.NewRequest(http.MethodPost, "/api/role/create", jsonBody(map[string]any{
		"name":   "顶级角色",
		"status": "enabled",
	}))
	withAdminSession(t, p, req, adminSessionContext{
		AccountID:    "00000000-0000-0000-0000-000000000103",
		IsSuperAdmin: true,
	})

	rec := httptest.NewRecorder()
	p.handleRoleCreate(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 0 {
		t.Fatalf("status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
	data := resp.Data.(map[string]any)
	if data["parent_role_id"] != "" {
		t.Fatalf("parent_role_id = %v, want empty", data["parent_role_id"])
	}
}

func TestHandleRoleCreateSuperAdminUsesDetailRoleBinding(t *testing.T) {
	p := testRolePlugin()
	req := httptest.NewRequest(http.MethodPost, "/api/role/create", jsonBody(map[string]any{
		"name":   "超管子角色",
		"status": "enabled",
	}))
	withAdminSession(t, p, req, adminSessionContext{
		AccountID:    "00000000-0000-0000-0000-000000000113",
		IsSuperAdmin: true,
		RoleIDs:      []string{rootRoleID},
	})

	rec := httptest.NewRecorder()
	p.handleRoleCreate(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 0 {
		t.Fatalf("status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
	data := resp.Data.(map[string]any)
	if data["parent_role_id"] != rootRoleID {
		t.Fatalf("parent_role_id = %v, want %s", data["parent_role_id"], rootRoleID)
	}
}

func TestHandleRoleCreateErrors(t *testing.T) {
	tests := []struct {
		name       string
		body       map[string]any
		session    adminSessionContext
		wantStatus int
	}{
		{
			name:       "普通账号无绑定角色",
			body:       map[string]any{"name": "无角色账号", "status": "enabled"},
			session:    adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000104"},
			wantStatus: 4106,
		},
		{
			name:       "指定不存在父级",
			body:       map[string]any{"name": "无父角色", "status": "enabled", "parent_role_id": "99999999-9999-9999-9999-999999999999"},
			session:    adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000105", RoleIDs: []string{rootRoleID}},
			wantStatus: 4103,
		},
		{
			name:       "指定停用父级",
			body:       map[string]any{"name": "停用父角色", "status": "enabled", "parent_role_id": disabledRoleID},
			session:    adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000106", RoleIDs: []string{disabledRoleID}},
			wantStatus: 4104,
		},
		{
			name:       "权限不存在",
			body:       map[string]any{"name": "坏权限", "status": "enabled", "parent_role_id": rootRoleID, "permission_ids": []string{"99999999-9999-9999-9999-999999999999"}},
			session:    adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000107", RoleIDs: []string{rootRoleID}},
			wantStatus: 4108,
		},
		{
			name:       "绑定角色被停用时自动推导父级失败",
			body:       map[string]any{"name": "越权父角色", "status": "enabled"},
			session:    adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000109", RoleIDs: []string{disabledRoleID}},
			wantStatus: 4107,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testRolePlugin()
			req := httptest.NewRequest(http.MethodPost, "/api/role/create", jsonBody(tt.body))
			withAdminSession(t, p, req, tt.session)
			rec := httptest.NewRecorder()
			p.handleRoleCreate(rec, req)
			resp := decodeTestResponse(t, rec)
			if resp.Status != tt.wantStatus {
				t.Fatalf("status = %d, want %d, msg=%s", resp.Status, tt.wantStatus, resp.Msg)
			}
		})
	}
}

func TestDeletedRoleFilteringAcrossExistingAPIs(t *testing.T) {
	p := testRolePlugin()
	deletedRole := roleRecord{ID: "00000000-0000-0000-0000-000000000241", Name: "已删除角色", ParentID: rootRoleID, Status: "enabled"}
	p.roles[deletedRole.ID] = deletedRole
	_, _, err := p.deleteRoleCascade(context.Background(), deletedRole.ID)
	if err != nil {
		t.Fatalf("delete role: %v", err)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/role/list?page=1&page_size=100", nil)
	listRec := httptest.NewRecorder()
	p.handleRoleList(listRec, listReq)
	listResp := decodeTestResponse(t, listRec)
	if listResp.Status != 0 {
		t.Fatalf("list status = %d, want 0, msg=%s", listResp.Status, listResp.Msg)
	}
	items := listResp.Data.(map[string]any)["items"].([]any)
	for _, item := range items {
		if item.(map[string]any)["role_id"] == deletedRole.ID {
			t.Fatal("deleted role should not appear in list")
		}
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/role/detail?role_id="+deletedRole.ID, nil)
	detailRec := httptest.NewRecorder()
	p.handleRoleDetail(detailRec, detailReq)
	if resp := decodeTestResponse(t, detailRec); resp.Status != 2122 {
		t.Fatalf("detail status = %d, want 2122, msg=%s", resp.Status, resp.Msg)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/api/role/update", jsonBody(map[string]any{
		"role_id":     deletedRole.ID,
		"name":        "已删除更新",
		"description": "should fail",
		"status":      "enabled",
	}))
	updateRec := httptest.NewRecorder()
	p.handleRoleUpdate(updateRec, updateReq)
	if resp := decodeTestResponse(t, updateRec); resp.Status != 2132 {
		t.Fatalf("update status = %d, want 2132, msg=%s", resp.Status, resp.Msg)
	}

	assignReq := httptest.NewRequest(http.MethodPut, "/api/role/assign-permissions", jsonBody(map[string]any{
		"role_id":        deletedRole.ID,
		"permission_ids": []string{rootPermID},
	}))
	withAdminSession(t, p, assignReq, adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000242", IsSuperAdmin: true})
	assignRec := httptest.NewRecorder()
	p.handleAssignPermissions(assignRec, assignReq)
	if resp := decodeTestResponse(t, assignRec); resp.Status != 4202 {
		t.Fatalf("assign status = %d, want 4202, msg=%s", resp.Status, resp.Msg)
	}

	checkReq := httptest.NewRequest(http.MethodPost, "/api/role/check-permission", jsonBody(map[string]any{
		"role_id":         deletedRole.ID,
		"permission_code": "system.manage",
	}))
	checkRec := httptest.NewRecorder()
	p.handleCheckPermission(checkRec, checkReq)
	if resp := decodeTestResponse(t, checkRec); resp.Status != 2173 {
		t.Fatalf("check status = %d, want 2173, msg=%s", resp.Status, resp.Msg)
	}
}

func TestCurrentAdminAccountContextIgnoresSpoofedIdentityHeaders(t *testing.T) {
	p := testRolePlugin()
	req := httptest.NewRequest(http.MethodPost, "/api/role/create", jsonBody(map[string]any{
		"name":   "伪造超级管理员",
		"status": "enabled",
	}))
	req.Header.Set("X-Admin-Is-Super", "true")
	req.Header.Set("X-Admin-Role-IDs", rootRoleID)
	req.Header.Set("X-Admin-Scope-Role-IDs", rootRoleID)

	rec := httptest.NewRecorder()
	p.handleRoleCreate(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 4109 {
		t.Fatalf("status = %d, want 4109, msg=%s", resp.Status, resp.Msg)
	}
}

func TestHandleAssignPermissionsMultiple(t *testing.T) {
	p := testRolePlugin()
	req := httptest.NewRequest(http.MethodPut, "/api/role/assign-permissions", jsonBody(map[string]any{
		"role_id":        rootRoleID,
		"permission_ids": []string{rootPermID, unassignedPermID},
	}))
	withAdminSession(t, p, req, adminSessionContext{
		AccountID:    "00000000-0000-0000-0000-000000000108",
		IsSuperAdmin: true,
	})

	rec := httptest.NewRecorder()
	p.handleAssignPermissions(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 0 {
		t.Fatalf("status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
	data := resp.Data.(map[string]any)
	if got := data["permission_ids"].([]any); len(got) != 2 {
		t.Fatalf("permission_ids len = %d, want 2", len(got))
	}
}

func TestHandleAssignPermissionsAcceptsLegacyShortPermissionIDs(t *testing.T) {
	p := testRolePlugin()
	legacyPerm := permissionRecord{ID: "KNaXAHF3yTFD", Code: "legacy.short", Name: "Legacy Short"}
	p.permissions[legacyPerm.ID] = legacyPerm
	p.rolePerms[rootRoleID][legacyPerm.ID] = true
	req := httptest.NewRequest(http.MethodPut, "/api/role/assign-permissions", jsonBody(map[string]any{
		"role_id":        supportRoleID,
		"permission_ids": []string{legacyPerm.ID},
	}))
	withAdminSession(t, p, req, adminSessionContext{
		AccountID:    "00000000-0000-0000-0000-000000000109",
		IsSuperAdmin: true,
	})

	rec := httptest.NewRecorder()
	p.handleAssignPermissions(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 0 {
		t.Fatalf("status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
	data := resp.Data.(map[string]any)
	got := data["permission_ids"].([]any)
	if len(got) != 1 || got[0] != legacyPerm.ID {
		t.Fatalf("permission_ids = %#v, want %s", got, legacyPerm.ID)
	}
}

func TestHandleAssignPermissionsErrors(t *testing.T) {
	tests := []struct {
		name       string
		body       map[string]any
		session    *adminSessionContext
		wantStatus int
	}{
		{
			name:       "角色不存在",
			body:       map[string]any{"role_id": "99999999-9999-9999-9999-999999999999", "permission_ids": []string{rootPermID}},
			session:    &adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000110", IsSuperAdmin: true},
			wantStatus: 4202,
		},
		{
			name:       "权限不存在",
			body:       map[string]any{"role_id": rootRoleID, "permission_ids": []string{"99999999-9999-9999-9999-999999999999"}},
			session:    &adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000111", IsSuperAdmin: true},
			wantStatus: 4204,
		},
		{
			name:       "停用角色不可绑定权限",
			body:       map[string]any{"role_id": disabledRoleID, "permission_ids": []string{rootPermID}},
			session:    &adminSessionContext{AccountID: "00000000-0000-0000-0000-000000000112", IsSuperAdmin: true},
			wantStatus: 4203,
		},
		{
			name:       "缺少后台账号上下文",
			body:       map[string]any{"role_id": rootRoleID, "permission_ids": []string{rootPermID}},
			wantStatus: 4203,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testRolePlugin()
			req := httptest.NewRequest(http.MethodPut, "/api/role/assign-permissions", jsonBody(tt.body))
			if tt.session != nil {
				withAdminSession(t, p, req, *tt.session)
			}
			rec := httptest.NewRecorder()
			p.handleAssignPermissions(rec, req)
			resp := decodeTestResponse(t, rec)
			if resp.Status != tt.wantStatus {
				t.Fatalf("status = %d, want %d, msg=%s", resp.Status, tt.wantStatus, resp.Msg)
			}
		})
	}
}

func testRolePlugin() *RolePlugin {
	p := &RolePlugin{logger: slog.Default()}
	p.ensureMemoryStore()
	return p
}

func jsonBody(v any) *bytes.Reader {
	raw, _ := json.Marshal(v)
	return bytes.NewReader(raw)
}

type adminSessionContext struct {
	AccountID    string
	IsSuperAdmin bool
	RoleIDs      []string
}

func withAdminSession(t *testing.T, p *RolePlugin, req *http.Request, ctx adminSessionContext) {
	t.Helper()
	token := "token-" + strings.ReplaceAll(ctx.AccountID, "-", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/account/detail" && r.URL.Query().Get("operator_session_token") == token && r.URL.Query().Get("account_id") == ctx.AccountID {
			writeJSON(w, 0, map[string]any{
				"account_id":     ctx.AccountID,
				"is_super_admin": ctx.IsSuperAdmin,
				"roles":          testAccountRoles(t, p, ctx.RoleIDs),
			}, "ok")
			return
		}
		if r.URL.Path != "/api/account/me" || r.URL.Query().Get("session_token") != token {
			writeJSON(w, 2212, nil, "会话不存在或已过期")
			return
		}
		roles := testAccountRoles(t, p, ctx.RoleIDs)
		if ctx.IsSuperAdmin {
			roles = []map[string]string{}
		}
		writeJSON(w, 0, map[string]any{
			"account_id":     ctx.AccountID,
			"is_super_admin": ctx.IsSuperAdmin,
			"roles":          roles,
		}, "ok")
	}))
	t.Cleanup(server.Close)
	p.runtimeAddr = server.URL
	req.Header.Set("X-Admin-Session-Token", token)
}

func testAccountRoles(t *testing.T, p *RolePlugin, roleIDs []string) []map[string]string {
	t.Helper()
	roles := make([]map[string]string, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, exists, err := p.getRole(context.Background(), roleID)
		if err != nil || !exists {
			roles = append(roles, map[string]string{"role_id": roleID, "role_status": "missing"})
			continue
		}
		roles = append(roles, map[string]string{"role_id": roleID, "role_status": role.Status})
	}
	return roles
}

type testResponse struct {
	Status int    `json:"status"`
	Data   any    `json:"data"`
	Msg    string `json:"msg"`
}

func decodeTestResponse(t *testing.T, rec *httptest.ResponseRecorder) testResponse {
	t.Helper()
	var resp testResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, rec.Body.String())
	}
	return resp
}
