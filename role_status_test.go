package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleRoleChildrenTree(t *testing.T) {
	p := testRolePlugin()
	parent := p.roles[supportRoleID]
	parent.ParentID = rootRoleID
	p.roles[supportRoleID] = parent
	operator := p.roles[disabledRoleID]
	operator.ParentID = ""
	p.roles[disabledRoleID] = operator
	nowChild := roleRecord{ID: "00000000-0000-0000-0000-000000000201", Name: "内容运营", ParentID: supportRoleID, Status: "enabled"}
	nowGrandChild := roleRecord{ID: "00000000-0000-0000-0000-000000000202", Name: "审核专员", ParentID: nowChild.ID, Status: "disabled"}
	p.roles[nowChild.ID] = nowChild
	p.roles[nowGrandChild.ID] = nowGrandChild

	req := httptest.NewRequest(http.MethodGet, "/api/role/children-tree?role_id="+supportRoleID, nil)
	rec := httptest.NewRecorder()
	p.handleRoleChildrenTree(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 0 {
		t.Fatalf("status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
	data := resp.Data.(map[string]any)
	if data["role_id"] != supportRoleID || int(data["children_count"].(float64)) != 1 {
		t.Fatalf("unexpected tree data: %#v", data)
	}
	children := data["children"].([]any)
	grandChildren := children[0].(map[string]any)["children"].([]any)
	if len(grandChildren) != 1 {
		t.Fatalf("grand children len = %d, want 1", len(grandChildren))
	}
}

func TestLegacyShortRoleIDStatusHandlers(t *testing.T) {
	p := testRolePlugin()
	role := roleRecord{ID: "fS9Cmj6bzKBa", Name: "历史角色", ParentID: rootRoleID, Status: "enabled"}
	p.roles[role.ID] = role

	detailReq := httptest.NewRequest(http.MethodGet, "/api/role/detail?role_id="+role.ID, nil)
	detailRec := httptest.NewRecorder()
	p.handleRoleDetail(detailRec, detailReq)
	if resp := decodeTestResponse(t, detailRec); resp.Status != 0 {
		t.Fatalf("detail status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}

	treeReq := httptest.NewRequest(http.MethodGet, "/api/role/children-tree?role_id="+role.ID, nil)
	treeRec := httptest.NewRecorder()
	p.handleRoleChildrenTree(treeRec, treeReq)
	if resp := decodeTestResponse(t, treeRec); resp.Status != 0 {
		t.Fatalf("children-tree status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}

	disableReq := httptest.NewRequest(http.MethodPost, "/api/role/disable", jsonBody(map[string]any{"role_id": role.ID}))
	disableRec := httptest.NewRecorder()
	p.handleRoleDisable(disableRec, disableReq)
	if resp := decodeTestResponse(t, disableRec); resp.Status != 0 {
		t.Fatalf("disable status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
}

func TestHandleRoleDeleteCascade(t *testing.T) {
	p := testRolePlugin()
	role := roleRecord{ID: "00000000-0000-0000-0000-000000000211", Name: "运营中心", ParentID: rootRoleID, Status: "enabled"}
	child := roleRecord{ID: "00000000-0000-0000-0000-000000000212", Name: "活动运营", ParentID: role.ID, Status: "enabled"}
	p.roles[role.ID] = role
	p.roles[child.ID] = child

	req := httptest.NewRequest(http.MethodPost, "/api/role/delete", jsonBody(map[string]any{"role_id": role.ID}))
	rec := httptest.NewRecorder()
	p.handleRoleDelete(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 0 {
		t.Fatalf("status = %d, want 0, msg=%s", resp.Status, resp.Msg)
	}
	if _, exists, _ := p.getRole(context.Background(), role.ID); exists {
		t.Fatal("deleted role should not be visible")
	}
	if _, exists, _ := p.getRole(context.Background(), child.ID); exists {
		t.Fatal("deleted child role should not be visible")
	}
}

func TestHandleRoleDeleteProtected(t *testing.T) {
	p := testRolePlugin()
	req := httptest.NewRequest(http.MethodPost, "/api/role/delete", jsonBody(map[string]any{"role_id": rootRoleID}))
	rec := httptest.NewRecorder()
	p.handleRoleDelete(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 2323 {
		t.Fatalf("status = %d, want 2323, msg=%s", resp.Status, resp.Msg)
	}

	liveLikeOperator := roleRecord{ID: "jt38GzzJ1Egf", Name: "运营", ParentID: supportRoleID, Status: "enabled"}
	p.roles[liveLikeOperator.ID] = liveLikeOperator
	liveReq := httptest.NewRequest(http.MethodPost, "/api/role/delete", jsonBody(map[string]any{"role_id": liveLikeOperator.ID}))
	liveRec := httptest.NewRecorder()
	p.handleRoleDelete(liveRec, liveReq)
	liveResp := decodeTestResponse(t, liveRec)
	if liveResp.Status != 2323 {
		t.Fatalf("live-like status = %d, want 2323, msg=%s", liveResp.Status, liveResp.Msg)
	}
}

func TestHandleRoleDisableEnable(t *testing.T) {
	p := testRolePlugin()
	auditActions := []string{}
	p.audit = func(action string, before any, after any, extra map[string]any) {
		auditActions = append(auditActions, action)
		if before == nil || after == nil {
			t.Fatalf("audit %s missing before/after", action)
		}
		if extra["role_id"] == "" {
			t.Fatalf("audit %s missing role_id", action)
		}
	}
	role := roleRecord{ID: "00000000-0000-0000-0000-000000000221", Name: "活动运营", ParentID: rootRoleID, Status: "enabled"}
	p.roles[role.ID] = role

	disableReq := httptest.NewRequest(http.MethodPost, "/api/role/disable", jsonBody(map[string]any{"role_id": role.ID}))
	disableRec := httptest.NewRecorder()
	p.handleRoleDisable(disableRec, disableReq)
	disableResp := decodeTestResponse(t, disableRec)
	if disableResp.Status != 0 {
		t.Fatalf("disable status = %d, want 0, msg=%s", disableResp.Status, disableResp.Msg)
	}

	enableReq := httptest.NewRequest(http.MethodPost, "/api/role/enable", jsonBody(map[string]any{"role_id": role.ID}))
	enableRec := httptest.NewRecorder()
	p.handleRoleEnable(enableRec, enableReq)
	enableResp := decodeTestResponse(t, enableRec)
	if enableResp.Status != 0 {
		t.Fatalf("enable status = %d, want 0, msg=%s", enableResp.Status, enableResp.Msg)
	}
	if len(auditActions) != 2 || auditActions[0] != "disable_role" || auditActions[1] != "enable_role" {
		t.Fatalf("audit actions = %#v, want disable_role then enable_role", auditActions)
	}
}

func TestHandleRoleEnableParentDisabled(t *testing.T) {
	p := testRolePlugin()
	parent := roleRecord{ID: "00000000-0000-0000-0000-000000000231", Name: "父角色", ParentID: rootRoleID, Status: "disabled"}
	role := roleRecord{ID: "00000000-0000-0000-0000-000000000232", Name: "子角色", ParentID: parent.ID, Status: "disabled"}
	p.roles[parent.ID] = parent
	p.roles[role.ID] = role

	req := httptest.NewRequest(http.MethodPost, "/api/role/enable", jsonBody(map[string]any{"role_id": role.ID}))
	rec := httptest.NewRecorder()
	p.handleRoleEnable(rec, req)
	resp := decodeTestResponse(t, rec)
	if resp.Status != 2344 {
		t.Fatalf("status = %d, want 2344, msg=%s", resp.Status, resp.Msg)
	}
}
