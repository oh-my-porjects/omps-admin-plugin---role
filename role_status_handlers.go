package main

import (
	"net/http"
	"strings"
)

func (p *RolePlugin) handleRoleChildrenTree(w http.ResponseWriter, r *http.Request) {
	roleID := strings.TrimSpace(r.URL.Query().Get("role_id"))
	if !validUUID(roleID) {
		writeJSON(w, 2311, nil, "role_id 参数非法")
		return
	}
	node, exists, err := p.roleChildrenTree(r.Context(), roleID)
	if err != nil {
		writeJSON(w, 2313, nil, "查询子角色树失败")
		return
	}
	if !exists {
		writeJSON(w, 2312, nil, "角色不存在或已删除")
		return
	}
	writeJSON(w, 0, node, "")
}

func (p *RolePlugin) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID string `json:"role_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2321, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	if !validUUID(req.RoleID) {
		writeJSON(w, 2321, nil, "role_id 参数非法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2324, nil, "删除角色或级联删除子角色失败")
		return
	}
	if !exists {
		writeJSON(w, 2322, nil, "角色不存在或已删除")
		return
	}
	if protectedRole(role) {
		writeJSON(w, 2323, nil, "根角色或系统内置角色不可删除")
		return
	}
	before, _, err := p.roleChildrenTree(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2324, nil, "删除角色或级联删除子角色失败")
		return
	}
	deletedIDs, deletedAt, err := p.deleteRoleCascade(r.Context(), req.RoleID)
	if err != nil || len(deletedIDs) == 0 {
		writeJSON(w, 2324, nil, "删除角色或级联删除子角色失败")
		return
	}
	after, err := p.rolesByIDsForAudit(r.Context(), deletedIDs)
	if err != nil {
		writeJSON(w, 2324, nil, "删除角色或级联删除子角色失败")
		return
	}
	p.auditRoleChange("delete_role", before, after, map[string]any{
		"role_id":          req.RoleID,
		"deleted_count":    len(deletedIDs),
		"deleted_role_ids": deletedIDs,
	})
	writeJSON(w, 0, map[string]any{
		"role_id":          req.RoleID,
		"deleted_count":    len(deletedIDs),
		"deleted_role_ids": deletedIDs,
		"deleted_at":       formatTime(deletedAt),
	}, "")
}

func (p *RolePlugin) handleRoleDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID string `json:"role_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2331, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	if !validUUID(req.RoleID) {
		writeJSON(w, 2331, nil, "role_id 参数非法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2335, nil, "禁用角色失败")
		return
	}
	if !exists {
		writeJSON(w, 2332, nil, "角色不存在或已删除")
		return
	}
	if protectedRole(role) {
		writeJSON(w, 2333, nil, "根角色或系统内置角色不可禁用")
		return
	}
	if role.Status == "disabled" {
		writeJSON(w, 2334, nil, "角色已处于禁用状态")
		return
	}
	updated, err := p.setRoleStatus(r.Context(), req.RoleID, "disabled")
	if err != nil {
		writeJSON(w, 2335, nil, "禁用角色失败")
		return
	}
	p.auditRoleChange("disable_role", role, updated, map[string]any{"role_id": req.RoleID})
	writeJSON(w, 0, map[string]any{"role_id": updated.ID, "name": updated.Name, "status": updated.Status, "updated_at": formatTime(updated.UpdatedAt)}, "")
}

func (p *RolePlugin) handleRoleEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID string `json:"role_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2341, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	if !validUUID(req.RoleID) {
		writeJSON(w, 2341, nil, "role_id 参数非法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2345, nil, "启用角色失败")
		return
	}
	if !exists {
		writeJSON(w, 2342, nil, "角色不存在或已删除")
		return
	}
	if role.Status == "enabled" {
		writeJSON(w, 2343, nil, "角色已处于启用状态")
		return
	}
	if role.ParentID != "" {
		parent, exists, err := p.getRole(r.Context(), role.ParentID)
		if err != nil {
			writeJSON(w, 2345, nil, "启用角色失败")
			return
		}
		if !exists || parent.Status != "enabled" {
			writeJSON(w, 2344, nil, "父级角色不存在、已删除或未启用")
			return
		}
	}
	updated, err := p.setRoleStatus(r.Context(), req.RoleID, "enabled")
	if err != nil {
		writeJSON(w, 2345, nil, "启用角色失败")
		return
	}
	p.auditRoleChange("enable_role", role, updated, map[string]any{"role_id": req.RoleID})
	writeJSON(w, 0, map[string]any{"role_id": updated.ID, "name": updated.Name, "status": updated.Status, "updated_at": formatTime(updated.UpdatedAt)}, "")
}

func (p *RolePlugin) auditRoleChange(action string, before any, after any, extra map[string]any) {
	if p.audit != nil {
		p.audit(action, before, after, extra)
	}
}
