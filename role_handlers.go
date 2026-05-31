package main

import (
	"net/http"
	"strings"
)

func (p *RolePlugin) handleRoleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		ParentID      string   `json:"parent_id"`
		ParentRoleID  string   `json:"parent_role_id"`
		Description   string   `json:"description"`
		Status        string   `json:"status"`
		PermissionIDs []string `json:"permission_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 4101, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.ParentID = strings.TrimSpace(req.ParentID)
	req.ParentRoleID = strings.TrimSpace(req.ParentRoleID)
	req.Description = strings.TrimSpace(req.Description)
	req.Status = strings.TrimSpace(req.Status)
	if req.ParentRoleID != "" {
		req.ParentID = req.ParentRoleID
	}
	if !validName(req.Name) {
		writeJSON(w, 4101, nil, "角色名称缺失或长度不合法")
		return
	}
	if !validStatus(req.Status) {
		writeJSON(w, 4101, nil, "角色状态不合法")
		return
	}
	if runeLen(req.Description) > 200 {
		writeJSON(w, 4101, nil, "角色说明过长")
		return
	}
	if req.ParentID != "" && !validRecordID(req.ParentID) {
		writeJSON(w, 4101, nil, "父级角色 ID 参数格式非法")
		return
	}
	permissionIDs, ok := cleanPermissionIDs(req.PermissionIDs)
	if !ok {
		writeJSON(w, 4101, nil, "权限 ID 列表参数格式非法")
		return
	}
	if !p.permissionsExist(r.Context(), permissionIDs) {
		writeJSON(w, 4108, nil, "绑定的权限不存在")
		return
	}
	accountCtx, ok, err := p.currentAdminAccountContext(r)
	if err != nil {
		writeJSON(w, 4109, nil, "当前账号身份或角色绑定信息读取失败")
		return
	}
	if !ok {
		writeJSON(w, 4109, nil, "缺少当前账号身份或角色绑定信息")
		return
	}
	parentID, manualParent := req.ParentID, req.ParentID != ""
	if parentID == "" {
		parentID, ok = accountCtx.uniqueRoleID()
		if !ok {
			if accountCtx.IsSuperAdmin && len(accountCtx.RoleIDs) == 0 {
				parentID = ""
			} else {
				writeJSON(w, 4106, nil, "当前账号未绑定角色，且不是允许创建顶级角色的超级管理员")
				return
			}
		}
	}
	if parentID != "" {
		parentRole, exists, err := p.getRole(r.Context(), parentID)
		if err != nil {
			writeJSON(w, 4109, nil, "当前账号身份或角色绑定信息读取失败")
			return
		}
		if !exists {
			if manualParent {
				writeJSON(w, 4103, nil, "手动指定的父级角色不存在或已删除")
			} else {
				writeJSON(w, 4107, nil, "当前账号绑定角色不存在、已删除或未启用")
			}
			return
		}
		if parentRole.Status != "enabled" {
			if manualParent {
				writeJSON(w, 4104, nil, "手动指定的父级角色未启用")
			} else {
				writeJSON(w, 4107, nil, "当前账号绑定角色不存在或未启用")
			}
			return
		}
		if !accountCtx.canOperateRole(parentID) {
			if manualParent {
				writeJSON(w, 4105, nil, "手动指定的父级角色不在当前账号可操作范围内")
			} else {
				writeJSON(w, 4107, nil, "当前账号绑定角色不存在或未启用")
			}
			return
		}
	}
	if !permissionsAllowedByParent(r.Context(), p, parentID, permissionIDs) {
		writeJSON(w, 4108, nil, "绑定的权限不存在或超出父级角色权限范围")
		return
	}
	if p.siblingNameExists(r.Context(), "", parentID, req.Name) {
		writeJSON(w, 4102, nil, "角色名称已存在")
		return
	}
	role, err := p.createRoleWithPermissions(r.Context(), req.Name, parentID, req.Description, req.Status, permissionIDs)
	if err != nil {
		writeJSON(w, 4102, nil, "创建角色失败")
		return
	}
	resp := roleToResponse(role, "")
	resp.PermissionIDs = permissionIDs
	writeJSON(w, 0, resp, "")
}

func (p *RolePlugin) handleRoleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, pageSize, ok := parsePage(q.Get("page"), q.Get("page_size"))
	if !ok {
		writeJSON(w, 2111, nil, "分页参数不合法")
		return
	}
	status := strings.TrimSpace(q.Get("status"))
	if status != "" && !validStatus(status) {
		writeJSON(w, 2112, nil, "状态参数不合法")
		return
	}
	parentID := strings.TrimSpace(q.Get("parent_id"))
	parentFilterSet := q.Has("parent_id")
	if parentID != "" && !validRecordID(parentID) {
		writeJSON(w, 2113, nil, "父角色参数格式不合法")
		return
	}
	keyword := strings.TrimSpace(q.Get("keyword"))
	if runeLen(keyword) > 30 {
		writeJSON(w, 2114, nil, "查询角色列表失败")
		return
	}
	items, total, err := p.listRoles(r.Context(), roleListFilter{ParentID: parentID, ParentSet: parentFilterSet, Status: status, Keyword: keyword, Page: page, PageSize: pageSize})
	if err != nil {
		writeJSON(w, 2114, nil, "查询角色列表失败")
		return
	}
	writeJSON(w, 0, map[string]any{"items": items, "total": total}, "")
}

func (p *RolePlugin) handleRoleDetail(w http.ResponseWriter, r *http.Request) {
	roleID := strings.TrimSpace(r.URL.Query().Get("role_id"))
	if !validRecordID(roleID) {
		writeJSON(w, 2121, nil, "角色 ID 缺失或格式不合法")
		return
	}
	resp, exists, err := p.roleDetail(r.Context(), roleID)
	if err != nil {
		writeJSON(w, 2123, nil, "查询角色详情失败")
		return
	}
	if !exists {
		writeJSON(w, 2122, nil, "角色不存在")
		return
	}
	writeJSON(w, 0, resp, "")
}

func (p *RolePlugin) handleRoleUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID      string `json:"role_id"`
		Name        string `json:"name"`
		ParentID    string `json:"parent_id"`
		Description string `json:"description"`
		Status      string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2131, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	req.Name = strings.TrimSpace(req.Name)
	req.ParentID = strings.TrimSpace(req.ParentID)
	req.Description = strings.TrimSpace(req.Description)
	req.Status = strings.TrimSpace(req.Status)
	if !validRecordID(req.RoleID) {
		writeJSON(w, 2131, nil, "角色 ID 缺失或格式不合法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2138, nil, "更新角色失败")
		return
	}
	if !exists {
		writeJSON(w, 2132, nil, "角色不存在")
		return
	}
	if !validName(req.Name) || !validStatus(req.Status) || runeLen(req.Description) > 200 {
		writeJSON(w, 2133, nil, "角色名称或状态参数不合法")
		return
	}
	if req.ParentID != "" {
		if req.ParentID == req.RoleID {
			writeJSON(w, 2135, nil, "角色层级不允许形成循环")
			return
		}
		if !validRecordID(req.ParentID) {
			writeJSON(w, 2134, nil, "父角色不存在或父角色设置不合法")
			return
		}
		parentRole, exists, err := p.getRole(r.Context(), req.ParentID)
		if err != nil {
			writeJSON(w, 2138, nil, "更新角色失败")
			return
		}
		if !exists {
			writeJSON(w, 2134, nil, "父角色不存在或父角色设置不合法")
			return
		}
		if parentRole.Status != "enabled" {
			writeJSON(w, 2134, nil, "父角色不存在或未启用")
			return
		}
		if p.wouldCreateCycle(r.Context(), req.RoleID, req.ParentID) {
			writeJSON(w, 2135, nil, "角色层级不允许形成循环")
			return
		}
	}
	withinParent, err := p.rolePermissionsWithinParent(r.Context(), req.RoleID, req.ParentID)
	if err != nil {
		writeJSON(w, 2138, nil, "更新角色失败")
		return
	}
	if !withinParent {
		writeJSON(w, 2136, nil, "当前角色权限超出新父角色权限范围")
		return
	}
	if p.siblingNameExists(r.Context(), req.RoleID, req.ParentID, req.Name) {
		writeJSON(w, 2137, nil, "同一父角色下角色名称已存在")
		return
	}
	role.Name = req.Name
	role.ParentID = req.ParentID
	role.Description = req.Description
	role.Status = req.Status
	updated, err := p.updateRole(r.Context(), role)
	if err != nil {
		writeJSON(w, 2138, nil, "更新角色失败")
		return
	}
	writeJSON(w, 0, roleToResponse(updated, ""), "")
}

func (p *RolePlugin) handlePermissionCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code        string `json:"code"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2141, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if !validPermissionCode(req.Code) {
		writeJSON(w, 2141, nil, "权限点标识缺失或格式不合法")
		return
	}
	if !validName(req.Name) {
		writeJSON(w, 2142, nil, "权限点名称缺失或长度不合法")
		return
	}
	if runeLen(req.Description) > 200 {
		writeJSON(w, 2142, nil, "权限点说明过长")
		return
	}
	if p.permissionCodeExists(r.Context(), req.Code) {
		writeJSON(w, 2143, nil, "权限点标识已存在")
		return
	}
	perm, err := p.createPermission(r.Context(), req.Code, req.Name, req.Description)
	if err != nil {
		writeJSON(w, 2144, nil, "创建权限点失败")
		return
	}
	writeJSON(w, 0, permissionToResponse(perm), "")
}

func (p *RolePlugin) handlePermissionList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, pageSize, ok := parsePage(q.Get("page"), q.Get("page_size"))
	if !ok {
		writeJSON(w, 2151, nil, "分页参数不合法")
		return
	}
	keyword := strings.TrimSpace(q.Get("keyword"))
	if runeLen(keyword) > 80 {
		writeJSON(w, 2152, nil, "关键词参数过长")
		return
	}
	items, total, err := p.listPermissions(r.Context(), keyword, page, pageSize)
	if err != nil {
		writeJSON(w, 2153, nil, "查询权限点列表失败")
		return
	}
	writeJSON(w, 0, map[string]any{"items": items, "total": total}, "")
}

func (p *RolePlugin) handleAssignPermissions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID        string    `json:"role_id"`
		PermissionIDs *[]string `json:"permission_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 4201, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	if !validRecordID(req.RoleID) {
		writeJSON(w, 4201, nil, "角色 ID 缺失或格式不合法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 4205, nil, "分配权限失败")
		return
	}
	if !exists {
		writeJSON(w, 4202, nil, "角色不存在")
		return
	}
	if role.Status != "enabled" {
		writeJSON(w, 4203, nil, "角色状态不允许分配权限")
		return
	}
	if fullPermissionBuiltInRole(role) {
		writeJSON(w, 4203, nil, "内置全权限角色不允许分配权限")
		return
	}
	if req.PermissionIDs == nil {
		writeJSON(w, 4201, nil, "权限点 ID 列表格式不合法")
		return
	}
	permissionIDs, ok := cleanPermissionIDs(*req.PermissionIDs)
	if !ok {
		writeJSON(w, 4201, nil, "权限点 ID 列表格式不合法")
		return
	}
	assigned := boolSet(permissionIDs)
	if !p.permissionsExist(r.Context(), permissionIDs) {
		writeJSON(w, 4204, nil, "权限不存在")
		return
	}
	accountCtx, ctxOK, err := p.currentAdminAccountContext(r)
	if err != nil {
		writeJSON(w, 4205, nil, "分配权限失败")
		return
	}
	if !ctxOK {
		writeJSON(w, 4203, nil, "无法读取当前后台账号身份")
		return
	}
	if !accountCtx.canOperateRole(req.RoleID) {
		writeJSON(w, 4203, nil, "角色不在当前账号可操作范围内")
		return
	}
	parentSet, err := p.permissionSet(r.Context(), role.ParentID)
	if err != nil {
		writeJSON(w, 4205, nil, "分配权限失败")
		return
	}
	if !permissionSetWithin(parentSet, assigned) {
		writeJSON(w, 4204, nil, "权限不存在或超出父角色权限范围")
		return
	}
	childrenWithin, err := p.childrenWithinPermissionSet(r.Context(), req.RoleID, assigned)
	if err != nil {
		writeJSON(w, 4205, nil, "分配权限失败")
		return
	}
	if !childrenWithin {
		writeJSON(w, 4205, nil, "当前角色存在子角色，清理权限会导致子角色越权")
		return
	}
	updatedAt, err := p.assignPermissions(r.Context(), req.RoleID, permissionIDs)
	if err != nil {
		writeJSON(w, 4205, nil, "分配权限失败")
		return
	}
	writeJSON(w, 0, map[string]any{"role_id": req.RoleID, "permission_ids": permissionIDs, "updated_at": formatTime(updatedAt)}, "")
}

func (p *RolePlugin) handleCheckPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID         string `json:"role_id"`
		PermissionCode string `json:"permission_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 2171, nil, "请求体解析失败: "+err.Error())
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	req.PermissionCode = strings.TrimSpace(req.PermissionCode)
	if !validRecordID(req.RoleID) {
		writeJSON(w, 2171, nil, "角色 ID 缺失或格式不合法")
		return
	}
	if !validPermissionCode(req.PermissionCode) {
		writeJSON(w, 2172, nil, "权限点标识缺失或格式不合法")
		return
	}
	role, exists, err := p.getRole(r.Context(), req.RoleID)
	if err != nil {
		writeJSON(w, 2175, nil, "权限校验失败")
		return
	}
	if !exists {
		writeJSON(w, 2173, nil, "角色不存在")
		return
	}
	if role.Status == "enabled" {
		hasSystemManage, err := p.roleHasPermissionCode(r.Context(), req.RoleID, "system.manage")
		if err != nil {
			writeJSON(w, 2175, nil, "权限校验失败")
			return
		}
		if hasSystemManage {
			writeJSON(w, 0, map[string]any{"allowed": true, "role_status": role.Status}, "")
			return
		}
	}
	perm, exists, err := p.getPermissionByCode(r.Context(), req.PermissionCode)
	if err != nil {
		writeJSON(w, 2175, nil, "权限校验失败")
		return
	}
	if !exists {
		writeJSON(w, 2174, nil, "权限点不存在")
		return
	}
	allowed := role.Status == "enabled" && p.roleDirectlyHasPermission(r.Context(), req.RoleID, perm.ID)
	writeJSON(w, 0, map[string]any{"allowed": allowed, "role_status": role.Status}, "")
}
