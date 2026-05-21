package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type roleListFilter struct {
	ParentID  string
	ParentSet bool
	Status    string
	Keyword   string
	Page      int
	PageSize  int
}

func (p *RolePlugin) createRole(ctx context.Context, name, parentID, description, status string) (roleRecord, error) {
	if p.db != nil {
		var role roleRecord
		var parent sql.NullString
		if parentID != "" {
			parent = sql.NullString{String: parentID, Valid: true}
		}
		err := p.db.QueryRowContext(ctx, `
			INSERT INTO role_roles (name, parent_id, description, status)
			VALUES ($1, $2, $3, $4)
			RETURNING id::text, name, COALESCE(parent_id::text, ''), description, status, created_at, updated_at, COALESCE(deleted_at, '0001-01-01'::timestamptz)`,
			name, parent, description, status).Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt, &role.DeletedAt)
		return role, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	role := roleRecord{ID: newUUIDLikeID(), Name: name, ParentID: parentID, Description: description, Status: status, CreatedAt: now, UpdatedAt: now}
	p.roles[role.ID] = role
	return role, nil
}

func (p *RolePlugin) createRoleWithPermissions(ctx context.Context, name, parentID, description, status string, permissionIDs []string) (roleRecord, error) {
	if p.db != nil {
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return roleRecord{}, err
		}
		defer tx.Rollback()
		var role roleRecord
		var parent sql.NullString
		if parentID != "" {
			parent = sql.NullString{String: parentID, Valid: true}
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO role_roles (name, parent_id, description, status)
			VALUES ($1, $2, $3, $4)
			RETURNING id::text, name, COALESCE(parent_id::text, ''), description, status, created_at, updated_at, COALESCE(deleted_at, '0001-01-01'::timestamptz)`,
			name, parent, description, status).Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt, &role.DeletedAt); err != nil {
			return roleRecord{}, err
		}
		for _, permissionID := range permissionIDs {
			if _, err := tx.ExecContext(ctx, "INSERT INTO role_role_permissions (role_id, permission_id) VALUES ($1, $2)", role.ID, permissionID); err != nil {
				return roleRecord{}, err
			}
		}
		if err := tx.Commit(); err != nil {
			return roleRecord{}, err
		}
		return role, nil
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	role := roleRecord{ID: newUUIDLikeID(), Name: name, ParentID: parentID, Description: description, Status: status, CreatedAt: now, UpdatedAt: now}
	set := map[string]bool{}
	for _, id := range permissionIDs {
		if _, exists := p.permissions[id]; !exists {
			return roleRecord{}, errors.New("permission not found")
		}
		set[id] = true
	}
	p.roles[role.ID] = role
	p.rolePerms[role.ID] = set
	return role, nil
}

func (p *RolePlugin) updateRole(ctx context.Context, role roleRecord) (roleRecord, error) {
	role.UpdatedAt = time.Now().UTC()
	if p.db != nil {
		var parent sql.NullString
		if role.ParentID != "" {
			parent = sql.NullString{String: role.ParentID, Valid: true}
		}
		err := p.db.QueryRowContext(ctx, `
			UPDATE role_roles
			SET name=$1, parent_id=$2, description=$3, status=$4, updated_at=now()
			WHERE id=$5 AND deleted_at IS NULL
			RETURNING id::text, name, COALESCE(parent_id::text, ''), description, status, created_at, updated_at, COALESCE(deleted_at, '0001-01-01'::timestamptz)`,
			role.Name, parent, role.Description, role.Status, role.ID).Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt, &role.DeletedAt)
		return role, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.roles[role.ID] = role
	return role, nil
}

func (p *RolePlugin) getRole(ctx context.Context, roleID string) (roleRecord, bool, error) {
	if p.db != nil {
		var role roleRecord
		err := p.db.QueryRowContext(ctx, `
			SELECT id::text, name, COALESCE(parent_id::text, ''), description, status, created_at, updated_at
			FROM role_roles WHERE id=$1 AND deleted_at IS NULL`, roleID).Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return roleRecord{}, false, nil
		}
		return role, err == nil, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	role, ok := p.roles[roleID]
	if ok && !role.DeletedAt.IsZero() {
		return roleRecord{}, false, nil
	}
	return role, ok, nil
}

func (p *RolePlugin) roleExists(ctx context.Context, roleID string) bool {
	_, exists, err := p.getRole(ctx, roleID)
	return err == nil && exists
}

func (p *RolePlugin) siblingNameExists(ctx context.Context, excludeRoleID, parentID, name string) bool {
	if p.db != nil {
		var count int
		var err error
		if parentID == "" {
			if excludeRoleID == "" {
				err = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_roles WHERE parent_id IS NULL AND name=$1 AND deleted_at IS NULL`, name).Scan(&count)
			} else {
				err = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_roles WHERE parent_id IS NULL AND name=$1 AND id<>$2 AND deleted_at IS NULL`, name, excludeRoleID).Scan(&count)
			}
		} else {
			if excludeRoleID == "" {
				err = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_roles WHERE parent_id=$1 AND name=$2 AND deleted_at IS NULL`, parentID, name).Scan(&count)
			} else {
				err = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_roles WHERE parent_id=$1 AND name=$2 AND id<>$3 AND deleted_at IS NULL`, parentID, name, excludeRoleID).Scan(&count)
			}
		}
		return err == nil && count > 0
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, role := range p.roles {
		if !role.DeletedAt.IsZero() {
			continue
		}
		if role.ID != excludeRoleID && role.ParentID == parentID && role.Name == name {
			return true
		}
	}
	return false
}

func (p *RolePlugin) listRoles(ctx context.Context, f roleListFilter) ([]roleResponse, int, error) {
	if p.db != nil {
		where, args := []string{"r.deleted_at IS NULL"}, []any{}
		if f.ParentSet {
			if f.ParentID == "" {
				where = append(where, "r.parent_id IS NULL")
			} else {
				args = append(args, f.ParentID)
				where = append(where, fmt.Sprintf("r.parent_id=$%d", len(args)))
			}
		}
		if f.Status != "" {
			args = append(args, f.Status)
			where = append(where, fmt.Sprintf("r.status=$%d", len(args)))
		}
		if f.Keyword != "" {
			args = append(args, "%"+f.Keyword+"%")
			where = append(where, fmt.Sprintf("r.name ILIKE $%d", len(args)))
		}
		whereSQL := strings.Join(where, " AND ")
		var total int
		if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM role_roles r WHERE "+whereSQL, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
		rows, err := p.db.QueryContext(ctx, `
			SELECT r.id::text, r.name, COALESCE(r.parent_id::text, ''), COALESCE(p.name, ''), r.status, r.description, r.created_at
			FROM role_roles r
			LEFT JOIN role_roles p ON p.id = r.parent_id AND p.deleted_at IS NULL
			WHERE `+whereSQL+`
			ORDER BY r.created_at DESC, r.id
			LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()
		items := []roleResponse{}
		for rows.Next() {
			var role roleRecord
			var parentName string
			if err := rows.Scan(&role.ID, &role.Name, &role.ParentID, &parentName, &role.Status, &role.Description, &role.CreatedAt); err != nil {
				return nil, 0, err
			}
			items = append(items, roleToResponse(role, parentName))
		}
		return items, total, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	all := make([]roleRecord, 0, len(p.roles))
	for _, role := range p.roles {
		if !role.DeletedAt.IsZero() {
			continue
		}
		if f.ParentSet && role.ParentID != f.ParentID {
			continue
		}
		if f.Status != "" && role.Status != f.Status {
			continue
		}
		if f.Keyword != "" && !strings.Contains(role.Name, f.Keyword) {
			continue
		}
		all = append(all, role)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	total := len(all)
	start, end := pageBounds(total, f.Page, f.PageSize)
	items := []roleResponse{}
	for _, role := range all[start:end] {
		parentName := ""
		if parent := p.roles[role.ParentID]; parent.ID != "" {
			parentName = parent.Name
		}
		items = append(items, roleToResponse(role, parentName))
	}
	return items, total, nil
}

func (p *RolePlugin) roleDetail(ctx context.Context, roleID string) (roleResponse, bool, error) {
	role, exists, err := p.getRole(ctx, roleID)
	if err != nil || !exists {
		return roleResponse{}, exists, err
	}
	parentName := ""
	if role.ParentID != "" {
		if parent, ok, err := p.getRole(ctx, role.ParentID); err == nil && ok {
			parentName = parent.Name
		}
	}
	resp := roleToResponse(role, parentName)
	permissions, err := p.rolePermissions(ctx, roleID)
	if err != nil {
		return roleResponse{}, false, err
	}
	resp.Permissions = permissions
	return resp, true, nil
}

func (p *RolePlugin) createPermission(ctx context.Context, code, name, description string) (permissionRecord, error) {
	if p.db != nil {
		var perm permissionRecord
		err := p.db.QueryRowContext(ctx, `
			INSERT INTO role_permissions (code, name, description)
			VALUES ($1, $2, $3)
			RETURNING id::text, code, name, description, created_at, updated_at`,
			code, name, description).Scan(&perm.ID, &perm.Code, &perm.Name, &perm.Description, &perm.CreatedAt, &perm.UpdatedAt)
		return perm, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	perm := permissionRecord{ID: newUUIDLikeID(), Code: code, Name: name, Description: description, CreatedAt: now, UpdatedAt: now}
	p.permissions[perm.ID] = perm
	return perm, nil
}

func (p *RolePlugin) permissionCodeExists(ctx context.Context, code string) bool {
	_, exists, err := p.getPermissionByCode(ctx, code)
	return err == nil && exists
}

func (p *RolePlugin) getPermissionByCode(ctx context.Context, code string) (permissionRecord, bool, error) {
	if p.db != nil {
		var perm permissionRecord
		err := p.db.QueryRowContext(ctx, `
			SELECT id::text, code, name, description, created_at, updated_at
			FROM role_permissions WHERE code=$1`, code).Scan(&perm.ID, &perm.Code, &perm.Name, &perm.Description, &perm.CreatedAt, &perm.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return permissionRecord{}, false, nil
		}
		return perm, err == nil, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, perm := range p.permissions {
		if perm.Code == code {
			return perm, true, nil
		}
	}
	return permissionRecord{}, false, nil
}

func (p *RolePlugin) listPermissions(ctx context.Context, keyword string, page, pageSize int) ([]permissionResponse, int, error) {
	if p.db != nil {
		where := "1=1"
		args := []any{}
		if keyword != "" {
			args = append(args, "%"+keyword+"%")
			where = "(code ILIKE $1 OR name ILIKE $1)"
		}
		var total int
		if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM role_permissions WHERE "+where, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		args = append(args, pageSize, (page-1)*pageSize)
		rows, err := p.db.QueryContext(ctx, `
			SELECT id::text, code, name, description, created_at
			FROM role_permissions
			WHERE `+where+`
			ORDER BY code
			LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()
		items := []permissionResponse{}
		for rows.Next() {
			var perm permissionRecord
			if err := rows.Scan(&perm.ID, &perm.Code, &perm.Name, &perm.Description, &perm.CreatedAt); err != nil {
				return nil, 0, err
			}
			items = append(items, permissionToResponse(perm))
		}
		return items, total, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	all := make([]permissionRecord, 0, len(p.permissions))
	for _, perm := range p.permissions {
		if keyword == "" || strings.Contains(perm.Code, keyword) || strings.Contains(perm.Name, keyword) {
			all = append(all, perm)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Code < all[j].Code })
	total := len(all)
	start, end := pageBounds(total, page, pageSize)
	items := []permissionResponse{}
	for _, perm := range all[start:end] {
		items = append(items, permissionToResponse(perm))
	}
	return items, total, nil
}
