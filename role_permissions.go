package main

import (
	"context"
	"time"
)

func (p *RolePlugin) permissionsExist(ctx context.Context, ids []string) bool {
	if len(ids) == 0 {
		return true
	}
	if p.db != nil {
		for _, id := range ids {
			var exists bool
			if err := p.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM role_permissions WHERE id=$1)", id).Scan(&exists); err != nil || !exists {
				return false
			}
		}
		return true
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		if _, ok := p.permissions[id]; !ok {
			return false
		}
	}
	return true
}

func (p *RolePlugin) assignPermissions(ctx context.Context, roleID string, permissionIDs []string) (time.Time, error) {
	now := time.Now().UTC()
	if p.db != nil {
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return time.Time{}, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, "DELETE FROM role_role_permissions WHERE role_id=$1", roleID); err != nil {
			return time.Time{}, err
		}
		for _, permissionID := range permissionIDs {
			if _, err := tx.ExecContext(ctx, "INSERT INTO role_role_permissions (role_id, permission_id) VALUES ($1, $2)", roleID, permissionID); err != nil {
				return time.Time{}, err
			}
		}
		if err := tx.QueryRowContext(ctx, "UPDATE role_roles SET updated_at=now() WHERE id=$1 AND deleted_at IS NULL RETURNING updated_at", roleID).Scan(&now); err != nil {
			return time.Time{}, err
		}
		return now, tx.Commit()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	set := map[string]bool{}
	for _, id := range permissionIDs {
		set[id] = true
	}
	p.rolePerms[roleID] = set
	role := p.roles[roleID]
	role.UpdatedAt = now
	p.roles[roleID] = role
	return now, nil
}

func (p *RolePlugin) permissionSet(ctx context.Context, roleID string) (map[string]bool, error) {
	set := map[string]bool{}
	if roleID == "" {
		return nil, nil
	}
	if p.db != nil {
		rows, err := p.db.QueryContext(ctx, "SELECT permission_id::text FROM role_role_permissions WHERE role_id=$1", roleID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			set[id] = true
		}
		return set, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.rolePerms[roleID] {
		set[id] = true
	}
	return set, nil
}

func (p *RolePlugin) rolePermissions(ctx context.Context, roleID string) ([]permissionResponse, error) {
	if p.db != nil {
		rows, err := p.db.QueryContext(ctx, `
			SELECT p.id::text, p.code, p.name, p.description, p.created_at
			FROM role_role_permissions rp
			JOIN role_permissions p ON p.id = rp.permission_id
			WHERE rp.role_id=$1
			ORDER BY p.code`, roleID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := []permissionResponse{}
		for rows.Next() {
			var perm permissionRecord
			if err := rows.Scan(&perm.ID, &perm.Code, &perm.Name, &perm.Description, &perm.CreatedAt); err != nil {
				return nil, err
			}
			items = append(items, permissionToResponse(perm))
		}
		return items, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := sortedKeys(p.rolePerms[roleID])
	items := []permissionResponse{}
	for _, id := range ids {
		if perm, ok := p.permissions[id]; ok {
			items = append(items, permissionToResponse(perm))
		}
	}
	return items, nil
}

func (p *RolePlugin) rolePermissionsWithinParent(ctx context.Context, roleID, parentID string) (bool, error) {
	parentSet, err := p.permissionSet(ctx, parentID)
	if err != nil {
		return false, err
	}
	roleSet, err := p.permissionSet(ctx, roleID)
	if err != nil {
		return false, err
	}
	return permissionSetWithin(parentSet, roleSet), nil
}

func (p *RolePlugin) childrenWithinPermissionSet(ctx context.Context, roleID string, parentSet map[string]bool) (bool, error) {
	children, err := p.childRoleIDs(ctx, roleID)
	if err != nil {
		return false, err
	}
	for _, childID := range children {
		childSet, err := p.permissionSet(ctx, childID)
		if err != nil {
			return false, err
		}
		if !permissionSetWithin(parentSet, childSet) {
			return false, nil
		}
	}
	return true, nil
}

func (p *RolePlugin) childRoleIDs(ctx context.Context, roleID string) ([]string, error) {
	if p.db != nil {
		rows, err := p.db.QueryContext(ctx, "SELECT id::text FROM role_roles WHERE parent_id=$1 AND deleted_at IS NULL", roleID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for _, role := range p.roles {
		if role.ParentID == roleID && role.DeletedAt.IsZero() {
			ids = append(ids, role.ID)
		}
	}
	return ids, nil
}

func (p *RolePlugin) wouldCreateCycle(ctx context.Context, roleID, parentID string) bool {
	for current := parentID; current != ""; {
		if current == roleID {
			return true
		}
		parent, exists, err := p.getRole(ctx, current)
		if err != nil || !exists {
			return false
		}
		current = parent.ParentID
	}
	return false
}

func (p *RolePlugin) roleDirectlyHasPermission(ctx context.Context, roleID, permissionID string) bool {
	if p.db != nil {
		var exists bool
		err := p.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM role_role_permissions WHERE role_id=$1 AND permission_id=$2)", roleID, permissionID).Scan(&exists)
		return err == nil && exists
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rolePerms[roleID][permissionID]
}

func (p *RolePlugin) roleHasPermissionCode(ctx context.Context, roleID, permissionCode string) (bool, error) {
	perm, exists, err := p.getPermissionByCode(ctx, permissionCode)
	if err != nil || !exists {
		return false, err
	}
	return p.roleDirectlyHasPermission(ctx, roleID, perm.ID), nil
}

func permissionSetWithin(parentSet map[string]bool, childSet map[string]bool) bool {
	if parentSet == nil {
		return true
	}
	for id := range childSet {
		if !parentSet[id] {
			return false
		}
	}
	return true
}
