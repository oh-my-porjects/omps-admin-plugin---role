package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (p *RolePlugin) roleChildrenTree(ctx context.Context, roleID string) (roleTreeNode, bool, error) {
	role, exists, err := p.getRole(ctx, roleID)
	if err != nil || !exists {
		return roleTreeNode{}, exists, err
	}
	return p.buildRoleTreeNode(ctx, role)
}

func (p *RolePlugin) buildRoleTreeNode(ctx context.Context, role roleRecord) (roleTreeNode, bool, error) {
	parentName := ""
	if role.ParentID != "" {
		if parent, ok, err := p.getRole(ctx, role.ParentID); err != nil {
			return roleTreeNode{}, false, err
		} else if ok {
			parentName = parent.Name
		}
	}
	children, err := p.childRoles(ctx, role.ID)
	if err != nil {
		return roleTreeNode{}, false, err
	}
	node := roleTreeNode{
		RoleID:        role.ID,
		Name:          role.Name,
		ParentID:      role.ParentID,
		ParentRoleID:  role.ParentID,
		ParentName:    parentName,
		Status:        role.Status,
		Description:   role.Description,
		HasChildren:   len(children) > 0,
		ChildrenCount: len(children),
		Children:      []roleTreeNode{},
	}
	for _, child := range children {
		childNode, ok, err := p.buildRoleTreeNode(ctx, child)
		if err != nil {
			return roleTreeNode{}, false, err
		}
		if ok {
			node.Children = append(node.Children, childNode)
		}
	}
	return node, true, nil
}

func (p *RolePlugin) childRoles(ctx context.Context, roleID string) ([]roleRecord, error) {
	if p.db != nil {
		rows, err := p.db.QueryContext(ctx, `
			SELECT id::text, name, COALESCE(parent_id::text, ''), description, status, created_at, updated_at
			FROM role_roles
			WHERE parent_id=$1 AND deleted_at IS NULL
			ORDER BY created_at ASC, id`, roleID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var roles []roleRecord
		for rows.Next() {
			var role roleRecord
			if err := rows.Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt); err != nil {
				return nil, err
			}
			roles = append(roles, role)
		}
		return roles, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	roles := []roleRecord{}
	for _, role := range p.roles {
		if role.ParentID == roleID && role.DeletedAt.IsZero() {
			roles = append(roles, role)
		}
	}
	sort.Slice(roles, func(i, j int) bool {
		if roles[i].CreatedAt.Equal(roles[j].CreatedAt) {
			return roles[i].ID < roles[j].ID
		}
		return roles[i].CreatedAt.Before(roles[j].CreatedAt)
	})
	return roles, nil
}

func (p *RolePlugin) deleteRoleCascade(ctx context.Context, roleID string) ([]string, time.Time, error) {
	now := time.Now().UTC()
	if p.db != nil {
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, time.Time{}, err
		}
		defer tx.Rollback()
		rows, err := tx.QueryContext(ctx, `
			WITH RECURSIVE tree AS (
				SELECT id FROM role_roles WHERE id=$1 AND deleted_at IS NULL
				UNION ALL
				SELECT r.id FROM role_roles r
				JOIN tree t ON r.parent_id = t.id
				WHERE r.deleted_at IS NULL
			),
			updated AS (
				UPDATE role_roles
				SET deleted_at=now(), updated_at=now()
				WHERE id IN (SELECT id FROM tree)
				RETURNING id::text, deleted_at
			)
			SELECT id, deleted_at FROM updated
			ORDER BY id`, roleID)
		if err != nil {
			return nil, time.Time{}, err
		}
		defer rows.Close()
		ids := []string{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id, &now); err != nil {
				return nil, time.Time{}, err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return nil, time.Time{}, err
		}
		return ids, now, tx.Commit()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := p.collectRoleIDsForDeleteLocked(roleID)
	for _, id := range ids {
		role := p.roles[id]
		role.DeletedAt = now
		role.UpdatedAt = now
		p.roles[id] = role
	}
	sort.Strings(ids)
	return ids, now, nil
}

func (p *RolePlugin) collectRoleIDsForDeleteLocked(roleID string) []string {
	role, exists := p.roles[roleID]
	if !exists || !role.DeletedAt.IsZero() {
		return nil
	}
	ids := []string{roleID}
	for _, child := range p.roles {
		if child.ParentID == roleID && child.DeletedAt.IsZero() {
			ids = append(ids, p.collectRoleIDsForDeleteLocked(child.ID)...)
		}
	}
	return ids
}

func (p *RolePlugin) setRoleStatus(ctx context.Context, roleID, status string) (roleRecord, error) {
	if p.db != nil {
		var role roleRecord
		err := p.db.QueryRowContext(ctx, `
			UPDATE role_roles
			SET status=$2, updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL
			RETURNING id::text, name, COALESCE(parent_id::text, ''), description, status, created_at, updated_at`,
			roleID, status).Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt)
		return role, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	role := p.roles[roleID]
	role.Status = status
	role.UpdatedAt = time.Now().UTC()
	p.roles[roleID] = role
	return role, nil
}

func (p *RolePlugin) rolesByIDsForAudit(ctx context.Context, roleIDs []string) ([]roleRecord, error) {
	if p.db != nil {
		placeholders := make([]string, 0, len(roleIDs))
		args := make([]any, 0, len(roleIDs))
		for i, id := range roleIDs {
			placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
			args = append(args, id)
		}
		rows, err := p.db.QueryContext(ctx, `
			SELECT id::text, name, COALESCE(parent_id::text, ''), description, status, created_at, updated_at, COALESCE(deleted_at, '0001-01-01'::timestamptz)
			FROM role_roles
			WHERE id IN (`+strings.Join(placeholders, ",")+`)
			ORDER BY id`, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		roles := []roleRecord{}
		for rows.Next() {
			var role roleRecord
			if err := rows.Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt, &role.DeletedAt); err != nil {
				return nil, err
			}
			roles = append(roles, role)
		}
		return roles, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	roles := make([]roleRecord, 0, len(roleIDs))
	for _, id := range roleIDs {
		if role, exists := p.roles[id]; exists {
			roles = append(roles, role)
		}
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].ID < roles[j].ID })
	return roles, nil
}

func (p *RolePlugin) activeRolesByIDs(ctx context.Context, roleIDs []string) ([]roleRecord, error) {
	roles, err := p.rolesByIDsForAudit(ctx, roleIDs)
	if err != nil {
		return nil, err
	}
	active := make([]roleRecord, 0, len(roles))
	for _, role := range roles {
		if role.DeletedAt.IsZero() {
			active = append(active, role)
		}
	}
	return active, nil
}
