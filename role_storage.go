package main

import (
	"context"
	"time"
)

func (p *RolePlugin) initStorage(ctx context.Context) error {
	p.ensureMemoryStore()
	if p.db == nil {
		return nil
	}
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS role_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL,
			parent_id UUID,
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'enabled',
			deleted_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT role_roles_parent_fk FOREIGN KEY (parent_id) REFERENCES role_roles(id),
			CONSTRAINT role_roles_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id)
		)`,
		`CREATE TABLE IF NOT EXISTS role_permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			code TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS role_role_permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			role_id UUID NOT NULL,
			permission_id UUID NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (role_id, permission_id),
			CONSTRAINT role_role_permissions_role_fk FOREIGN KEY (role_id) REFERENCES role_roles(id) ON DELETE CASCADE,
			CONSTRAINT role_role_permissions_permission_fk FOREIGN KEY (permission_id) REFERENCES role_permissions(id) ON DELETE CASCADE
		)`,
	}
	for _, stmt := range stmts {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE role_roles ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_roles (id, name, status, description)
		VALUES ($1, 'Root', 'enabled', 'system root role')
		ON CONFLICT (id) DO NOTHING`, rootRoleID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_permissions (id, code, name, description)
		VALUES ($1, 'system.manage', 'System Manage', 'root management permission')
		ON CONFLICT (id) DO NOTHING`, rootPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_permissions (id, code, name, description)
		VALUES ($1, 'users.read', 'View Users', 'permission intentionally not assigned to root')
		ON CONFLICT (id) DO NOTHING`, unassignedPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_roles (id, name, parent_id, status, description)
		VALUES ($1, 'Support', $2, 'enabled', 'bootstrap child role')
		ON CONFLICT (id) DO NOTHING`, supportRoleID, rootRoleID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_roles (id, name, status, description)
		VALUES ($1, 'Disabled Role', 'disabled', 'bootstrap disabled role')
		ON CONFLICT (id) DO NOTHING`, disabledRoleID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING`, rootRoleID, rootPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING`, supportRoleID, rootPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING`, disabledRoleID, rootPermID); err != nil {
		return err
	}
	return nil
}

func (p *RolePlugin) ensureMemoryStore() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.roles == nil {
		p.roles = map[string]roleRecord{}
	}
	if p.permissions == nil {
		p.permissions = map[string]permissionRecord{}
	}
	if p.rolePerms == nil {
		p.rolePerms = map[string]map[string]bool{}
	}
	if _, exists := p.roles[rootRoleID]; !exists {
		now := time.Now().UTC()
		p.roles[rootRoleID] = roleRecord{ID: rootRoleID, Name: "Root", Status: "enabled", CreatedAt: now, UpdatedAt: now}
		p.permissions[rootPermID] = permissionRecord{ID: rootPermID, Code: "system.manage", Name: "System Manage", CreatedAt: now, UpdatedAt: now}
		p.permissions[unassignedPermID] = permissionRecord{ID: unassignedPermID, Code: "users.read", Name: "View Users", Description: "permission intentionally not assigned to root", CreatedAt: now, UpdatedAt: now}
		p.roles[supportRoleID] = roleRecord{ID: supportRoleID, Name: "Support", ParentID: rootRoleID, Status: "enabled", Description: "bootstrap child role", CreatedAt: now, UpdatedAt: now}
		p.roles[disabledRoleID] = roleRecord{ID: disabledRoleID, Name: "Disabled Role", Status: "disabled", Description: "bootstrap disabled role", CreatedAt: now, UpdatedAt: now}
		p.rolePerms[rootRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[supportRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[disabledRoleID] = map[string]bool{rootPermID: true}
	}
}
