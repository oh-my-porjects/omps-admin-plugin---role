package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type builtInRoleSeed struct {
	ID          string
	LegacyName  string
	Name        string
	ParentName  string
	Status      string
	Description string
}

var builtInRoleSeeds = []builtInRoleSeed{
	{ID: rootRoleID, LegacyName: "Root", Name: "超级管理员", Status: "enabled", Description: "系统预设角色，拥有最高权限"},
	{ID: supportRoleID, LegacyName: "Support", Name: "开发者", ParentName: "超级管理员", Status: "enabled", Description: "系统预设角色，开发人员使用"},
	{ID: disabledRoleID, LegacyName: "Disabled Role", Name: "运营", ParentName: "开发者", Status: "enabled", Description: "系统预设角色，运营人员使用"},
}

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
	roleIDs := make([]string, 0, len(builtInRoleSeeds))
	for _, seed := range builtInRoleSeeds {
		roleID, err := p.ensureBuiltInRole(ctx, seed)
		if err != nil {
			return err
		}
		roleIDs = append(roleIDs, roleID)
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_permissions (id, code, name, description)
		VALUES ($1, 'system.manage', 'System Manage', 'root management permission')
		ON CONFLICT (code) DO UPDATE
		SET name=EXCLUDED.name, description=EXCLUDED.description, updated_at=now()`, rootPermID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_permissions (id, code, name, description)
		VALUES ($1, 'users.read', 'View Users', 'permission intentionally not assigned to root')
		ON CONFLICT (code) DO UPDATE
		SET name=EXCLUDED.name, description=EXCLUDED.description, updated_at=now()`, unassignedPermID); err != nil {
		return err
	}
	var rootPermissionID string
	if err := p.db.QueryRowContext(ctx, `
		SELECT id::text
		FROM role_permissions
		WHERE code='system.manage'`).Scan(&rootPermissionID); err != nil {
		return err
	}
	for _, roleID := range roleIDs {
		if _, err := p.db.ExecContext(ctx, `
			INSERT INTO role_role_permissions (role_id, permission_id)
			VALUES ($1, $2)
			ON CONFLICT (role_id, permission_id) DO NOTHING`, roleID, rootPermissionID); err != nil {
			return err
		}
	}
	return nil
}

func (p *RolePlugin) ensureBuiltInRole(ctx context.Context, seed builtInRoleSeed) (string, error) {
	parentID, err := p.builtInParentID(ctx, seed.ParentName)
	if err != nil {
		return "", err
	}
	var existingID string
	err = p.db.QueryRowContext(ctx, `
		SELECT id::text
		FROM role_roles
		WHERE name=$1
		LIMIT 1`, seed.Name).Scan(&existingID)
	if err == nil {
		if existingID != seed.ID {
			if err := p.ensureBuiltInRoleTarget(ctx, seed, parentID); err != nil {
				return "", err
			}
			if err := p.migrateBuiltInRoleID(ctx, existingID, seed.ID); err != nil {
				return "", err
			}
			if err := p.upsertBuiltInRole(ctx, seed, parentID); err != nil {
				return "", err
			}
			return seed.ID, nil
		}
		if err := p.upsertBuiltInRole(ctx, seed, parentID); err != nil {
			return "", err
		}
		return seed.ID, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	if err := p.upsertBuiltInRole(ctx, seed, parentID); err != nil {
		return "", err
	}
	return seed.ID, nil
}

func (p *RolePlugin) upsertBuiltInRole(ctx context.Context, seed builtInRoleSeed, parentID sql.NullString) error {
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_roles (id, name, parent_id, status, description)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE
		SET name=EXCLUDED.name,
			parent_id=EXCLUDED.parent_id,
			status=EXCLUDED.status,
			description=EXCLUDED.description,
			deleted_at=NULL,
			updated_at=now()`, seed.ID, seed.Name, parentID, seed.Status, seed.Description); err != nil {
		return err
	}
	return nil
}

func (p *RolePlugin) ensureBuiltInRoleTarget(ctx context.Context, seed builtInRoleSeed, parentID sql.NullString) error {
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO role_roles (id, name, parent_id, status, description)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE
		SET parent_id=EXCLUDED.parent_id,
			status=EXCLUDED.status,
			description=EXCLUDED.description,
			deleted_at=NULL,
			updated_at=now()`, seed.ID, builtInRoleMigrationName(seed.ID), parentID, seed.Status, seed.Description); err != nil {
		return err
	}
	return nil
}

func builtInRoleMigrationName(roleID string) string {
	return "__omps_builtin_role_migrating__" + roleID
}

func (p *RolePlugin) migrateBuiltInRoleID(ctx context.Context, fromID string, toID string) error {
	if fromID == "" || fromID == toID {
		return nil
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := copyRolePermissions(ctx, tx, fromID, toID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM role_role_permissions
		WHERE role_id=$1`, fromID); err != nil {
		return err
	}
	if exists, err := tableExists(ctx, tx, "account_role_bindings"); err != nil {
		return err
	} else if exists {
		if _, err := tx.ExecContext(ctx, `
			UPDATE account_role_bindings
			SET role_id=$2
			WHERE role_id=$1`, fromID, toID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE role_roles
		SET parent_id=$2,
			updated_at=now()
		WHERE parent_id=$1`, fromID, toID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM role_roles
		WHERE id=$1`, fromID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func copyRolePermissions(ctx context.Context, tx *sql.Tx, fromID string, toID string) error {
	columnType, err := tableColumnDataType(ctx, tx, "role_role_permissions", "id")
	if err != nil {
		return err
	}
	if columnType == "uuid" {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO role_role_permissions (role_id, permission_id, created_at)
			SELECT $2, permission_id, MIN(created_at)
			FROM role_role_permissions
			WHERE role_id=$1
			GROUP BY permission_id
			ON CONFLICT (role_id, permission_id) DO NOTHING`, fromID, toID)
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO role_role_permissions (id, role_id, permission_id, created_at)
		SELECT gen_random_uuid()::text, $2, permission_id, MIN(created_at)
		FROM role_role_permissions
		WHERE role_id=$1
		GROUP BY permission_id
		ON CONFLICT (role_id, permission_id) DO NOTHING`, fromID, toID)
	return err
}

func tableExists(ctx context.Context, q queryRower, tableName string) (bool, error) {
	var exists bool
	err := q.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+tableName).Scan(&exists)
	return exists, err
}

func tableColumnDataType(ctx context.Context, q queryRower, tableName string, columnName string) (string, error) {
	var dataType string
	err := q.QueryRowContext(ctx, `
		SELECT data_type
		FROM information_schema.columns
		WHERE table_schema='public'
			AND table_name=$1
			AND column_name=$2`, tableName, columnName).Scan(&dataType)
	if err != nil {
		return "", fmt.Errorf("inspect %s.%s data type: %w", tableName, columnName, err)
	}
	return dataType, nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (p *RolePlugin) builtInParentID(ctx context.Context, parentName string) (sql.NullString, error) {
	if parentName == "" {
		return sql.NullString{}, nil
	}
	var parentID string
	err := p.db.QueryRowContext(ctx, `
		SELECT id::text
		FROM role_roles
		WHERE name=$1 AND deleted_at IS NULL
		LIMIT 1`, parentName).Scan(&parentID)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: parentID, Valid: true}, nil
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
		p.roles[rootRoleID] = roleRecord{ID: rootRoleID, Name: "超级管理员", Status: "enabled", Description: "系统预设角色，拥有最高权限", CreatedAt: now, UpdatedAt: now}
		p.permissions[rootPermID] = permissionRecord{ID: rootPermID, Code: "system.manage", Name: "System Manage", CreatedAt: now, UpdatedAt: now}
		p.permissions[unassignedPermID] = permissionRecord{ID: unassignedPermID, Code: "users.read", Name: "View Users", Description: "permission intentionally not assigned to root", CreatedAt: now, UpdatedAt: now}
		p.roles[supportRoleID] = roleRecord{ID: supportRoleID, Name: "开发者", ParentID: rootRoleID, Status: "enabled", Description: "系统预设角色，开发人员使用", CreatedAt: now, UpdatedAt: now}
		p.roles[disabledRoleID] = roleRecord{ID: disabledRoleID, Name: "运营", ParentID: supportRoleID, Status: "enabled", Description: "系统预设角色，运营人员使用", CreatedAt: now, UpdatedAt: now}
		p.rolePerms[rootRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[supportRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[disabledRoleID] = map[string]bool{rootPermID: true}
	}
}
