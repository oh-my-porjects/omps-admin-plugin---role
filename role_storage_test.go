package main

import (
	"context"
	"database/sql"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestInitStorageUsesExistingPermissionIDForSeedBindings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	p := &RolePlugin{db: db}
	for i := 0; i < 5; i++ {
		mock.ExpectExec("CREATE|ALTER").
			WillReturnResult(sqlmock.NewResult(0, 0))
	}
	for _, seed := range builtInRoleSeeds {
		if seed.ParentName != "" {
			parentID := rootRoleID
			if seed.ParentName == "开发者" {
				parentID = supportRoleID
			}
			mock.ExpectQuery(regexp.QuoteMeta("SELECT id::text")).
				WithArgs(seed.ParentName).
				WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(parentID))
		}
		mock.ExpectQuery(regexp.QuoteMeta("SELECT id::text")).
			WithArgs(seed.Name).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_roles (id, name, parent_id, status, description)")).
			WithArgs(seed.ID, seed.Name, sqlmock.AnyArg(), seed.Status, seed.Description).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_permissions (id, code, name, description)")).
		WithArgs(rootPermID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_permissions (id, code, name, description)")).
		WithArgs(unassignedPermID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	existingRootPermID := "11111111-1111-1111-1111-111111111111"
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id::text")).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(existingRootPermID))
	for _, roleID := range []string{rootRoleID, supportRoleID, disabledRoleID} {
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_role_permissions (role_id, permission_id)")).
			WithArgs(roleID, existingRootPermID).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}

	if err := p.initStorage(context.Background()); err != nil {
		t.Fatalf("initStorage: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestMigrateBuiltInRoleIDMovesReferencesToFixedID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	p := &RolePlugin{db: db}
	oldRoleID := "legacy-role-id"
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT data_type")).
		WithArgs("role_role_permissions", "id").
		WillReturnRows(sqlmock.NewRows([]string{"data_type"}).AddRow("text"))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_role_permissions (id, role_id, permission_id, created_at)")).
		WithArgs(oldRoleID, rootRoleID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM role_role_permissions")).
		WithArgs(oldRoleID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT to_regclass($1) IS NOT NULL")).
		WithArgs("public.account_role_bindings").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE account_role_bindings")).
		WithArgs(oldRoleID, rootRoleID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE role_roles")).
		WithArgs(oldRoleID, rootRoleID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM role_roles")).
		WithArgs(oldRoleID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := p.migrateBuiltInRoleID(context.Background(), oldRoleID, rootRoleID); err != nil {
		t.Fatalf("migrateBuiltInRoleID: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestEnsureBuiltInRoleMigratesBeforeApplyingBuiltInName(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	p := &RolePlugin{db: db}
	legacyID := "legacy-root-id"
	seed := builtInRoleSeeds[0]
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id::text")).
		WithArgs(seed.Name).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(legacyID))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_roles (id, name, parent_id, status, description)")).
		WithArgs(seed.ID, builtInRoleMigrationName(seed.ID), sqlmock.AnyArg(), seed.Status, seed.Description).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT data_type")).
		WithArgs("role_role_permissions", "id").
		WillReturnRows(sqlmock.NewRows([]string{"data_type"}).AddRow("text"))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_role_permissions (id, role_id, permission_id, created_at)")).
		WithArgs(legacyID, seed.ID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM role_role_permissions")).
		WithArgs(legacyID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT to_regclass($1) IS NOT NULL")).
		WithArgs("public.account_role_bindings").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE role_roles")).
		WithArgs(legacyID, seed.ID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM role_roles")).
		WithArgs(legacyID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_roles (id, name, parent_id, status, description)")).
		WithArgs(seed.ID, seed.Name, sqlmock.AnyArg(), seed.Status, seed.Description).
		WillReturnResult(sqlmock.NewResult(0, 1))

	roleID, err := p.ensureBuiltInRole(context.Background(), seed)
	if err != nil {
		t.Fatalf("ensureBuiltInRole: %v", err)
	}
	if roleID != seed.ID {
		t.Fatalf("role id = %q, want %q", roleID, seed.ID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
