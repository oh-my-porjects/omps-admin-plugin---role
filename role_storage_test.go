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
		mock.ExpectQuery(regexp.QuoteMeta("SELECT id::text")).
			WithArgs(seed.Name).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_roles (id, name, status, description)")).
			WithArgs(seed.ID, seed.Name, seed.Status, seed.Description).
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
