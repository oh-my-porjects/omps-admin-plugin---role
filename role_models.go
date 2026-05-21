package main

import (
	"regexp"
	"time"
)

type roleRecord struct {
	ID          string    `json:"role_id"`
	Name        string    `json:"name"`
	ParentID    string    `json:"parent_id,omitempty"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	DeletedAt   time.Time `json:"deleted_at,omitempty"`
}

type permissionRecord struct {
	ID          string    `json:"permission_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type roleResponse struct {
	RoleID        string               `json:"role_id"`
	Name          string               `json:"name"`
	ParentID      *string              `json:"parent_id"`
	ParentRoleID  string               `json:"parent_role_id"`
	ParentName    string               `json:"parent_name"`
	Status        string               `json:"status"`
	Description   string               `json:"description"`
	CreatedAt     string               `json:"created_at,omitempty"`
	UpdatedAt     string               `json:"updated_at,omitempty"`
	DeletedAt     string               `json:"deleted_at,omitempty"`
	Permissions   []permissionResponse `json:"permissions"`
	PermissionIDs []string             `json:"permission_ids,omitempty"`
}

type roleTreeNode struct {
	RoleID        string         `json:"role_id"`
	Name          string         `json:"name"`
	ParentID      string         `json:"parent_id"`
	ParentRoleID  string         `json:"parent_role_id"`
	ParentName    string         `json:"parent_name"`
	Status        string         `json:"status"`
	Description   string         `json:"description"`
	HasChildren   bool           `json:"has_children"`
	ChildrenCount int            `json:"children_count"`
	Children      []roleTreeNode `json:"children"`
}

type permissionResponse struct {
	PermissionID string `json:"permission_id"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	CreatedAt    string `json:"created_at,omitempty"`
}

const (
	rootRoleID       = "00000000-0000-0000-0000-000000000001"
	rootPermID       = "00000000-0000-0000-0000-000000000002"
	supportRoleID    = "00000000-0000-0000-0000-000000000003"
	unassignedPermID = "00000000-0000-0000-0000-000000000004"
	disabledRoleID   = "00000000-0000-0000-0000-000000000005"
)

var (
	uuidRE           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	recordIDRE       = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	permissionCodeRE = regexp.MustCompile(`^[a-z0-9._-]{3,80}$`)
)
