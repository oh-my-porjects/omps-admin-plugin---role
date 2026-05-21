package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func roleToResponse(role roleRecord, parentName string) roleResponse {
	resp := roleResponse{
		RoleID:      role.ID,
		Name:        role.Name,
		ParentName:  parentName,
		Status:      role.Status,
		Description: role.Description,
		CreatedAt:   formatTime(role.CreatedAt),
		UpdatedAt:   formatTime(role.UpdatedAt),
		DeletedAt:   formatTime(role.DeletedAt),
		Permissions: []permissionResponse{},
	}
	if role.ParentID != "" {
		parentID := role.ParentID
		resp.ParentID = &parentID
		resp.ParentRoleID = parentID
	}
	return resp
}

func permissionToResponse(perm permissionRecord) permissionResponse {
	return permissionResponse{
		PermissionID: perm.ID,
		Code:         perm.Code,
		Name:         perm.Name,
		Description:  perm.Description,
		CreatedAt:    formatTime(perm.CreatedAt),
	}
}

func validName(s string) bool {
	n := runeLen(s)
	return n >= 2 && n <= 30
}

func runeLen(s string) int {
	return len([]rune(s))
}

func validStatus(s string) bool {
	return s == "enabled" || s == "disabled"
}

func validUUID(s string) bool {
	return uuidRE.MatchString(s)
}

func protectedRole(role roleRecord) bool {
	switch role.ID {
	case rootRoleID, supportRoleID, disabledRoleID:
		return true
	default:
		return false
	}
}

func validPermissionCode(s string) bool {
	return permissionCodeRE.MatchString(s)
}

func parsePage(pageRaw, sizeRaw string) (int, int, bool) {
	page, err1 := strconv.Atoi(strings.TrimSpace(pageRaw))
	size, err2 := strconv.Atoi(strings.TrimSpace(sizeRaw))
	if err1 != nil || err2 != nil || page < 1 || size < 1 || size > 100 {
		return 0, 0, false
	}
	return page, size, true
}

func pageBounds(total, page, size int) (int, int) {
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return start, end
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	return json.NewDecoder(r.Body).Decode(dst)
}

func newUUIDLikeID() string {
	n := time.Now().UnixNano()
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", n&0xffffffffffff)
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
