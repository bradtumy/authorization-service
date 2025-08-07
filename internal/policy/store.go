package policy

import (
	"context"
	"errors"
)

// Permission represents an allowed action.
type Permission string

// PolicyStore provides permission lookups for roles within a tenant.
type PolicyStore interface {
	// RolePermissions returns permissions for the given tenant and role.
	// It returns ErrNotFound if the tenant or role does not exist.
	RolePermissions(ctx context.Context, tenant, role string) ([]Permission, error)
}

// ErrNotFound is returned when a tenant or role does not exist.
var ErrNotFound = errors.New("policy not found")
