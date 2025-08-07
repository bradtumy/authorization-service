package identity

import "context"

// User represents a system user scoped to a tenant.
type User struct {
	Username string   `json:"username" yaml:"username"`
	Roles    []string `json:"roles" yaml:"roles"`
	TenantID string   `json:"tenantID" yaml:"-"`
}

// Provider abstracts user/identity management operations.
type Provider interface {
	Get(ctx context.Context, tenantID, subject string) (User, error)
	List(ctx context.Context, tenantID string) ([]User, error)
	Create(ctx context.Context, tenantID, subject string, roles []string) (User, error)
	AssignRoles(ctx context.Context, tenantID, subject string, roles []string) error
	Delete(ctx context.Context, tenantID, subject string) error
	HasRole(ctx context.Context, tenantID, subject string, roles ...string) bool
}
