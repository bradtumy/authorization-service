package user

import (
	"context"
	"errors"

	"github.com/bradtumy/authorization-service/pkg/identity"
)

// User represents a system user. It is an alias of identity.User for compatibility.
type User = identity.User

var provider identity.Provider

// SetProvider configures the global identity provider used by this wrapper package.
func SetProvider(p identity.Provider) {
	provider = p
}

// Create adds a new user under a tenant.
func Create(tenantID, username string, roles []string) (User, error) {
	if provider == nil {
		return User{}, errors.New("identity provider not configured")
	}
	return provider.Create(context.Background(), tenantID, username, roles)
}

// AssignRoles sets roles for an existing user.
func AssignRoles(tenantID, username string, roles []string) error {
	if provider == nil {
		return errors.New("identity provider not configured")
	}
	return provider.AssignRoles(context.Background(), tenantID, username, roles)
}

// Delete removes a user from the tenant.
func Delete(tenantID, username string) error {
	if provider == nil {
		return errors.New("identity provider not configured")
	}
	return provider.Delete(context.Background(), tenantID, username)
}

// List returns all users for a tenant.
func List(tenantID string) []User {
	if provider == nil {
		return nil
	}
	list, _ := provider.List(context.Background(), tenantID)
	return list
}

// Get returns a user by username.
func Get(tenantID, username string) (User, error) {
	if provider == nil {
		return User{}, errors.New("identity provider not configured")
	}
	return provider.Get(context.Background(), tenantID, username)
}

// HasRole checks if a user has any of the provided roles.
func HasRole(tenantID, username string, roles ...string) bool {
	if provider == nil {
		return false
	}
	return provider.HasRole(context.Background(), tenantID, username, roles...)
}

// Reset clears all users if the provider supports it (used in tests).
func Reset() {
	if r, ok := provider.(interface{ Reset() }); ok {
		r.Reset()
	}
}
