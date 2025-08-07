package authz

import (
	"context"

	"github.com/bradtumy/authorization-service/internal/identity"
	"github.com/bradtumy/authorization-service/internal/policy"
)

// Authorizer checks permissions for principals.
type Authorizer interface {
	// IsAllowed returns true if the principal has the permission on the resource.
	// Default deny: absence of matching permission yields false with nil error.
	IsAllowed(ctx context.Context, p identity.Principal, perm policy.Permission, resource map[string]string) (bool, error)
}
