package middleware

import (
	"context"

	"github.com/bradtumy/authorization-service/internal/identity"
)

// principalKey is the context key used to store the authenticated principal.
type principalKey struct{}

// PrincipalFromContext retrieves the authenticated principal from ctx.
// It returns false if no principal is present.
func PrincipalFromContext(ctx context.Context) (*identity.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*identity.Principal)
	return p, ok
}
