package identity

import "context"

// Principal represents an authenticated entity.
type Principal struct {
	Subject  string
	Username string
	Tenant   string
	Roles    []string
	Issuer   string
	Attrs    map[string]string
}

// TokenInfo holds metadata about a verified token.
type TokenInfo struct {
	Raw    string
	Issuer string
	Aud    string
	Claims map[string]any
}

// IdentityProvider verifies tokens and extracts principals.
type IdentityProvider interface {
	// Verify validates the raw token and returns token information.
	Verify(ctx context.Context, raw string) (TokenInfo, error)
	// PrincipalFromClaims maps token claims to a Principal.
	PrincipalFromClaims(ctx context.Context, ti TokenInfo) (Principal, error)
}

// AuthError represents an authentication/authorization error.
type AuthError struct {
	Code    string
	Message string
}

func (e *AuthError) Error() string { return e.Message }

var (
	ErrInvalidToken = &AuthError{Code: "invalid_token", Message: "token validation failed"}
	ErrClaimMapping = &AuthError{Code: "claim_mapping_error", Message: "required claim missing"}
	ErrKeyNotFound  = &AuthError{Code: "key_not_found", Message: "signing key not found"}
)
