package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/bradtumy/authorization-service/pkg/oidc"
)

// JWTMiddleware validates access tokens and stores claims in the request context.
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		claims, err := oidc.ValidateToken(r.Context(), token)
		if err != nil {
			if errors.Is(err, oidc.ErrMissingTenant) {
				http.Error(w, "Missing tenant", http.StatusForbidden)
			} else {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
			}
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, "claims", claims)
		if sub, ok := claims["sub"].(string); ok {
			ctx = context.WithValue(ctx, "subject", sub)
		}
		if tenant, ok := claims[oidc.TenantClaim()].(string); ok {
			ctx = context.WithValue(ctx, "tenant", tenant)
		}
		if email, ok := claims["email"].(string); ok {
			ctx = context.WithValue(ctx, "email", email)
		}
		if roles, ok := claims["roles"]; ok {
			ctx = context.WithValue(ctx, "roles", roles)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
