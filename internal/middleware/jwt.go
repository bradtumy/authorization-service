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
		if roles := extractRoles(claims); len(roles) > 0 {
			ctx = context.WithValue(ctx, "roles", roles)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractRoles(claims map[string]interface{}) []string {
	var roles []string
	if rs, ok := claims["roles"]; ok {
		switch v := rs.(type) {
		case []interface{}:
			for _, r := range v {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		case []string:
			roles = append(roles, v...)
		}
	}
	if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
		if rs, ok := ra["roles"].([]interface{}); ok {
			for _, r := range rs {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}
	if resAcc, ok := claims["resource_access"].(map[string]interface{}); ok {
		for _, v := range resAcc {
			if m, ok := v.(map[string]interface{}); ok {
				if rs, ok := m["roles"].([]interface{}); ok {
					for _, r := range rs {
						if s, ok := r.(string); ok {
							roles = append(roles, s)
						}
					}
				}
			}
		}
	}
	return roles
}
