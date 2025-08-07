package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/bradtumy/authorization-service/internal/identity"
)

// JWTAuth validates a bearer token using the provided IdentityProvider. On
// successful verification the resulting principal is stored on the request
// context and the next handler is invoked. Failure results in 401 Unauthorized.
func JWTAuth(idp identity.IdentityProvider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		raw := strings.TrimPrefix(auth, "Bearer ")
		ti, err := idp.Verify(r.Context(), raw)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		principal, err := idp.PrincipalFromClaims(r.Context(), ti)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, &principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
