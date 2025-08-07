package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bradtumy/authorization-service/internal/identity"
)

type mockIDP struct {
	verify    func(ctx context.Context, raw string) (identity.TokenInfo, error)
	principal func(ctx context.Context, ti identity.TokenInfo) (identity.Principal, error)
}

func (m *mockIDP) Verify(ctx context.Context, raw string) (identity.TokenInfo, error) {
	return m.verify(ctx, raw)
}

func (m *mockIDP) PrincipalFromClaims(ctx context.Context, ti identity.TokenInfo) (identity.Principal, error) {
	return m.principal(ctx, ti)
}

func TestJWTAuth(t *testing.T) {
	idp := &mockIDP{
		verify: func(ctx context.Context, raw string) (identity.TokenInfo, error) {
			if raw != "good" {
				return identity.TokenInfo{}, identity.ErrInvalidToken
			}
			return identity.TokenInfo{Raw: raw, Claims: map[string]any{}}, nil
		},
		principal: func(ctx context.Context, ti identity.TokenInfo) (identity.Principal, error) {
			return identity.Principal{Subject: "user"}, nil
		},
	}

	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok || p.Subject != "user" {
			t.Fatalf("principal missing from context")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := func() http.Handler { return JWTAuth(idp, final) }

	t.Run("missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 got %d", rr.Code)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer bad")
		rr := httptest.NewRecorder()
		handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 got %d", rr.Code)
		}
	})

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer good")
		rr := httptest.NewRecorder()
		handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 got %d", rr.Code)
		}
	})
}
