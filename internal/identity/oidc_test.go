package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	jose "gopkg.in/go-jose/go-jose.v2"

	"github.com/bradtumy/authorization-service/internal/config"
)

func genKey(t *testing.T, kid string) (*rsa.PrivateKey, jose.JSONWebKey) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "RS256"}
	return k, jwk
}

func jwksJSON(keys ...jose.JSONWebKey) []byte {
	set := jose.JSONWebKeySet{Keys: keys}
	b, _ := json.Marshal(set)
	return b
}

func tokenString(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func cloneClaims(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func setupProvider(t *testing.T, jwksData *string, issuer, audience string) *OIDCProvider {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(*jwksData))
	}))
	t.Cleanup(srv.Close)

	cfg := config.IdentityConfig{
		Issuer:   issuer,
		JWKSURL:  srv.URL,
		Audience: audience,
		Claims: config.ClaimsConfig{
			Subject:     "sub",
			Username:    "preferred_username",
			Tenant:      "tenant",
			Roles:       []string{"realm_access.roles", "resource_access.authorization-service.roles"},
			StripPrefix: "ROLE_",
		},
	}
	p, err := NewOIDCProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	return p
}

func TestOIDCVerify(t *testing.T) {
	issuer := "https://issuer.example.com"
	audience := "authorization-service"
	key1, jwk1 := genKey(t, "k1")
	jwks := string(jwksJSON(jwk1))
	p := setupProvider(t, &jwks, issuer, audience)

	base := map[string]any{
		"iss":                issuer,
		"aud":                audience,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"nbf":                time.Now().Add(-time.Minute).Unix(),
		"sub":                "alice",
		"preferred_username": "alice",
	}

	tests := []struct {
		name    string
		mod     func(map[string]any)
		wantErr bool
	}{
		{"valid", func(m map[string]any) {}, false},
		{"wrong_iss", func(m map[string]any) { m["iss"] = "other" }, true},
		{"wrong_aud", func(m map[string]any) { m["aud"] = "other" }, true},
		{"expired", func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() }, true},
		{"nbf_future", func(m map[string]any) { m["nbf"] = time.Now().Add(time.Hour).Unix() }, true},
	}

	for _, tc := range tests {
		claims := cloneClaims(base)
		tc.mod(claims)
		tok := tokenString(t, key1, "k1", claims)
		_, err := p.Verify(context.Background(), tok)
		if tc.wantErr && err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
	}
}

func TestOIDCUnknownKidAndRotation(t *testing.T) {
	issuer := "https://issuer.example.com"
	audience := "authorization-service"
	key1, jwk1 := genKey(t, "k1")
	key2, jwk2 := genKey(t, "k2")
	jwks := string(jwksJSON(jwk1))
	p := setupProvider(t, &jwks, issuer, audience)

	claims := map[string]any{
		"iss":                issuer,
		"aud":                audience,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"nbf":                time.Now().Add(-time.Minute).Unix(),
		"sub":                "alice",
		"preferred_username": "alice",
	}

	// token signed with key2 but JWKS only has key1
	tok2 := tokenString(t, key2, "k2", claims)
	if _, err := p.Verify(context.Background(), tok2); err == nil {
		t.Fatalf("expected unknown kid error")
	}

	// rotate JWKS to key2
	jwks = string(jwksJSON(jwk2))
	if err := p.jwks.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := p.Verify(context.Background(), tok2); err != nil {
		t.Fatalf("verify after rotate: %v", err)
	}

	// old token with key1 should now fail
	tok1 := tokenString(t, key1, "k1", claims)
	if _, err := p.Verify(context.Background(), tok1); err == nil {
		t.Fatalf("expected failure for old key")
	}
}

func TestPrincipalFromClaimsRoles(t *testing.T) {
	issuer := "https://issuer.example.com"
	audience := "authorization-service"
	key1, jwk1 := genKey(t, "k1")
	jwks := string(jwksJSON(jwk1))
	p := setupProvider(t, &jwks, issuer, audience)

	claims := map[string]any{
		"iss":                issuer,
		"aud":                audience,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"nbf":                time.Now().Add(-time.Minute).Unix(),
		"sub":                "s1",
		"preferred_username": "bob",
		"tenant":             "t1",
		"realm_access":       map[string]any{"roles": []any{"Admin", "ROLE_user"}},
		"resource_access":    map[string]any{"authorization-service": map[string]any{"roles": []any{"ROLE_ADMIN", "user"}}},
	}

	tok := tokenString(t, key1, "k1", claims)
	ti, err := p.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	princ, err := p.PrincipalFromClaims(context.Background(), ti)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	want := []string{"admin", "user"}
	if len(princ.Roles) != len(want) {
		t.Fatalf("expected %d roles got %v", len(want), princ.Roles)
	}
	for i, r := range want {
		if princ.Roles[i] != r {
			t.Fatalf("role %d = %s want %s", i, princ.Roles[i], r)
		}
	}
}
