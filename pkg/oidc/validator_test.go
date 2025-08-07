package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	jose "gopkg.in/go-jose/go-jose.v2"
)

func TestValidateToken(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	kid := "testkid"
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	jwksBytes, _ := json.Marshal(jwks)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"jwks_uri": server.URL + "/keys", "issuer": server.URL})
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	os.Setenv("OIDC_ISSUERS", server.URL)
	os.Setenv("OIDC_AUDIENCES", "test-aud")
	os.Setenv("OIDC_TENANT_CLAIM", "tenantID")
	LoadConfig(context.Background())

	makeToken := func(iss, aud string, exp time.Time, claims map[string]interface{}) string {
		base := jwt.MapClaims{
			"iss": iss,
			"aud": aud,
			"exp": exp.Unix(),
		}
		for k, v := range claims {
			base[k] = v
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
		token.Header["kid"] = kid
		str, err := token.SignedString(priv)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return str
	}

	ctx := context.Background()

	t.Run("valid", func(t *testing.T) {
		tok := makeToken(server.URL, "test-aud", time.Now().Add(time.Hour), map[string]interface{}{"sub": "u", "tenantID": "t"})
		claims, err := ValidateToken(ctx, tok)
		if err != nil {
			t.Fatalf("valid: %v", err)
		}
		if claims["sub"].(string) != "u" {
			t.Fatalf("unexpected sub")
		}
	})

	t.Run("expired", func(t *testing.T) {
		tok := makeToken(server.URL, "test-aud", time.Now().Add(-time.Hour), map[string]interface{}{"sub": "u", "tenantID": "t"})
		if _, err := ValidateToken(ctx, tok); err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		tok := makeToken(server.URL, "other", time.Now().Add(time.Hour), map[string]interface{}{"sub": "u", "tenantID": "t"})
		if _, err := ValidateToken(ctx, tok); err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("missing tenant", func(t *testing.T) {
		tok := makeToken(server.URL, "test-aud", time.Now().Add(time.Hour), map[string]interface{}{"sub": "u"})
		_, err := ValidateToken(ctx, tok)
		if !errors.Is(err, ErrMissingTenant) {
			t.Fatalf("expected missing tenant error")
		}
	})

	t.Run("unknown issuer", func(t *testing.T) {
		tok := makeToken("http://other", "test-aud", time.Now().Add(time.Hour), map[string]interface{}{"sub": "u", "tenantID": "t"})
		if _, err := ValidateToken(ctx, tok); err == nil {
			t.Fatalf("expected error")
		}
	})
}
