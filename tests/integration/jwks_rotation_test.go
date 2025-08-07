package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	api "github.com/bradtumy/authorization-service/api"
	"github.com/bradtumy/authorization-service/pkg/identity/local"
	"github.com/bradtumy/authorization-service/pkg/oidc"
	"github.com/bradtumy/authorization-service/pkg/user"
	jwt "github.com/golang-jwt/jwt/v4"
	jose "gopkg.in/go-jose/go-jose.v2"
)

func TestJWKSRotation(t *testing.T) {
	t.Skip("JWKS rotation not implemented in go-oidc validator")
	oldPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	newPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	oldKid := "oldkid"
	newKid := "newkid"
	oldJWK := jose.JSONWebKey{Key: &oldPriv.PublicKey, KeyID: oldKid, Algorithm: "RS256", Use: "sig"}
	newJWK := jose.JSONWebKey{Key: &newPriv.PublicKey, KeyID: newKid, Algorithm: "RS256", Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{oldJWK}}
	jwksBytes, _ := json.Marshal(jwks)
	var mu sync.RWMutex

	var oidcSrv *httptest.Server
	oidcSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"jwks_uri": oidcSrv.URL + "/keys", "issuer": oidcSrv.URL})
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			mu.RLock()
			w.Write(jwksBytes)
			mu.RUnlock()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer oidcSrv.Close()

	os.Setenv("OIDC_ISSUERS", oidcSrv.URL)
	os.Setenv("OIDC_AUDIENCES", "test-aud")
	os.Setenv("OIDC_TENANT_CLAIM", "tenantID")
	os.Setenv("OIDC_JWKS_REFRESH_INTERVAL", "500ms")
	oidc.LoadConfig(context.Background())

	idp := local.New(false)
	user.SetProvider(idp)
	router := api.SetupRouter(idp)
	srv := httptest.NewServer(router)
	defer srv.Close()

	makeToken := func(priv *rsa.PrivateKey, kid string) string {
		claims := jwt.MapClaims{
			"iss":      oidcSrv.URL,
			"sub":      "tester",
			"aud":      "test-aud",
			"exp":      time.Now().Add(time.Hour).Unix(),
			"tenantID": "t",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		str, err := token.SignedString(priv)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return str
	}

	call := func(tok string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		return resp
	}

	oldTok := makeToken(oldPriv, oldKid)
	resp := call(oldTok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}
	resp.Body.Close()

	mu.Lock()
	jwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{newJWK}}
	jwksBytes, _ = json.Marshal(jwks)
	mu.Unlock()

	time.Sleep(time.Second)

	resp = call(oldTok)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d", resp.StatusCode)
	}
	resp.Body.Close()

	newTok := makeToken(newPriv, newKid)
	resp = call(newTok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
