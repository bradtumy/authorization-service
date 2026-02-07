package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/bradtumy/authorization-service/pkg/identity/local"
	"github.com/bradtumy/authorization-service/pkg/user"
	"github.com/golang-jwt/jwt/v4"
)

func TestTokenPolicyHook(t *testing.T) {
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"allow":           true,
			"scopes_to_issue": []string{"hooked"},
			"claims_to_embed": map[string]interface{}{"act": map[string]interface{}{"sub": "agent"}},
		})
	}))
	defer pdp.Close()

	os.Setenv("TOKEN_SIGNING_KEY", "test-secret")
	os.Setenv("CLIENT_ID", "client")
	os.Setenv("CLIENT_SECRET", "secret")
	os.Setenv("POLICY_HOOKS_ENABLED", "true")
	os.Setenv("POLICY_HOOKS_ENDPOINT", pdp.URL)
	os.Setenv("POLICY_HOOKS_ALLOWED_HOSTS", "")
	tokenService = newTokenService()

	idp := local.New(false)
	user.SetProvider(idp)
	router := SetupRouter(idp)
	srv := httptest.NewServer(router)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("tenant_id", "acme")
	form.Set("scope", "ignored")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client", "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims := jwt.MapClaims{}
	_, _, err = new(jwt.Parser).ParseUnverified(out.AccessToken, claims)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if scope, ok := claims["scope"].([]interface{}); !ok || len(scope) != 1 || scope[0] != "hooked" {
		t.Fatalf("expected hooked scope, got %v", claims["scope"])
	}
	if _, ok := claims["act"].(map[string]interface{}); !ok {
		t.Fatalf("expected act claim")
	}
}
