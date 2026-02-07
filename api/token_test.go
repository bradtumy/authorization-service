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
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

func TestTokenClientCredentials(t *testing.T) {
	os.Setenv("TOKEN_SIGNING_KEY", "test-secret")
	os.Setenv("CLIENT_ID", "client")
	os.Setenv("CLIENT_SECRET", "secret")
	os.Setenv("POLICY_HOOKS_ENABLED", "false")
	tokenService = newTokenService()

	idp := local.New(false)
	user.SetProvider(idp)
	router := SetupRouter(idp)
	srv := httptest.NewServer(router)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("tenant_id", "acme")
	form.Set("scope", "read write")
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
	var out tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.AccessToken == "" || out.TokenType != "bearer" || out.ExpiresIn == 0 {
		t.Fatalf("unexpected response: %+v", out)
	}
}
