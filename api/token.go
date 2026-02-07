package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bradtumy/authorization-service/internal/oauth"
	"github.com/bradtumy/authorization-service/internal/policyhook"
)

func newTokenService() *oauth.TokenService {
	issuer, err := oauth.NewIssuerFromEnv()
	if err != nil {
		return nil
	}
	failClosed := true
	if v := strings.ToLower(os.Getenv("POLICY_HOOKS_FAIL_CLOSED")); v != "" {
		failClosed = v != "false"
	}
	var pre policyhook.PreIssueHook = policyhook.NoopHook{}
	var post policyhook.PostIssueHook = policyhook.NoopHook{}
	if strings.ToLower(os.Getenv("POLICY_HOOKS_ENABLED")) == "true" {
		allowedHosts := strings.Split(os.Getenv("POLICY_HOOKS_ALLOWED_HOSTS"), ",")
		timeout := 3 * time.Second
		if raw := os.Getenv("POLICY_HOOKS_TIMEOUT"); raw != "" {
			if parsed, err := time.ParseDuration(raw); err == nil {
				timeout = parsed
			}
		}
		client := policyhook.HTTPClient{
			Endpoint:     os.Getenv("POLICY_HOOKS_ENDPOINT"),
			Timeout:      timeout,
			AllowedHosts: filterEmpty(allowedHosts),
		}
		pre = client
		post = client
	}
	service := oauth.TokenService{
		Clients:    oauth.EnvClientStore{},
		Issuer:     issuer,
		PreHook:    pre,
		PostHook:   post,
		FailClosed: failClosed,
	}
	return &service
}

func Token(w http.ResponseWriter, r *http.Request) {
	if tokenService == nil {
		http.Error(w, "token service not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, err := clientCredentials(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if !tokenService.Clients.Validate(clientID, clientSecret) {
		http.Error(w, "invalid client", http.StatusUnauthorized)
		return
	}
	scope := strings.Fields(r.FormValue("scope"))
	tenantID := r.FormValue("tenant_id")
	if tenantID == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}
	req := oauth.TokenRequest{
		GrantType: "client_credentials",
		ClientID:  clientID,
		Scopes:    scope,
		TenantID:  tenantID,
		Audience:  r.FormValue("audience"),
		Subject:   clientID,
	}
	resp, err := tokenService.IssueClientCredentials(r.Context(), req)
	if err != nil {
		http.Error(w, "token issuance failed", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func clientCredentials(r *http.Request) (string, string, error) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret, nil
	}
	id := r.FormValue("client_id")
	secret := r.FormValue("client_secret")
	if id == "" || secret == "" {
		return "", "", errors.New("missing client credentials")
	}
	return id, secret, nil
}

func filterEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(v))
	}
	return out
}
