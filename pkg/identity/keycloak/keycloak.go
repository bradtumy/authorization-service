package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/bradtumy/authorization-service/pkg/identity"
)

// Provider implements identity.Provider backed by Keycloak's Admin REST API.
type Provider struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	mu    sync.Mutex
	token string
}

// New creates a Provider using explicit configuration values.
func New(baseURL, clientID, clientSecret string) *Provider {
	return &Provider{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   http.DefaultClient,
	}
}

// NewFromEnv constructs a Provider using environment variables.
//
// Required variables:
//
//	KEYCLOAK_BASE_URL - base URL of the Keycloak server
//	KEYCLOAK_CLIENT_ID - client ID for admin access
//	KEYCLOAK_CLIENT_SECRET - client secret for admin access
func NewFromEnv() *Provider {
	return New(
		os.Getenv("KEYCLOAK_BASE_URL"),
		os.Getenv("KEYCLOAK_CLIENT_ID"),
		os.Getenv("KEYCLOAK_CLIENT_SECRET"),
	)
}

func (p *Provider) getToken(ctx context.Context, realm string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" {
		return p.token, nil
	}
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	u := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", p.baseURL, realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("no access token")
	}
	p.token = out.AccessToken
	return p.token, nil
}

func (p *Provider) request(ctx context.Context, realm, method, path string, body interface{}) (*http.Response, error) {
	token, err := p.getToken(ctx, realm)
	if err != nil {
		return nil, err
	}
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		buf = bytes.NewBuffer(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("%s%s", p.baseURL, path), buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return p.httpClient.Do(req)
}

// Create adds a new user under a tenant.
func (p *Provider) Create(ctx context.Context, tenantID, username string, roles []string) (identity.User, error) {
	payload := map[string]interface{}{
		"username": username,
		"roles":    roles,
	}
	resp, err := p.request(ctx, tenantID, http.MethodPost, fmt.Sprintf("/admin/realms/%s/users", tenantID), payload)
	if err != nil {
		return identity.User{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return identity.User{}, fmt.Errorf("create user: %s", resp.Status)
	}
	var u identity.User
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return identity.User{}, err
	}
	u.TenantID = tenantID
	return u, nil
}

// AssignRoles sets roles for an existing user.
func (p *Provider) AssignRoles(ctx context.Context, tenantID, username string, roles []string) error {
	resp, err := p.request(ctx, tenantID, http.MethodPost, fmt.Sprintf("/admin/realms/%s/users/%s/roles", tenantID, username), roles)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("assign roles: %s", resp.Status)
	}
	return nil
}

// Delete removes a user.
func (p *Provider) Delete(ctx context.Context, tenantID, username string) error {
	resp, err := p.request(ctx, tenantID, http.MethodDelete, fmt.Sprintf("/admin/realms/%s/users/%s", tenantID, username), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("delete user: %s", resp.Status)
	}
	return nil
}

// List returns all users for a tenant.
func (p *Provider) List(ctx context.Context, tenantID string) ([]identity.User, error) {
	resp, err := p.request(ctx, tenantID, http.MethodGet, fmt.Sprintf("/admin/realms/%s/users", tenantID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list users: %s", resp.Status)
	}
	var users []identity.User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, err
	}
	for i := range users {
		users[i].TenantID = tenantID
	}
	return users, nil
}

// Get returns a user by username.
func (p *Provider) Get(ctx context.Context, tenantID, username string) (identity.User, error) {
	resp, err := p.request(ctx, tenantID, http.MethodGet, fmt.Sprintf("/admin/realms/%s/users/%s", tenantID, username), nil)
	if err != nil {
		return identity.User{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return identity.User{}, fmt.Errorf("get user: %s", resp.Status)
	}
	var u identity.User
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return identity.User{}, err
	}
	u.TenantID = tenantID
	return u, nil
}

// HasRole checks if the user has any of the provided roles.
func (p *Provider) HasRole(ctx context.Context, tenantID, username string, roles ...string) bool {
	u, err := p.Get(ctx, tenantID, username)
	if err != nil {
		return false
	}
	set := make(map[string]struct{}, len(u.Roles))
	for _, r := range u.Roles {
		set[r] = struct{}{}
	}
	for _, r := range roles {
		if _, ok := set[r]; ok {
			return true
		}
	}
	return false
}
