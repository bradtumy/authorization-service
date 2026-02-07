package oauth

import "time"

// TokenRequest represents an OAuth token request.
type TokenRequest struct {
	GrantType    string
	ClientID     string
	Scopes       []string
	TenantID     string
	Audience     string
	Subject      string
	RequestedTTL time.Duration
}

// TokenResponse is a minimal OAuth token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// ClientStore validates client credentials.
type ClientStore interface {
	Validate(clientID, clientSecret string) bool
}
