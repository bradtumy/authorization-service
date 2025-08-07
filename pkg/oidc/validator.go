package oidc

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"

	oidclib "github.com/coreos/go-oidc"
	jwt "github.com/golang-jwt/jwt/v4"
)

// Provider holds verifier for an issuer/audience pair.
type Provider struct {
	Issuer   string
	Audience string
	Verifier *oidclib.IDTokenVerifier
}

var (
	providers   []Provider
	tenantClaim string = "tenantID"
	mu          sync.RWMutex
)

// ErrMissingTenant indicates that the required tenant claim is missing.
var ErrMissingTenant = errors.New("missing tenant claim")

// LoadConfig initializes OIDC providers from environment variables.
// OIDC_ISSUERS and OIDC_AUDIENCES are comma separated lists.
// OIDC_TENANT_CLAIM configures the required tenant claim (default: tenantID).
func LoadConfig(ctx context.Context) {
	mu.Lock()
	defer mu.Unlock()
	providers = nil
	if tc := os.Getenv("OIDC_TENANT_CLAIM"); tc != "" {
		tenantClaim = tc
	}
	issuers := strings.Split(os.Getenv("OIDC_ISSUERS"), ",")
	audiences := strings.Split(os.Getenv("OIDC_AUDIENCES"), ",")
	for i := range issuers {
		iss := strings.TrimSpace(issuers[i])
		if iss == "" {
			continue
		}
		aud := ""
		if i < len(audiences) {
			aud = strings.TrimSpace(audiences[i])
		}
		provider, err := oidclib.NewProvider(ctx, iss)
		if err != nil {
			continue
		}
		cfg := &oidclib.Config{ClientID: aud}
		if aud == "" {
			cfg.SkipClientIDCheck = true
		}
		ver := provider.Verifier(cfg)
		providers = append(providers, Provider{Issuer: iss, Audience: aud, Verifier: ver})
	}
}

// TenantClaim returns the configured tenant claim name.
func TenantClaim() string { return tenantClaim }

// ValidateToken verifies the token and returns its claims.
// If no providers are configured, it only parses the token without verification.
func ValidateToken(ctx context.Context, tokenString string) (map[string]interface{}, error) {
	mu.RLock()
	if len(providers) == 0 {
		mu.RUnlock()
		LoadConfig(ctx)
		mu.RLock()
	}
	provs := providers
	tc := tenantClaim
	mu.RUnlock()

	// Parse unverified to select provider and capture claims when no providers configured.
	unverified := jwt.MapClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(tokenString, unverified)
	if err != nil {
		return nil, err
	}

	if len(provs) == 0 {
		if _, ok := unverified["sub"].(string); !ok {
			return nil, errors.New("missing sub")
		}
		if _, ok := unverified[tc]; !ok {
			return nil, ErrMissingTenant
		}
		return map[string]interface{}(unverified), nil
	}

	iss, _ := unverified["iss"].(string)
	audClaim := unverified["aud"]
	var prov *Provider
	for i := range provs {
		if provs[i].Issuer == iss && audienceMatch(audClaim, provs[i].Audience) {
			prov = &provs[i]
			break
		}
	}
	if prov == nil {
		return nil, errors.New("unknown issuer")
	}
	idToken, err := prov.Verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	claims := map[string]interface{}{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return nil, errors.New("missing sub")
	}
	if _, ok := claims[tc]; !ok {
		return nil, ErrMissingTenant
	}
	return claims, nil
}

func audienceMatch(claim interface{}, aud string) bool {
	if aud == "" {
		return true
	}
	switch v := claim.(type) {
	case string:
		return v == aud
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == aud {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == aud {
				return true
			}
		}
	}
	return false
}
