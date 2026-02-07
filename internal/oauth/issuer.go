package oauth

import (
	"errors"
	"os"
	"time"

	"github.com/bradtumy/authorization-service/pkg/oidc"
	"github.com/golang-jwt/jwt/v4"
)

// Issuer mints signed JWTs for access tokens.
type Issuer struct {
	SigningKey []byte
	Issuer     string
	Audience   string
	TTL        time.Duration
}

// NewIssuerFromEnv builds an issuer from environment variables.
func NewIssuerFromEnv() (Issuer, error) {
	key := os.Getenv("TOKEN_SIGNING_KEY")
	if key == "" {
		return Issuer{}, errors.New("TOKEN_SIGNING_KEY is required")
	}
	iss := os.Getenv("TOKEN_ISSUER")
	if iss == "" {
		iss = "authorization-service"
	}
	aud := os.Getenv("TOKEN_AUDIENCE")
	if aud == "" {
		aud = "authorization-service"
	}
	ttl := time.Hour
	if raw := os.Getenv("TOKEN_TTL"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			ttl = parsed
		}
	}
	return Issuer{SigningKey: []byte(key), Issuer: iss, Audience: aud, TTL: ttl}, nil
}

// Issue creates a signed JWT access token.
func (i Issuer) Issue(req TokenRequest, scopes []string, claims map[string]interface{}, ttlOverride time.Duration) (string, int64, error) {
	ttl := i.TTL
	if req.RequestedTTL > 0 {
		ttl = req.RequestedTTL
	}
	if ttlOverride > 0 {
		ttl = ttlOverride
	}
	now := time.Now()
	exp := now.Add(ttl).Unix()
	base := jwt.MapClaims{
		"iss":       i.Issuer,
		"sub":       req.Subject,
		"aud":       req.Audience,
		"iat":       now.Unix(),
		"exp":       exp,
		"client_id": req.ClientID,
	}
	if req.TenantID != "" {
		base[oidc.TenantClaim()] = req.TenantID
	}
	if len(scopes) > 0 {
		base["scope"] = scopes
	}
	for k, v := range claims {
		base[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, base)
	str, err := tok.SignedString(i.SigningKey)
	return str, exp - now.Unix(), err
}
