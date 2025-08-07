package identity

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/bradtumy/authorization-service/internal/config"
	"github.com/bradtumy/authorization-service/internal/security"
)

// OIDCProvider implements IdentityProvider using OIDC JWTs.
type OIDCProvider struct {
	cfg  config.IdentityConfig
	jwks *security.JWKSCache
}

// NewOIDCProvider creates a provider with JWKS caching.
func NewOIDCProvider(ctx context.Context, cfg config.IdentityConfig) (*OIDCProvider, error) {
	cache, err := security.NewJWKSCache(ctx, cfg.JWKSURL, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	return &OIDCProvider{cfg: cfg, jwks: cache}, nil
}

// Verify validates the JWT and returns token metadata.
func (p *OIDCProvider) Verify(ctx context.Context, raw string) (TokenInfo, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, ErrInvalidToken
		}
		key, err := p.jwks.Key(ctx, kid)
		if errors.Is(err, security.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return key, err
	}

	var claims jwt.MapClaims
	parser := &jwt.Parser{}
	tok, err := parser.ParseWithClaims(raw, &claims, keyFunc)
	if err != nil || !tok.Valid {
		return TokenInfo{}, ErrInvalidToken
	}
	if !claims.VerifyIssuer(p.cfg.Issuer, true) {
		return TokenInfo{}, ErrInvalidToken
	}
	if !claims.VerifyAudience(p.cfg.Audience, true) {
		return TokenInfo{}, ErrInvalidToken
	}
	now := time.Now()
	if !claims.VerifyExpiresAt(now.Add(time.Minute).Unix(), true) {
		return TokenInfo{}, ErrInvalidToken
	}
	if !claims.VerifyNotBefore(now.Add(-time.Minute).Unix(), true) {
		return TokenInfo{}, ErrInvalidToken
	}
	aud, _ := claims["aud"].(string)
	iss, _ := claims["iss"].(string)

	return TokenInfo{Raw: raw, Issuer: iss, Aud: aud, Claims: map[string]any(claims)}, nil
}

// PrincipalFromClaims maps the token claims to a Principal based on config.
func (p *OIDCProvider) PrincipalFromClaims(ctx context.Context, ti TokenInfo) (Principal, error) {
	subj, ok := claimString(ti.Claims, p.cfg.Claims.Subject)
	if !ok || subj == "" {
		return Principal{}, ErrClaimMapping
	}
	uname, ok := claimString(ti.Claims, p.cfg.Claims.Username)
	if !ok || uname == "" {
		return Principal{}, ErrClaimMapping
	}
	tenant, _ := claimString(ti.Claims, p.cfg.Claims.Tenant)

	roleSet := make(map[string]struct{})
	for _, path := range p.cfg.Claims.Roles {
		val, ok := claimValue(ti.Claims, path)
		if !ok {
			continue
		}
		for _, r := range toStringSlice(val) {
			r = strings.ToLower(strings.TrimSpace(r))
			if sp := strings.ToLower(p.cfg.Claims.StripPrefix); sp != "" && strings.HasPrefix(r, sp) {
				r = strings.TrimPrefix(r, sp)
			}
			if r == "" {
				continue
			}
			roleSet[r] = struct{}{}
		}
	}
	roles := make([]string, 0, len(roleSet))
	for r := range roleSet {
		roles = append(roles, r)
	}
	sort.Strings(roles)

	return Principal{
		Subject:  subj,
		Username: uname,
		Tenant:   tenant,
		Roles:    roles,
		Issuer:   ti.Issuer,
		Attrs:    map[string]string{},
	}, nil
}

func claimValue(m map[string]any, path string) (any, bool) {
	cur := any(m)
	for _, p := range strings.Split(path, ".") {
		mp, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mp[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func claimString(m map[string]any, path string) (string, bool) {
	v, ok := claimValue(m, path)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, i := range t {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		if s, ok := t.(string); ok {
			return []string{s}
		}
	}
	return nil
}
