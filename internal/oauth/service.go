package oauth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bradtumy/authorization-service/internal/policyhook"
)

// TokenService issues OAuth tokens.
type TokenService struct {
	Clients    ClientStore
	Issuer     Issuer
	PreHook    policyhook.PreIssueHook
	PostHook   policyhook.PostIssueHook
	FailClosed bool
}

// IssueClientCredentials issues a token for client credentials flow.
func (s TokenService) IssueClientCredentials(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	if s.Clients == nil {
		return TokenResponse{}, errors.New("client store is not configured")
	}
	if req.ClientID == "" {
		return TokenResponse{}, errors.New("client_id is required")
	}
	if req.Audience == "" {
		req.Audience = s.Issuer.Audience
	}
	if req.Subject == "" {
		req.Subject = req.ClientID
	}
	if s.PreHook != nil {
		decision, err := s.PreHook.PreIssue(ctx, policyhook.Request{
			GrantType:       req.GrantType,
			ClientID:        req.ClientID,
			Subject:         req.Subject,
			RequestedScopes: req.Scopes,
			Audience:        req.Audience,
			TenantID:        req.TenantID,
			RequestedTTL:    int64(req.RequestedTTL.Seconds()),
		})
		if err != nil {
			if s.FailClosed {
				return TokenResponse{}, err
			}
		} else if !decision.Allow {
			return TokenResponse{}, errors.New(decision.DenyReason)
		} else if len(decision.Scopes) > 0 {
			req.Scopes = decision.Scopes
		}
		claims := decision.Claims
		if claims == nil {
			claims = map[string]interface{}{}
		}
		if s.PostHook != nil {
			claims, err = s.PostHook.PostIssue(ctx, claims, policyhook.Request{GrantType: req.GrantType, ClientID: req.ClientID})
			if err != nil && s.FailClosed {
				return TokenResponse{}, err
			}
		}
		ttlOverride := time.Duration(decision.TTLSeconds) * time.Second
		accessToken, expiresIn, err := s.Issuer.Issue(req, req.Scopes, claims, ttlOverride)
		if err != nil {
			return TokenResponse{}, err
		}
		return TokenResponse{AccessToken: accessToken, TokenType: "bearer", ExpiresIn: expiresIn, Scope: strings.Join(req.Scopes, " ")}, nil
	}

	accessToken, expiresIn, err := s.Issuer.Issue(req, req.Scopes, map[string]interface{}{}, 0)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: accessToken, TokenType: "bearer", ExpiresIn: expiresIn, Scope: strings.Join(req.Scopes, " ")}, nil
}
