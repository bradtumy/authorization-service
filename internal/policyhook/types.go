package policyhook

import "context"

// Decision represents a policy hook decision.
type Decision struct {
	Allow      bool                   `json:"allow"`
	Scopes     []string               `json:"scopes_to_issue,omitempty"`
	Claims     map[string]interface{} `json:"claims_to_embed,omitempty"`
	TTLSeconds int64                  `json:"ttl_override_seconds,omitempty"`
	DenyReason string                 `json:"deny_reason,omitempty"`
	DecisionID string                 `json:"decision_id,omitempty"`
}

// Request captures the context sent to a policy hook.
type Request struct {
	GrantType       string            `json:"grant_type"`
	ClientID        string            `json:"client_id"`
	Subject         string            `json:"subject,omitempty"`
	Actor           string            `json:"actor,omitempty"`
	RequestedScopes []string          `json:"requested_scopes,omitempty"`
	Audience        string            `json:"audience,omitempty"`
	Resource        string            `json:"resource,omitempty"`
	TenantID        string            `json:"tenant_id,omitempty"`
	RequestedTTL    int64             `json:"requested_ttl_seconds,omitempty"`
	TokenExchange   map[string]string `json:"token_exchange,omitempty"`
}

// PreIssueHook consults policy before issuing a token.
type PreIssueHook interface {
	PreIssue(ctx context.Context, req Request) (Decision, error)
}

// PostIssueHook mutates the token claims after issuance.
type PostIssueHook interface {
	PostIssue(ctx context.Context, claims map[string]interface{}, req Request) (map[string]interface{}, error)
}
