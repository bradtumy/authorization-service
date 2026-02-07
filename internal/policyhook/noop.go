package policyhook

import "context"

// NoopHook allows all requests and makes no modifications.
type NoopHook struct{}

func (NoopHook) PreIssue(ctx context.Context, req Request) (Decision, error) {
	return Decision{Allow: true}, nil
}

func (NoopHook) PostIssue(ctx context.Context, claims map[string]interface{}, req Request) (map[string]interface{}, error) {
	return claims, nil
}
