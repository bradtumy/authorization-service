package evaluator

import (
	"path/filepath"
	"testing"
)

func policyDir() string {
	return filepath.Join("..", "..", "policies")
}

func TestRBACEvaluation(t *testing.T) {
	e, err := New(policyDir())
	if err != nil {
		t.Fatalf("new evaluator: %v", err)
	}
	ctx := Context{Action: "read", Resource: "doc"}
	vc := map[string]any{"credentialSubject": map[string]any{"roles": []any{"admin"}}}
	res := e.Evaluate(vc, ctx)
	if !res.Allowed {
		t.Fatalf("expected allowed, got %+v", res)
	}
	vc = map[string]any{"credentialSubject": map[string]any{"roles": []any{"viewer"}}}
	res = e.Evaluate(vc, ctx)
	if res.Allowed || res.Advice != "admin role required" {
		t.Fatalf("expected deny with advice, got %+v", res)
	}
}

func TestABACEvaluation(t *testing.T) {
	e, err := New(policyDir())
	if err != nil {
		t.Fatalf("new evaluator: %v", err)
	}
	ctx := Context{Action: "view", Resource: "report"}
	vc := map[string]any{"credentialSubject": map[string]any{"department": "sales"}}
	res := e.Evaluate(vc, ctx)
	if !res.Allowed {
		t.Fatalf("expected allowed, got %+v", res)
	}
	vc = map[string]any{"credentialSubject": map[string]any{"department": "engineering"}}
	res = e.Evaluate(vc, ctx)
	if res.Allowed || res.Advice != "sales department required" {
		t.Fatalf("expected deny with advice, got %+v", res)
	}
}
