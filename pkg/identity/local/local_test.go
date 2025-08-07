package local

import (
	"context"
	"testing"
)

func TestCRUD(t *testing.T) {
	p := New(false)
	ctx := context.Background()
	if _, err := p.Create(ctx, "acme", "alice", []string{"TenantAdmin"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !p.HasRole(ctx, "acme", "alice", "TenantAdmin") {
		t.Fatalf("alice missing role")
	}
	if err := p.AssignRoles(ctx, "acme", "alice", []string{"PolicyAdmin"}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	u, err := p.Get(ctx, "acme", "alice")
	if err != nil || len(u.Roles) != 1 || u.Roles[0] != "PolicyAdmin" {
		t.Fatalf("get after assign")
	}
	list, err := p.List(ctx, "acme")
	if err != nil || len(list) != 1 || list[0].Username != "alice" {
		t.Fatalf("list incorrect")
	}
	if err := p.Delete(ctx, "acme", "alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := p.Get(ctx, "acme", "alice"); err == nil {
		t.Fatalf("expected not found")
	}
}
