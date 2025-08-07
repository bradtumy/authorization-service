package authz

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bradtumy/authorization-service/internal/identity"
	"github.com/bradtumy/authorization-service/internal/policy"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

const testPolicy = `tenants:
  default:
    roles:
      admin:
        permissions: ["user:list","user:create","policy:read"]
      viewer:
        permissions: ["user:list"]
  acme:
    roles:
      admin:
        permissions: ["user:list"]
`

func newAuthorizer(t *testing.T) Authorizer {
	path := writePolicy(t, testPolicy)
	store, err := policy.NewFileStore(path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return NewRBAC(store, time.Minute)
}

func TestAdminViewer(t *testing.T) {
	a := newAuthorizer(t)
	ctx := context.Background()

	admin := identity.Principal{Roles: []string{"admin"}}
	ok, err := a.IsAllowed(ctx, admin, policy.Permission("user:create"), nil)
	if err != nil || !ok {
		t.Fatalf("admin should allow create: ok=%v err=%v", ok, err)
	}

	viewer := identity.Principal{Roles: []string{"viewer"}}
	ok, err = a.IsAllowed(ctx, viewer, policy.Permission("user:create"), nil)
	if err != nil {
		t.Fatalf("viewer error: %v", err)
	}
	if ok {
		t.Fatalf("viewer should deny create")
	}
}

func TestMultipleRoles(t *testing.T) {
	a := newAuthorizer(t)
	ctx := context.Background()
	p := identity.Principal{Roles: []string{"viewer", "admin"}}
	ok, err := a.IsAllowed(ctx, p, policy.Permission("policy:read"), nil)
	if err != nil || !ok {
		t.Fatalf("expected allow with multiple roles: ok=%v err=%v", ok, err)
	}
}

func TestTenantScoping(t *testing.T) {
	a := newAuthorizer(t)
	ctx := context.Background()

	// default tenant
	p := identity.Principal{Roles: []string{"admin"}}
	ok, err := a.IsAllowed(ctx, p, policy.Permission("user:create"), nil)
	if err != nil || !ok {
		t.Fatalf("default tenant admin should allow create")
	}

	// named tenant
	p = identity.Principal{Tenant: "acme", Roles: []string{"admin"}}
	ok, err = a.IsAllowed(ctx, p, policy.Permission("user:create"), nil)
	if err != nil {
		t.Fatalf("named tenant error: %v", err)
	}
	if ok {
		t.Fatalf("acme admin should deny create")
	}
}

func TestUnknownRoleTenant(t *testing.T) {
	a := newAuthorizer(t)
	ctx := context.Background()

	p := identity.Principal{Roles: []string{"bogus"}}
	ok, err := a.IsAllowed(ctx, p, policy.Permission("user:list"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("unknown role should deny")
	}

	p = identity.Principal{Tenant: "unknown", Roles: []string{"admin"}}
	ok, err = a.IsAllowed(ctx, p, policy.Permission("user:list"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("unknown tenant should deny")
	}
}
