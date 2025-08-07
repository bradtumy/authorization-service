package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bradtumy/authorization-service/pkg/identity"
)

func TestCRUD(t *testing.T) {
	users := map[string]identity.User{}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/acme/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token"}`))
	})
	mux.HandleFunc("/admin/realms/acme/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var u identity.User
			if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
				t.Fatalf("decode: %v", err)
			}
			u.TenantID = "acme"
			users[u.Username] = u
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(u)
		case http.MethodGet:
			list := []identity.User{}
			for _, u := range users {
				list = append(list, u)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(list)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/admin/realms/acme/users/alice", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			u, ok := users["alice"]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(u)
		case http.MethodDelete:
			delete(users, "alice")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/admin/realms/acme/users/alice/roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var roles []string
		if err := json.NewDecoder(r.Body).Decode(&roles); err != nil {
			t.Fatalf("decode roles: %v", err)
		}
		u := users["alice"]
		u.Roles = roles
		users["alice"] = u
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	os.Setenv("KEYCLOAK_BASE_URL", server.URL)
	os.Setenv("KEYCLOAK_CLIENT_ID", "id")
	os.Setenv("KEYCLOAK_CLIENT_SECRET", "secret")

	p := NewFromEnv()
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
