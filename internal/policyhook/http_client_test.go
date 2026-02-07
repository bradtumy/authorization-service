package policyhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPClientPreIssue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.ClientID != "client" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(Decision{Allow: true, Scopes: []string{"read"}})
	}))
	defer srv.Close()

	client := HTTPClient{Endpoint: srv.URL, Timeout: 500 * time.Millisecond}
	decision, err := client.PreIssue(context.Background(), Request{ClientID: "client"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Allow || len(decision.Scopes) != 1 || decision.Scopes[0] != "read" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestHTTPClientPreIssueHostAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Decision{Allow: true})
	}))
	defer srv.Close()

	client := HTTPClient{Endpoint: srv.URL, Timeout: time.Second, AllowedHosts: []string{"example.com"}}
	_, err := client.PreIssue(context.Background(), Request{ClientID: "client"})
	if err == nil {
		t.Fatalf("expected allowlist error")
	}
}
