package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func init() {
	os.Setenv("OIDC_CONFIG_FILE", "/dev/null")
	os.Setenv("POLICY_FILE", "../configs/policies.yaml")
}

func TestAuthorizeValidRequest(t *testing.T) {
	body := `{"credential":{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"https://example.org/credentials/3732","type":["VerifiableCredential"],"issuer":"https://example.org/issuers/14","issuanceDate":"2023-01-01T19:23:24Z","credentialSubject":{"id":"user1","role":"admin"}},"context":{"action":"read","resource":"file1","environment":{"tenantID":"default"},"consent":"granted"}}`
	r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(body))
	w := httptest.NewRecorder()
	Authorize(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if allow, ok := resp["allow"].(bool); !ok || !allow {
		t.Fatalf("expected allow decision")
	}
}

func TestAuthorizeMissingConsent(t *testing.T) {
	body := `{"credential":{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"https://example.org/credentials/3732","type":["VerifiableCredential"],"issuer":"https://example.org/issuers/14","issuanceDate":"2023-01-01T19:23:24Z","credentialSubject":{"id":"user1","role":"admin"}},"context":{"action":"read","resource":"file1","environment":{"tenantID":"default"}}}`
	r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(body))
	w := httptest.NewRecorder()
	Authorize(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "consent") {
		t.Fatalf("expected consent error, got %s", w.Body.String())
	}
}
