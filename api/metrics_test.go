package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	_ "unsafe"
)

func init() {
	os.Setenv("OIDC_CONFIG_FILE", "/dev/null")
	os.Setenv("POLICY_FILE", "../configs/policies.yaml")
}

//go:linkname httpLatency github.com/bradtumy/authorization-service/internal/middleware.httpLatency
var httpLatency *prometheus.HistogramVec

func TestMetricsHandlerRecordsLatency(t *testing.T) {
	router := SetupRouter()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "tester", "tenantID": "default"})
	str, _ := tok.SignedString([]byte("secret"))
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+str)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	obs, err := httpLatency.GetMetricWithLabelValues("/metrics")
	if err != nil {
		t.Fatalf("get metric: %v", err)
	}
	m := &dto.Metric{}
	if err := obs.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("metric write: %v", err)
	}
	if m.GetHistogram().GetSampleCount() == 0 {
		t.Fatalf("expected histogram sample count > 0")
	}
}
