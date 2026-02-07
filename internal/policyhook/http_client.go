package policyhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient calls an external policy decision point.
type HTTPClient struct {
	Endpoint     string
	Timeout      time.Duration
	AllowedHosts []string
	HTTPClient   *http.Client
}

// PreIssue sends a policy consult request to the PDP endpoint.
func (c HTTPClient) PreIssue(ctx context.Context, req Request) (Decision, error) {
	if c.Endpoint == "" {
		return Decision{}, errors.New("policy hook endpoint is not configured")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return Decision{}, err
	}
	if len(c.AllowedHosts) > 0 {
		host := u.Hostname()
		allowed := false
		for _, h := range c.AllowedHosts {
			if strings.EqualFold(strings.TrimSpace(h), host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Decision{}, errors.New("policy hook host not allowed")
		}
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: c.Timeout}
	}
	if client.Timeout == 0 {
		client.Timeout = c.Timeout
	}
	if client.Timeout == 0 {
		client.Timeout = 3 * time.Second
	}
	body, err := json.Marshal(req)
	if err != nil {
		return Decision{}, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, client.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		if isTimeout(err) {
			return Decision{}, errors.New("policy hook timeout")
		}
		return Decision{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Decision{}, errors.New("policy hook denied")
	}
	var decision Decision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

// PostIssue returns claims unchanged for HTTPClient.
func (c HTTPClient) PostIssue(ctx context.Context, claims map[string]interface{}, req Request) (map[string]interface{}, error) {
	return claims, nil
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
