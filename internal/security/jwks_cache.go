package security

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"sync"
	"time"

	jose "gopkg.in/go-jose/go-jose.v2"
)

// ErrNotFound indicates the requested key ID was not present.
var ErrNotFound = errors.New("jwks key not found")

// JWKSCache caches keys from a JWKS endpoint and refreshes them periodically.
type JWKSCache struct {
	url      string
	client   *http.Client
	mu       sync.RWMutex
	keys     map[string]any
	interval time.Duration
	rnd      *rand.Rand
}

// NewJWKSCache creates a cache and starts a background refresh loop.
func NewJWKSCache(ctx context.Context, url string, interval time.Duration) (*JWKSCache, error) {
	c := &JWKSCache{
		url:      url,
		client:   &http.Client{Timeout: 5 * time.Second},
		keys:     make(map[string]any),
		interval: interval,
		rnd:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	if err := c.Refresh(ctx); err != nil {
		return nil, err
	}
	go c.loop(ctx)
	return c, nil
}

func (c *JWKSCache) loop(ctx context.Context) {
	for {
		jitter := time.Duration(c.rnd.Int63n(int64(c.interval / 10)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.interval + jitter):
			_ = c.Refresh(context.Background())
		}
	}
}

// Refresh fetches the latest JWKS from the remote URL.
func (c *JWKSCache) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}

	m := make(map[string]any)
	for _, k := range set.Keys {
		if k.KeyID == "" || k.Key == nil {
			continue
		}
		m[k.KeyID] = k.Key
	}

	c.mu.Lock()
	c.keys = m
	c.mu.Unlock()
	return nil
}

// Key returns the public key for the given kid.
func (c *JWKSCache) Key(ctx context.Context, kid string) (any, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	c.mu.RUnlock()
	if ok {
		return k, nil
	}
	if err := c.Refresh(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	k, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	return k, nil
}
