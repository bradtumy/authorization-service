package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bradtumy/authorization-service/internal/identity"
	"github.com/bradtumy/authorization-service/internal/policy"
)

// RBAC implements role-based access control Authorizer.
type RBAC struct {
	store policy.PolicyStore
	ttl   time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	perms   map[policy.Permission]struct{}
	expires time.Time
}

// NewRBAC creates a new RBAC authorizer with the given PolicyStore and cache TTL.
func NewRBAC(store policy.PolicyStore, ttl time.Duration) *RBAC {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &RBAC{store: store, ttl: ttl, cache: make(map[string]cacheEntry)}
}

// IsAllowed checks if the principal has the given permission.
// Resources are currently ignored but accepted for future ABAC extensions.
func (r *RBAC) IsAllowed(ctx context.Context, p identity.Principal, perm policy.Permission, resource map[string]string) (bool, error) {
	tenant := p.Tenant
	if tenant == "" {
		tenant = "default"
	}
	if len(p.Roles) == 0 {
		return false, nil
	}
	roles := append([]string(nil), p.Roles...)
	sort.Strings(roles)
	h := sha256.Sum256([]byte(strings.Join(roles, ",")))
	key := tenant + ":" + hex.EncodeToString(h[:])

	r.mu.Lock()
	ce, ok := r.cache[key]
	if ok && time.Now().Before(ce.expires) {
		_, allowed := ce.perms[perm]
		r.mu.Unlock()
		return allowed, nil
	}
	r.mu.Unlock()

	perms := make(map[policy.Permission]struct{})
	for _, role := range roles {
		ps, err := r.store.RolePermissions(ctx, tenant, role)
		if err != nil {
			if errors.Is(err, policy.ErrNotFound) {
				continue
			}
			return false, err
		}
		for _, p := range ps {
			perms[p] = struct{}{}
		}
	}
	r.mu.Lock()
	r.cache[key] = cacheEntry{perms: perms, expires: time.Now().Add(r.ttl)}
	_, allowed := perms[perm]
	r.mu.Unlock()
	return allowed, nil
}

var _ Authorizer = (*RBAC)(nil)
