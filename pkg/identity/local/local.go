package local

import (
	"context"
	"errors"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/bradtumy/authorization-service/pkg/identity"
)

// Provider implements identity.Provider backed by in-memory maps with optional YAML persistence.
type Provider struct {
	mu      sync.RWMutex
	users   map[string][]identity.User // tenantID -> []User
	loaded  map[string]bool
	persist bool
}

// New returns a new local Provider. If persist is true, users are stored under configs/<tenantID>/users.yaml.
func New(persist bool) *Provider {
	return &Provider{
		users:   make(map[string][]identity.User),
		loaded:  make(map[string]bool),
		persist: persist,
	}
}

func (p *Provider) filePath(tenantID string) string {
	return "configs/" + tenantID + "/users.yaml"
}

func (p *Provider) load(tenantID string) {
	if !p.persist || p.loaded[tenantID] {
		return
	}
	path := p.filePath(tenantID)
	data, err := os.ReadFile(path)
	if err != nil {
		p.loaded[tenantID] = true
		return
	}
	var wrapper struct {
		Users []identity.User `yaml:"users"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err == nil {
		for i := range wrapper.Users {
			wrapper.Users[i].TenantID = tenantID
		}
		p.users[tenantID] = wrapper.Users
	}
	p.loaded[tenantID] = true
}

func (p *Provider) save(tenantID string) {
	if !p.persist {
		return
	}
	path := p.filePath(tenantID)
	if err := os.MkdirAll("configs/"+tenantID, 0755); err != nil {
		return
	}
	wrapper := struct {
		Users []identity.User `yaml:"users"`
	}{Users: p.users[tenantID]}
	data, err := yaml.Marshal(wrapper)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0644)
}

// Create adds a new user under a tenant.
func (p *Provider) Create(ctx context.Context, tenantID, username string, roles []string) (identity.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load(tenantID)
	for _, u := range p.users[tenantID] {
		if u.Username == username {
			return identity.User{}, errors.New("user exists")
		}
	}
	u := identity.User{Username: username, Roles: roles, TenantID: tenantID}
	p.users[tenantID] = append(p.users[tenantID], u)
	p.save(tenantID)
	return u, nil
}

// AssignRoles sets roles for an existing user.
func (p *Provider) AssignRoles(ctx context.Context, tenantID, username string, roles []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load(tenantID)
	for i, u := range p.users[tenantID] {
		if u.Username == username {
			p.users[tenantID][i].Roles = roles
			p.save(tenantID)
			return nil
		}
	}
	return errors.New("user not found")
}

// Delete removes a user from the tenant.
func (p *Provider) Delete(ctx context.Context, tenantID, username string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load(tenantID)
	arr := p.users[tenantID]
	for i, u := range arr {
		if u.Username == username {
			p.users[tenantID] = append(arr[:i], arr[i+1:]...)
			p.save(tenantID)
			return nil
		}
	}
	return errors.New("user not found")
}

// List returns all users for a tenant.
func (p *Provider) List(ctx context.Context, tenantID string) ([]identity.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	p.load(tenantID)
	list := p.users[tenantID]
	cp := make([]identity.User, len(list))
	copy(cp, list)
	return cp, nil
}

// Get returns a user by username.
func (p *Provider) Get(ctx context.Context, tenantID, username string) (identity.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	p.load(tenantID)
	for _, u := range p.users[tenantID] {
		if u.Username == username {
			return u, nil
		}
	}
	return identity.User{}, errors.New("user not found")
}

// HasRole checks if a user has any of the provided roles.
func (p *Provider) HasRole(ctx context.Context, tenantID, username string, roles ...string) bool {
	u, err := p.Get(ctx, tenantID, username)
	if err != nil {
		return false
	}
	roleSet := make(map[string]struct{}, len(u.Roles))
	for _, r := range u.Roles {
		roleSet[r] = struct{}{}
	}
	for _, r := range roles {
		if _, ok := roleSet[r]; ok {
			return true
		}
	}
	return false
}

// Reset clears all users (used in tests).
func (p *Provider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users = make(map[string][]identity.User)
	p.loaded = make(map[string]bool)
}
