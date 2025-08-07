package policy

import (
	"context"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// FileStore loads policy definitions from a YAML file.
type FileStore struct {
	mu       sync.RWMutex
	policies map[string]map[string][]Permission // tenant -> role -> perms
}

// NewFileStore reads the policy file from path.
func NewFileStore(path string) (*FileStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Tenants map[string]struct {
			Roles map[string]struct {
				Permissions []Permission `yaml:"permissions"`
			} `yaml:"roles"`
		} `yaml:"tenants"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	policies := make(map[string]map[string][]Permission)
	for t, td := range cfg.Tenants {
		roles := make(map[string][]Permission)
		for r, rd := range td.Roles {
			roles[r] = append([]Permission(nil), rd.Permissions...)
		}
		policies[t] = roles
	}
	return &FileStore{policies: policies}, nil
}

// RolePermissions returns permissions for the given tenant and role.
func (s *FileStore) RolePermissions(ctx context.Context, tenant, role string) ([]Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.policies[tenant]
	if !ok {
		return nil, ErrNotFound
	}
	perms, ok := t[role]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]Permission(nil), perms...), nil
}

// Refresh reloads the policy file from path.
func (s *FileStore) Refresh(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg struct {
		Tenants map[string]struct {
			Roles map[string]struct {
				Permissions []Permission `yaml:"permissions"`
			} `yaml:"roles"`
		} `yaml:"tenants"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return err
	}
	policies := make(map[string]map[string][]Permission)
	for t, td := range cfg.Tenants {
		roles := make(map[string][]Permission)
		for r, rd := range td.Roles {
			roles[r] = append([]Permission(nil), rd.Permissions...)
		}
		policies[t] = roles
	}
	s.mu.Lock()
	s.policies = policies
	s.mu.Unlock()
	return nil
}

var _ PolicyStore = (*FileStore)(nil)
