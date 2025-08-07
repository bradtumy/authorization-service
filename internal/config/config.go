package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	Identity IdentityConfig `yaml:"identity"`
	Server   ServerConfig   `yaml:"server"`
}

// IdentityConfig defines OIDC related settings.
type IdentityConfig struct {
	Issuer   string       `yaml:"issuer"`
	JWKSURL  string       `yaml:"jwks_url"`
	Audience string       `yaml:"audience"`
	Claims   ClaimsConfig `yaml:"claims"`
}

// ClaimsConfig maps claim paths to principal fields.
type ClaimsConfig struct {
	Subject     string   `yaml:"subject"`
	Username    string   `yaml:"username"`
	Tenant      string   `yaml:"tenant"`
	Roles       []string `yaml:"roles"`
	StripPrefix string   `yaml:"strip_prefix"`
}

// ServerConfig defines server settings.
type ServerConfig struct {
	Addr     string `yaml:"addr"`
	LogLevel string `yaml:"log_level"`
}

// Load reads configuration from a YAML file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
