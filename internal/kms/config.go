package kms

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// secretSource specifies where to read a secret value from: either an
// environment variable or a file. When a file is used, it is cleared after
// being read (see resolve).
type secretSource struct {
	Env  string `yaml:"env"`
	File string `yaml:"file"`
}

// resolve returns the secret value. For an env source the variable is read.
// For a file source the file is read and then deleted from the filesystem so
// the secret does not persist on disk after startup.
func (s secretSource) resolve() (string, error) {
	switch {
	case s.Env != "":
		v := os.Getenv(s.Env)
		if v == "" {
			return "", fmt.Errorf("env var %q is empty", s.Env)
		}
		return v, nil
	case s.File != "":
		b, err := os.ReadFile(s.File)
		if err != nil {
			return "", fmt.Errorf("reading secret file %q: %w", s.File, err)
		}
		// Clear the file after reading so the secret is not left on disk.
		if err := os.Remove(s.File); err != nil {
			return "", fmt.Errorf("clearing secret file %q: %w", s.File, err)
		}
		return strings.TrimSpace(string(b)), nil
	default:
		return "", nil
	}
}

// Config is the top-level Xipher KMS (XKMS) server configuration loaded from a YAML file.
type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`

	// SeedFile is the path to the master seed file. It is read once at startup,
	// validated, loaded into memory, then deleted from the filesystem.
	SeedFile string `yaml:"seed_file"`

	OIDC struct {
		IssuerURL    string       `yaml:"issuer_url"`
		ClientID     string       `yaml:"client_id"`
		ClientSecret secretSource `yaml:"client_secret"`
		RedirectURI  string       `yaml:"redirect_uri"`
		Scopes       []string     `yaml:"scopes"`
		UsePKCE      bool         `yaml:"use_pkce"`
	} `yaml:"oidc"`

	// Claims maps each entity type to the OIDC claim that carries its identity.
	Claims struct {
		User    string `yaml:"user"`    // single value, e.g. "email"
		Group   string `yaml:"group"`   // array value, e.g. "groups"
		Service string `yaml:"service"` // single value, e.g. "sub"
	} `yaml:"claims"`

	// AuthHeader configures the header carrying the OIDC JWT for direct API auth.
	AuthHeader struct {
		Type string `yaml:"type"` // "bearer" | "custom"
		Name string `yaml:"name"` // header name; ignored when type == "bearer"
	} `yaml:"auth_header"`

	Credential struct {
		Type    string `yaml:"type"`    // "seed" | "key" | "both"
		Timeout int    `yaml:"timeout"` // seconds; 0 = ephemeral
	} `yaml:"credential"`

	// PostQuantum controls the kind of public key served by the public /xpk
	// endpoints: quantum-safe hybrid (X25519 + ML-KEM-1024) when true, ECC when
	// false. It does not affect the sealed-credential flow (that seals to the
	// requester's own public key).
	PostQuantum bool `yaml:"post_quantum"`

	// AllowedCallbackURLs is the allowlist of xipher app URLs (the xcb param).
	AllowedCallbackURLs []string `yaml:"callback_urls"`
}

const (
	authHeaderBearer = "bearer"
	authHeaderCustom = "custom"

	credTypeSeed = "seed"
	credTypeKey  = "key"
	credTypeBoth = "both"
)

// LoadConfig reads, parses, and validates the Xipher KMS (XKMS) config from the given path.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Server.Port == 0 {
		return fmt.Errorf("server.port is required")
	}
	if c.SeedFile == "" {
		return fmt.Errorf("seed_file is required")
	}
	if c.OIDC.IssuerURL == "" {
		return fmt.Errorf("oidc.issuer_url is required")
	}
	if c.OIDC.ClientID == "" {
		return fmt.Errorf("oidc.client_id is required")
	}
	if c.OIDC.RedirectURI == "" {
		return fmt.Errorf("oidc.redirect_uri is required")
	}
	if c.Claims.User == "" && c.Claims.Group == "" && c.Claims.Service == "" {
		return fmt.Errorf("at least one of claims.user/group/service is required")
	}
	switch c.AuthHeader.Type {
	case authHeaderBearer:
		c.AuthHeader.Name = "Authorization"
	case authHeaderCustom:
		if c.AuthHeader.Name == "" {
			return fmt.Errorf("auth_header.name is required when auth_header.type is custom")
		}
	default:
		return fmt.Errorf("auth_header.type must be %q or %q", authHeaderBearer, authHeaderCustom)
	}
	switch c.Credential.Type {
	case credTypeSeed, credTypeKey, credTypeBoth:
	default:
		return fmt.Errorf("credential.type must be one of %q, %q, %q", credTypeSeed, credTypeKey, credTypeBoth)
	}
	if len(c.AllowedCallbackURLs) == 0 {
		return fmt.Errorf("callback_urls must list at least one URL")
	}
	return nil
}
