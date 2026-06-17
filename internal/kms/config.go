package kms

import (
	"fmt"
	"os"
	"sort"
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

// OIDCProviderConfig holds configuration for a single OIDC provider, including
// its own claim mapping. Each provider may expose a different subset of entity
// types depending on which claims it includes in its tokens.
// ID is populated from the map key during config loading and is used in the
// /xpk/{id}/… URL path and as part of the HKDF derivation info string.
type OIDCProviderConfig struct {
	ID           string       // set from the map key, not from YAML
	Name         string       `yaml:"name"`
	IssuerURL    string       `yaml:"issuer_url"`
	ClientID     string       `yaml:"client_id"`
	ClientSecret secretSource `yaml:"client_secret"`
	RedirectURI  string       `yaml:"redirect_uri"`
	Scopes       []string     `yaml:"scopes"`
	UsePKCE      bool         `yaml:"use_pkce"`

	// Claims maps each entity type to the OIDC claim that carries its identity
	// for this provider. Omit a field to disable that entity type for this provider.
	Claims struct {
		User    string `yaml:"user"`    // single value, e.g. "email"
		Group   string `yaml:"group"`   // array value, e.g. "groups"
		Service string `yaml:"service"` // single value, e.g. "sub"
	} `yaml:"claims"`
}

// rawConfig is used for YAML parsing only. providers is a map so the key
// serves as the provider ID; after parsing it is converted to a sorted slice.
type rawConfig struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	SeedFile   string                        `yaml:"seed_file"`
	PubKeyPath string                        `yaml:"pubkey_path"`
	Providers  map[string]OIDCProviderConfig `yaml:"providers"`
	AuthHeader struct {
		Type string `yaml:"type"`
		Name string `yaml:"name"`
	} `yaml:"auth_header"`
	Credential struct {
		Seed    bool `yaml:"seed"`
		Key     bool `yaml:"key"`
		Timeout int  `yaml:"timeout"`
	} `yaml:"credential"`
	PostQuantum         bool     `yaml:"post_quantum"`
	AllowedCallbackURLs []string `yaml:"xipher_urls"`
}

// Config is the top-level Xipher KMS (XKMS) server configuration loaded from a YAML file.
type Config struct {
	Server struct {
		Host string
		Port int
	}
	SeedFile string

	// PubKeyPath is the URL path prefix under which the public-key (xpk)
	// discovery endpoints are served. Defaults to "/xpk/" when unset. Always
	// normalized to a leading and trailing slash. This is routing only and does
	// not affect HKDF derivation.
	PubKeyPath string

	// Providers is the ordered list of OIDC identity providers XKMS trusts,
	// sorted by provider ID. At least one is required. For the browser flow,
	// when multiple providers are configured a selector page is shown; when
	// only one is configured it is used directly. For direct API auth, XKMS
	// tries each provider's verifier in order.
	Providers []OIDCProviderConfig

	// AuthHeader configures the header carrying the OIDC JWT for direct API auth.
	// This is shared across all providers.
	AuthHeader struct {
		Type string // "bearer" | "custom"
		Name string // header name; ignored when type == "bearer"
	}

	Credential struct {
		Seed    bool // include the base64-encoded raw seed in responses
		Key     bool // include the XSK_-prefixed key in responses
		Timeout int  // seconds; 0 = ephemeral
	}

	// PostQuantum controls the kind of public key served by the public /xpk
	// endpoints: quantum-safe hybrid (X25519 + ML-KEM-1024) when true, ECC when
	// false. It does not affect the sealed-credential flow.
	PostQuantum bool

	// AllowedCallbackURLs is the allowlist of xipher app URLs (the xcb param).
	AllowedCallbackURLs []string
}

const (
	authHeaderBearer = "bearer"
	authHeaderCustom = "custom"

	defaultPubKeyPath = "/xpk/"
)

// normalizePathPrefix returns a URL path prefix with exactly one leading and
// one trailing slash. An empty input yields the default "/xpk/".
func normalizePathPrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return defaultPubKeyPath
	}
	p = "/" + strings.Trim(p, "/") + "/"
	return p
}

// LoadConfig reads, parses, and validates the Xipher KMS (XKMS) config from the given path.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var raw rawConfig
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Convert providers map → sorted slice, injecting the map key as ID.
	ids := make([]string, 0, len(raw.Providers))
	for id := range raw.Providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	providers := make([]OIDCProviderConfig, len(ids))
	for i, id := range ids {
		p := raw.Providers[id]
		p.ID = id
		providers[i] = p
	}

	c := &Config{
		SeedFile:            raw.SeedFile,
		PubKeyPath:          normalizePathPrefix(raw.PubKeyPath),
		Providers:           providers,
		PostQuantum:         raw.PostQuantum,
		AllowedCallbackURLs: raw.AllowedCallbackURLs,
	}
	c.Server.Host = raw.Server.Host
	c.Server.Port = raw.Server.Port
	c.AuthHeader.Type = raw.AuthHeader.Type
	c.AuthHeader.Name = raw.AuthHeader.Name
	c.Credential.Seed = raw.Credential.Seed
	c.Credential.Key = raw.Credential.Key
	c.Credential.Timeout = raw.Credential.Timeout

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.Server.Port == 0 {
		return fmt.Errorf("server.port is required")
	}
	if c.SeedFile == "" {
		return fmt.Errorf("seed_file is required")
	}
	if len(c.Providers) == 0 {
		return fmt.Errorf("at least one provider is required")
	}
	seenNames := make(map[string]bool)
	for _, p := range c.Providers {
		if p.Name == "" {
			return fmt.Errorf("provider %q: name is required", p.ID)
		}
		if seenNames[p.Name] {
			return fmt.Errorf("duplicate provider name %q", p.Name)
		}
		seenNames[p.Name] = true
		if p.IssuerURL == "" {
			return fmt.Errorf("provider %q: issuer_url is required", p.ID)
		}
		if p.ClientID == "" {
			return fmt.Errorf("provider %q: client_id is required", p.ID)
		}
		if p.RedirectURI == "" {
			return fmt.Errorf("provider %q: redirect_uri is required", p.ID)
		}
		if p.Claims.User == "" && p.Claims.Group == "" && p.Claims.Service == "" {
			return fmt.Errorf("provider %q: at least one of claims.user/group/service is required", p.ID)
		}
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
	if !c.Credential.Seed && !c.Credential.Key {
		return fmt.Errorf("at least one of credential.seed/credential.key must be true")
	}
	if len(c.AllowedCallbackURLs) == 0 {
		return fmt.Errorf("xipher_urls must list at least one URL")
	}
	return nil
}
