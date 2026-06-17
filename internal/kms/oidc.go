package kms

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// authenticator wraps OIDC discovery, token verification, and the OAuth2 code
// flow configuration for a single provider. It is built once at startup.
type authenticator struct {
	cfg          OIDCProviderConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2       oauth2.Config
	clientSecret string
}

// newAuthenticator performs OIDC discovery against the provider's issuer and
// builds the verifier and oauth2 config from the resolved client secret.
func newAuthenticator(ctx context.Context, cfg OIDCProviderConfig) (*authenticator, error) {
	clientSecret, err := cfg.ClientSecret.resolve()
	if err != nil {
		return nil, fmt.Errorf("provider %q: resolving client secret: %w", cfg.Name, err)
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("provider %q: oidc discovery: %w", cfg.Name, err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	return &authenticator{
		cfg:          cfg,
		provider:     provider,
		verifier:     verifier,
		clientSecret: clientSecret,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopes,
		},
	}, nil
}

// identity is a single resolvable identity carried by a verified token.
type identity struct {
	Type string `json:"type"` // user | group | service
	ID   string `json:"id"`   // claim value
	Name string `json:"name"` // display name
}

// verify validates a raw id token and returns its claims map.
func (a *authenticator) verify(ctx context.Context, rawIDToken string) (map[string]any, error) {
	tok, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verifying id token: %w", err)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}
	return claims, nil
}

// identitiesFromClaims extracts all identities the configured claims describe
// from a verified claims map.
func (a *authenticator) identitiesFromClaims(claims map[string]any) []identity {
	name := stringClaim(claims, "name")
	var ids []identity

	if c := a.cfg.Claims.User; c != "" {
		if v := stringClaim(claims, c); v != "" {
			ids = append(ids, identity{Type: entityUser, ID: v, Name: name})
		}
	}
	if c := a.cfg.Claims.Service; c != "" {
		if v := stringClaim(claims, c); v != "" {
			ids = append(ids, identity{Type: entityService, ID: v, Name: name})
		}
	}
	if c := a.cfg.Claims.Group; c != "" {
		for _, g := range stringSliceClaim(claims, c) {
			ids = append(ids, identity{Type: entityGroup, ID: g, Name: name})
		}
	}
	return ids
}

// hasIdentity reports whether the claims contain the given entity type and id.
func (a *authenticator) hasIdentity(claims map[string]any, entityType, entityID string) bool {
	for _, id := range a.identitiesFromClaims(claims) {
		if id.Type == entityType && id.ID == entityID {
			return true
		}
	}
	return false
}

// verifyAny tries each authenticator in order and returns the claims and the
// index of the matching authenticator. Each verifier only accepts tokens issued
// by its own provider, so typically only one will succeed.
func verifyAny(ctx context.Context, rawIDToken string, auths []*authenticator) (map[string]any, int, error) {
	var lastErr error
	for i, a := range auths {
		claims, err := a.verify(ctx, rawIDToken)
		if err == nil {
			return claims, i, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, -1, lastErr
	}
	return nil, -1, fmt.Errorf("no providers configured")
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func stringSliceClaim(claims map[string]any, key string) []string {
	v, ok := claims[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
}
