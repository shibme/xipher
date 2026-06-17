package kms

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// providerStateTTL bounds how long a pending xipher provider request (xpk +
// state + xcb) is held server-side between /login and the credential call.
const providerStateTTL = 10 * time.Minute

// providerState holds the xipher provider parameters for an in-flight browser
// flow, keyed by an opaque id carried through the OIDC round-trip.
type providerState struct {
	providerIdx int    // index into Server.auths
	xpk         string // ephemeral XPK_ public key from the xipher app
	state       string // original xipher state token (echoed back in xck redirect)
	xcb         string // validated callback URL
	expires     time.Time
}

// Server is the running Xipher KMS (XKMS) instance.
type Server struct {
	cfg   *Config
	auths []*authenticator // one per provider, same order as cfg.Providers

	seed []byte

	mu     sync.Mutex
	states map[string]providerState
}

// NewServer builds a Xipher KMS (XKMS) server: loads the master seed (clearing
// the seed file), performs OIDC discovery for each configured provider, and
// prepares the HTTP handlers.
func NewServer(ctx context.Context, cfg *Config) (*Server, error) {
	seed, err := loadSeed(cfg.SeedFile)
	if err != nil {
		return nil, err
	}
	auths := make([]*authenticator, len(cfg.Providers))
	for i, p := range cfg.Providers {
		a, err := newAuthenticator(ctx, p)
		if err != nil {
			return nil, err
		}
		auths[i] = a
	}
	return &Server{
		cfg:    cfg,
		auths:  auths,
		seed:   seed,
		states: make(map[string]providerState),
	}, nil
}

// Run starts the HTTP server and blocks until ctx is cancelled, then shuts
// down gracefully and zeroes the in-memory seed.
func (s *Server) Run(ctx context.Context) error {
	defer s.zeroSeed()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /{$}", s.handleRoot)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("GET /callback", s.handleCallback)
	mux.HandleFunc("GET /consent", s.handleConsent)
	mux.HandleFunc("POST /api/v1/credential/user", s.handleCredentialUser)
	mux.HandleFunc("POST /api/v1/credential/group/{name}", s.handleCredentialGroup)
	mux.HandleFunc("POST /api/v1/credential/service", s.handleCredentialService)

	// Public, unauthenticated public-key endpoints (xipher resolver format).
	// Path: {pubkey_path}{provider}/{type}/{id}/.well-known/xipher
	// The prefix defaults to /xpk/ and is configurable via config.PubKeyPath.
	// These carry permissive CORS so any origin's browser may read them; the
	// OPTIONS route answers CORS preflight for the whole subtree.
	pk := s.cfg.PubKeyPath
	mux.HandleFunc("GET "+pk+"{provider}/user/{id}/.well-known/xipher", s.handlePublicKeyUser)
	mux.HandleFunc("GET "+pk+"{provider}/group/{id}/.well-known/xipher", s.handlePublicKeyGroup)
	mux.HandleFunc("GET "+pk+"{provider}/service/{id}/.well-known/xipher", s.handlePublicKeyService)
	mux.HandleFunc("OPTIONS "+pk, s.handlePublicKeyPreflight)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port),
		Handler: securityHeaders(mux),
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}

func (s *Server) zeroSeed() {
	for i := range s.seed {
		s.seed[i] = 0
	}
}

// putState stores a provider state under a fresh opaque id and returns the id.
func (s *Server) putState(st providerState) (string, error) {
	id, err := randomToken(16)
	if err != nil {
		return "", err
	}
	st.expires = time.Now().Add(providerStateTTL)
	s.mu.Lock()
	s.states[id] = st
	s.pruneLocked()
	s.mu.Unlock()
	return id, nil
}

// takeState removes and returns a provider state by id, reporting whether it
// existed and was unexpired.
func (s *Server) takeState(id string) (providerState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[id]
	if !ok {
		return providerState{}, false
	}
	delete(s.states, id)
	if time.Now().After(st.expires) {
		return providerState{}, false
	}
	return st, true
}

func (s *Server) pruneLocked() {
	now := time.Now()
	for k, v := range s.states {
		if now.After(v.expires) {
			delete(s.states, k)
		}
	}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
