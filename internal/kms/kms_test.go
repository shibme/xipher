package kms

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xipher.org/xipher"
)

const testProviderID = "test-provider"

func TestDeriveSeedDeterministic(t *testing.T) {
	master := make([]byte, 64)
	rand.Read(master)

	a, err := deriveSeed(master, testProviderID, entityUser, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != credentialSeedLength {
		t.Fatalf("want %d bytes, got %d", credentialSeedLength, len(a))
	}
	// Same input -> same output.
	b, _ := deriveSeed(master, testProviderID, entityUser, "alice@example.com")
	if !bytes.Equal(a, b) {
		t.Fatal("derivation not deterministic")
	}
	// Different type -> different output (no cross-type collision).
	c, _ := deriveSeed(master, testProviderID, entityService, "alice@example.com")
	if bytes.Equal(a, c) {
		t.Fatal("user and service collide for same id")
	}
	// Different id -> different output.
	d, _ := deriveSeed(master, testProviderID, entityUser, "bob@example.com")
	if bytes.Equal(a, d) {
		t.Fatal("different ids collide")
	}
	// Different providerID -> different output.
	e, _ := deriveSeed(master, "other-provider", entityUser, "alice@example.com")
	if bytes.Equal(a, e) {
		t.Fatal("different provider IDs collide for same identity")
	}
}

func TestSecretKeyFromDerivedSeed(t *testing.T) {
	master := make([]byte, 64)
	rand.Read(master)
	seed, _ := deriveSeed(master, testProviderID, entityGroup, "platform")
	sk, err := secretKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sk.String(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSeed(t *testing.T) {
	dir := t.TempDir()

	t.Run("rejects short", func(t *testing.T) {
		p := filepath.Join(dir, "short")
		os.WriteFile(p, []byte("tooshort"), 0600)
		if _, err := loadSeed(p); err == nil {
			t.Fatal("expected error for short seed")
		}
	})

	t.Run("rejects low entropy", func(t *testing.T) {
		p := filepath.Join(dir, "lowent")
		os.WriteFile(p, bytes.Repeat([]byte("A"), 80), 0600)
		if _, err := loadSeed(p); err == nil {
			t.Fatal("expected error for low-entropy seed")
		}
	})

	t.Run("accepts good raw seed and deletes file", func(t *testing.T) {
		p := filepath.Join(dir, "good")
		raw := make([]byte, 64)
		rand.Read(raw)
		os.WriteFile(p, raw, 0600)
		seed, err := loadSeed(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(seed, raw) {
			t.Fatal("loaded seed mismatch")
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("seed file not deleted after load")
		}
	})

	t.Run("decodes hex seed", func(t *testing.T) {
		p := filepath.Join(dir, "hex")
		raw := make([]byte, 64)
		rand.Read(raw)
		os.WriteFile(p, []byte(hex.EncodeToString(raw)), 0600)
		seed, err := loadSeed(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(seed, raw) {
			t.Fatal("hex-decoded seed mismatch")
		}
	})
}

func testServer(master []byte) *Server {
	auth := &authenticator{
		cfg: OIDCProviderConfig{
			ID:          "test-provider",
			Name:        "Test Provider",
			IssuerURL:   "https://sso.example.com",
			RedirectURI: "https://xkms.example.com/callback",
		},
	}
	return &Server{
		cfg:   &Config{},
		auths: []*authenticator{auth},
		seed:  master,
	}
}

func TestServePublicKey(t *testing.T) {
	master := make([]byte, 64)
	rand.Read(master)
	s := testServer(master)

	for _, pq := range []bool{false, true} {
		s.cfg.PostQuantum = pq
		req := httptest.NewRequest("GET", "/xpk/test-provider/group/cloud-engineering/.well-known/xipher", nil)
		req.SetPathValue("provider", "test-provider")
		req.SetPathValue("id", "cloud-engineering")
		rec := httptest.NewRecorder()
		s.servePublicKey(rec, req, entityGroup, "Group")

		if rec.Code != 200 {
			t.Fatalf("pq=%v: status %d", pq, rec.Code)
		}
		var out map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("pq=%v: bad json: %v", pq, err)
		}
		if out["name"] != "Group - cloud-engineering" {
			t.Errorf("pq=%v: name = %q", pq, out["name"])
		}
		if !xipher.IsPubKeyStr(out["publicKey"]) {
			t.Errorf("pq=%v: not a public key: %q", pq, out["publicKey"])
		}
	}

	// Same identity must yield the same served key (deterministic).
	mkReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/xpk/test-provider/user/alice@example.com/.well-known/xipher", nil)
		req.SetPathValue("provider", "test-provider")
		req.SetPathValue("id", "alice@example.com")
		rec := httptest.NewRecorder()
		s.cfg.PostQuantum = false
		s.servePublicKey(rec, req, entityUser, "User")
		return rec
	}
	first := mkReq().Body.String()
	second := mkReq().Body.String()
	if first != second {
		t.Fatal("served public key not deterministic")
	}
}

func TestPublicKeyCORS(t *testing.T) {
	master := make([]byte, 64)
	rand.Read(master)
	s := testServer(master)

	// /xpk/ responses must allow any origin.
	req := httptest.NewRequest("GET", "/xpk/test-provider/user/alice@example.com/.well-known/xipher", nil)
	req.SetPathValue("provider", "test-provider")
	req.SetPathValue("id", "alice@example.com")
	rec := httptest.NewRecorder()
	s.servePublicKey(rec, req, entityUser, "User")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("pubkey ACAO = %q, want *", got)
	}

	// Preflight answers with CORS and no body.
	rec = httptest.NewRecorder()
	s.handlePublicKeyPreflight(rec, httptest.NewRequest("OPTIONS", "/xpk/test-provider/user/x/.well-known/xipher", nil))
	if rec.Code != 204 {
		t.Errorf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("preflight ACAO = %q, want *", got)
	}
}

func TestSecurityHeadersLockdown(t *testing.T) {
	// Non-/xpk, non-/consent endpoints must NOT be CORS-open and must carry the
	// strict default CSP.
	var inner http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(inner)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/credential/user", nil))
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("credential endpoint should not be CORS-open, got ACAO=%q", got)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != "default-src 'none'; frame-ancestors 'none'; base-uri 'none'" {
		t.Errorf("unexpected default CSP: %q", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}

	// The middleware applies the strict default CSP to every path, including the
	// HTML pages. The /login and /consent handlers overwrite it with their own
	// nonce-based CSP on the success path; setting the strict default first keeps
	// any early error response locked down. With a stub inner handler (no
	// overwrite) the default is what we observe.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/consent", nil))
	if csp := rec.Header().Get("Content-Security-Policy"); csp != "default-src 'none'; frame-ancestors 'none'; base-uri 'none'" {
		t.Errorf("expected strict default CSP from middleware, got %q", csp)
	}
}

func TestCallbackAllowed(t *testing.T) {
	s := &Server{cfg: &Config{}}
	s.cfg.AllowedCallbackURLs = []string{"https://xipher.org", "https://xipher.int.example.com"}

	cases := map[string]bool{
		"https://xipher.org/callback":      true,
		"https://xipher.int.example.com/x": true,
		"https://evil.com":                 false,
		"http://xipher.org":                false, // scheme mismatch
		"not-a-url":                        false,
	}
	for url, want := range cases {
		if got := s.callbackAllowed(url); got != want {
			t.Errorf("callbackAllowed(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestXipherURLsValidation(t *testing.T) {
	provider := OIDCProviderConfig{ID: "p", Name: "Provider", IssuerURL: "https://sso.example.com", ClientID: "xkms", RedirectURI: "https://xkms.example.com/callback"}
	provider.Claims.User = "email"
	c := &Config{
		SeedFile:            "/tmp/seed",
		Providers:           []OIDCProviderConfig{provider},
		XipherHomeURL:       "https://xipher.org/app",
		AllowedCallbackURLs: []string{"https://xipher.org/app", "https://xipher.int.example.com"},
	}
	c.Server.Port = 8080
	c.AuthHeader.Type = authHeaderBearer
	c.Credential.Key = true
	if err := c.validate(); err != nil {
		t.Fatalf("expected xipher_urls.default to validate, got %v", err)
	}
	if !originAllowed("https://xipher.org/callback", c.AllowedCallbackURLs) {
		t.Fatal("expected xipher_urls.default origin to be allowed")
	}
	if !originAllowed("https://xipher.int.example.com/app", c.AllowedCallbackURLs) {
		t.Fatal("expected xipher_urls.allowed origin to be allowed")
	}

	c.XipherHomeURL = "not-a-url"
	if err := c.validate(); err == nil {
		t.Fatal("expected invalid xipher_urls.default to fail")
	}
}

func TestLoadConfigXipherURLs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xkms.yaml")
	cfg := []byte(`
server:
  port: 8080
seed_file: /tmp/xkms.seed
providers:
  corp:
    name: Corporate
    issuer_url: https://sso.example.com
    client_id: xkms
    redirect_uri: https://xkms.example.com/callback
    claims:
      user: email
auth_header:
  type: bearer
credential:
  key: true
xipher_urls:
  default: https://xipher.org/app
  allowed:
    - https://xipher.int.example.com
`)
	if err := os.WriteFile(path, cfg, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.XipherHomeURL != "https://xipher.org/app" {
		t.Fatalf("XipherHomeURL = %q", c.XipherHomeURL)
	}
	if !originAllowed("https://xipher.org/callback", c.AllowedCallbackURLs) {
		t.Fatal("default xipher URL was not allowed")
	}
	if !originAllowed("https://xipher.int.example.com/app", c.AllowedCallbackURLs) {
		t.Fatal("allowed xipher URL was not allowed")
	}
}

func TestHandleRootLaunchesXipherHomeURL(t *testing.T) {
	s := testServer(make([]byte, 64))
	s.cfg.XipherHomeURL = "https://xipher.org/app"
	s.cfg.PubKeyPath = "/xpk/"
	s.auths[0].cfg.Claims.User = "email"
	s.auths[0].cfg.Claims.Group = "groups"

	rec := httptest.NewRecorder()
	s.handleRoot(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"window.__XKMS_HOME__=",
		`"defaultXipherURL":"https://xipher.org/app"`,
		`"providerURL":"https://xkms.example.com/login"`,
		`"pubKeyPath":"/xpk/"`,
		`"id":"test-provider"`,
		`"types":["user","group"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("home page missing %q in:\n%s", want, body)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("home page CSP missing connect-src self: %q", csp)
	}

	rec = httptest.NewRecorder()
	s.handleRoot(rec, httptest.NewRequest("GET", "/?xpk=XPK_test", nil))
	if got := rec.Header().Get("Location"); got != "/login?xpk=XPK_test" {
		t.Fatalf("query-bearing root Location = %q", got)
	}
}
