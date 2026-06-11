package utils

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"xipher.org/xipher"
)

// newTestPubKey derives a valid XPK_ public key string for use in tests.
func newTestPubKey(t *testing.T) string {
	t.Helper()
	sk, err := xipher.NewSecretKey()
	if err != nil {
		t.Fatalf("failed to create secret key: %v", err)
	}
	pub, err := sk.PublicKey(false)
	if err != nil {
		t.Fatalf("failed to derive public key: %v", err)
	}
	pubStr, err := pub.String()
	if err != nil {
		t.Fatalf("failed to stringify public key: %v", err)
	}
	return pubStr
}

// serveBody starts a TLS test server returning body for every request and wires
// keyFetchClient to trust it. It returns the server URL.
func serveBody(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	keyFetchClient = srv.Client()
	keyFetchClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errInsecureKeyURL
		}
		return nil
	}
	clearKeyCache()
	return srv
}

func TestIsKeyURL(t *testing.T) {
	cases := map[string]bool{
		"https://keys.example.com/xpk": true,
		"  https://example.com  ":      true,
		"http://example.com/xpk":       false,
		"XPK_ABCDEF":                   false,
		"my.dotted.password":           false,
		"example.com":                  false,
		"":                             false,
	}
	for in, want := range cases {
		if got := isKeyURL(in); got != want {
			t.Errorf("isKeyURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFetchPublicKeyPlaintext(t *testing.T) {
	pubStr := newTestPubKey(t)
	// surround with whitespace to confirm trimming
	srv := serveBody(t, "\n  "+pubStr+"\n")

	got, name, err := fetchPublicKey(srv.URL)
	if err != nil {
		t.Fatalf("fetchPublicKey returned error: %v", err)
	}
	if got != pubStr {
		t.Errorf("fetchPublicKey key = %q, want %q", got, pubStr)
	}
	if name != "" {
		t.Errorf("plaintext key should have no name, got %q", name)
	}
}

func TestFetchPublicKeyJSON(t *testing.T) {
	pubStr := newTestPubKey(t)

	t.Run("with name", func(t *testing.T) {
		srv := serveBody(t, `{"name":"Alice","publicKey":"`+pubStr+`"}`)
		got, name, err := fetchPublicKey(srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != pubStr {
			t.Errorf("key = %q, want %q", got, pubStr)
		}
		if name != "Alice" {
			t.Errorf("name = %q, want %q", name, "Alice")
		}
	})

	t.Run("without name", func(t *testing.T) {
		srv := serveBody(t, `{"publicKey":"`+pubStr+`"}`)
		got, name, err := fetchPublicKey(srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != pubStr {
			t.Errorf("key = %q, want %q", got, pubStr)
		}
		if name != "" {
			t.Errorf("name = %q, want empty", name)
		}
	})

	t.Run("bad publicKey field", func(t *testing.T) {
		srv := serveBody(t, `{"name":"Alice","publicKey":"not-a-key"}`)
		if _, _, err := fetchPublicKey(srv.URL); err != errBadKeyResponse {
			t.Errorf("want errBadKeyResponse, got %v", err)
		}
	})

	t.Run("name length capped", func(t *testing.T) {
		longName := strings.Repeat("a", maxKeyNameLen+50)
		srv := serveBody(t, `{"name":"`+longName+`","publicKey":"`+pubStr+`"}`)
		_, name, err := fetchPublicKey(srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len([]rune(name)) != maxKeyNameLen {
			t.Errorf("name length = %d, want %d", len([]rune(name)), maxKeyNameLen)
		}
	})
}

func TestFetchPublicKeyWellKnownProbing(t *testing.T) {
	pubStr := newTestPubKey(t)

	t.Run("bare host probes well-known", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Write([]byte(pubStr))
		}))
		t.Cleanup(srv.Close)
		keyFetchClient = srv.Client()
		clearKeyCache()

		if _, _, err := fetchPublicKey(srv.URL); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotPath != wellKnownKeyPath {
			t.Errorf("bare host requested path %q, want %q", gotPath, wellKnownKeyPath)
		}
	})

	t.Run("explicit path fetched verbatim", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Write([]byte(pubStr))
		}))
		t.Cleanup(srv.Close)
		keyFetchClient = srv.Client()
		clearKeyCache()

		if _, _, err := fetchPublicKey(srv.URL + "/mykey"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotPath != "/mykey" {
			t.Errorf("explicit path requested %q, want %q", gotPath, "/mykey")
		}
	})

	t.Run("path falls back to well-known under that path", func(t *testing.T) {
		var paths []string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			// The verbatim path has no key; only the well-known fallback does.
			if r.URL.Path == "/shib"+wellKnownKeyPath {
				w.Write([]byte(pubStr))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(srv.Close)
		keyFetchClient = srv.Client()
		clearKeyCache()

		got, _, err := fetchPublicKey(srv.URL + "/shib")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != pubStr {
			t.Errorf("key = %q, want %q", got, pubStr)
		}
		want := []string{"/shib", "/shib" + wellKnownKeyPath}
		if len(paths) != len(want) || paths[0] != want[0] || paths[1] != want[1] {
			t.Errorf("probed paths = %v, want %v", paths, want)
		}
	})
}

func TestFetchPublicKeyErrors(t *testing.T) {
	t.Run("insecure http", func(t *testing.T) {
		clearKeyCache()
		if _, _, err := fetchPublicKey("http://example.com/xpk"); err != errInsecureKeyURL {
			t.Errorf("want errInsecureKeyURL, got %v", err)
		}
	})

	t.Run("non-key body", func(t *testing.T) {
		srv := serveBody(t, "not a public key")
		if _, _, err := fetchPublicKey(srv.URL); err != errBadKeyResponse {
			t.Errorf("want errBadKeyResponse, got %v", err)
		}
	})

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(srv.Close)
		keyFetchClient = srv.Client()
		clearKeyCache()
		if _, _, err := fetchPublicKey(srv.URL); err == nil {
			t.Error("want error for non-200, got nil")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		srv := serveBody(t, strings.Repeat("X", maxKeyRespBytes+10))
		if _, _, err := fetchPublicKey(srv.URL); err != errKeyResponseLarge {
			t.Errorf("want errKeyResponseLarge, got %v", err)
		}
	})
}

func TestResolveKeyForEncryptionFetchesURL(t *testing.T) {
	pubStr := newTestPubKey(t)
	srv := serveBody(t, pubStr)

	// URL resolution now happens in ResolveKeyForEncryption; the resolved key is
	// then handed to NewEncryptingWriter (which no longer fetches).
	resolved, err := ResolveKeyForEncryption(srv.URL)
	if err != nil {
		t.Fatalf("ResolveKeyForEncryption returned error: %v", err)
	}

	var buf bytes.Buffer
	wc, err := NewEncryptingWriter(resolved, &buf, true, true)
	if err != nil {
		t.Fatalf("NewEncryptingWriter returned error: %v", err)
	}
	if _, err := wc.Write([]byte("hello")); err != nil {
		t.Fatalf("write error: %v", err)
	}
	if err := wc.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected ciphertext output, got none")
	}
}

func TestResolveKeyForEncryptionBadURLHardErrors(t *testing.T) {
	srv := serveBody(t, "garbage")

	if _, err := ResolveKeyForEncryption(srv.URL); err == nil {
		t.Error("expected hard error for bad URL, got nil (would have been treated as password)")
	}
}

func TestGetSanitisedKeyOrPwdURL(t *testing.T) {
	pubStr := newTestPubKey(t)
	srv := serveBody(t, `{"name":"Alice","publicKey":"`+pubStr+`"}`)

	got, isKey, name, err := GetSanitisedKeyOrPwd(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isKey {
		t.Error("resolved URL should be reported as a key")
	}
	if got != pubStr {
		t.Errorf("got %q, want %q", got, pubStr)
	}
	if name != "Alice" {
		t.Errorf("name = %q, want %q", name, "Alice")
	}
}

func TestGetSanitisedKeyOrPwdPasswordUnchanged(t *testing.T) {
	clearKeyCache()
	pwd := "my.dotted.password"
	got, isKey, name, err := GetSanitisedKeyOrPwd(pwd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isKey {
		t.Error("a dotted password must not be treated as a key")
	}
	if got != pwd {
		t.Errorf("got %q, want %q", got, pwd)
	}
	if name != "" {
		t.Errorf("password should have no name, got %q", name)
	}
}

func TestLooksLikeDomain(t *testing.T) {
	cases := map[string]bool{
		"alice.com":         true,
		"alice.example.com": true,
		"alice.com/keys":    true,
		"alice.com:8443/k":  true,
		"https://alice.com": false, // already has a scheme
		"http://alice.com":  false, // already has a scheme
		"XPK_ABCDEF":        false,
		"my password":       false, // space
		"justaword":         false, // no dot
		"":                  false,
		"localhost":         false, // no dot/TLD
		"a.b":               false, // single-char TLD
		"a.io":              true,
	}
	for in, want := range cases {
		if got := looksLikeDomain(in); got != want {
			t.Errorf("looksLikeDomain(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormaliseKeyURL(t *testing.T) {
	cases := map[string]string{
		"alice.com":         "https://alice.com",
		"alice.com/keys":    "https://alice.com/keys",
		"https://alice.com": "https://alice.com",
		"http://alice.com":  "http://alice.com", // scheme preserved; rejected later
		"  alice.com  ":     "https://alice.com",
		"localhost:8080":    "http://localhost:8080", // loopback defaults to http
		"127.0.0.1/key":     "http://127.0.0.1/key",
		"localhost":         "http://localhost",
	}
	for in, want := range cases {
		if got := normaliseKeyURL(in); got != want {
			t.Errorf("normaliseKeyURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFetchPublicKeyFromURLBareLoopback(t *testing.T) {
	pubStr := newTestPubKey(t)
	var gotPath string
	// Plain http loopback server; schemeless loopback input must default to http.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(pubStr))
	}))
	t.Cleanup(srv.Close)
	keyFetchClient = &http.Client{Timeout: keyFetchTimeout}
	clearKeyCache()

	// Strip the scheme to simulate a bare "127.0.0.1:PORT" input.
	bareHost := strings.TrimPrefix(srv.URL, "http://")
	got, _, err := FetchPublicKeyFromURL(bareHost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != pubStr {
		t.Errorf("key = %q, want %q", got, pubStr)
	}
	if gotPath != wellKnownKeyPath {
		t.Errorf("bare loopback requested path %q, want %q", gotPath, wellKnownKeyPath)
	}
}

func TestFetchPublicKeyFromURLRejectsNonHTTPS(t *testing.T) {
	clearKeyCache()
	if _, _, err := FetchPublicKeyFromURL("http://alice.com/key"); err != errInsecureKeyURL {
		t.Errorf("want errInsecureKeyURL, got %v", err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"localhost":   true,
		"LOCALHOST":   true,
		"127.0.0.1":   true,
		"127.0.0.5":   true,
		"::1":         true,
		"alice.com":   false,
		"example.org": false,
		"10.0.0.1":    false,
	}
	for in, want := range cases {
		if got := isLoopbackHost(in); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestKeyURLCandidatesAllowsLoopbackHTTP(t *testing.T) {
	cases := map[string]bool{ // url -> should be allowed
		"http://localhost/key":      true,
		"http://localhost:8080/key": true,
		"http://127.0.0.1:9000":     true,
		"https://localhost/key":     true,
		"http://alice.com/key":      false,
	}
	for in, wantOK := range cases {
		_, err := keyURLCandidates(in)
		if wantOK && err != nil {
			t.Errorf("keyURLCandidates(%q) = %v, want no error", in, err)
		}
		if !wantOK && err != errInsecureKeyURL {
			t.Errorf("keyURLCandidates(%q) err = %v, want errInsecureKeyURL", in, err)
		}
	}
}

func TestKeyURLCandidatesWellKnownProbing(t *testing.T) {
	cases := map[string][]string{
		"https://alice.com":  {"https://alice.com/.well-known/xipher"},
		"https://alice.com/": {"https://alice.com/.well-known/xipher"},
		"https://alice.com/shib": {
			"https://alice.com/shib",
			"https://alice.com/shib/.well-known/xipher",
		},
		"https://alice.com/shib/": {
			"https://alice.com/shib/",
			"https://alice.com/shib/.well-known/xipher",
		},
	}
	for in, want := range cases {
		got, err := keyURLCandidates(in)
		if err != nil {
			t.Fatalf("keyURLCandidates(%q) error: %v", in, err)
		}
		if len(got) != len(want) {
			t.Errorf("keyURLCandidates(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("keyURLCandidates(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}

func TestFetchPublicKeyLoopbackHTTP(t *testing.T) {
	pubStr := newTestPubKey(t)
	// A plain (non-TLS) http server on loopback.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(pubStr))
	}))
	t.Cleanup(srv.Close)
	keyFetchClient = &http.Client{Timeout: keyFetchTimeout}
	clearKeyCache()

	// httptest.NewServer yields http://127.0.0.1:PORT, a loopback http endpoint.
	got, _, err := fetchPublicKey(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error fetching loopback http: %v", err)
	}
	if got != pubStr {
		t.Errorf("key = %q, want %q", got, pubStr)
	}
}

func clearKeyCache() {
	keyCacheMu.Lock()
	keyCache = make(map[string]keyCacheEntry)
	keyCacheMu.Unlock()
}
