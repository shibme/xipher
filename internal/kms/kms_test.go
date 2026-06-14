package kms

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"xipher.org/xipher"
)

func TestDeriveSeedDeterministic(t *testing.T) {
	master := make([]byte, 64)
	rand.Read(master)

	a, err := deriveSeed(master, entityUser, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != credentialSeedLength {
		t.Fatalf("want %d bytes, got %d", credentialSeedLength, len(a))
	}
	// Same input -> same output.
	b, _ := deriveSeed(master, entityUser, "alice@example.com")
	if !bytes.Equal(a, b) {
		t.Fatal("derivation not deterministic")
	}
	// Different type -> different output (no cross-type collision).
	c, _ := deriveSeed(master, entityService, "alice@example.com")
	if bytes.Equal(a, c) {
		t.Fatal("user and service collide for same id")
	}
	// Different id -> different output.
	d, _ := deriveSeed(master, entityUser, "bob@example.com")
	if bytes.Equal(a, d) {
		t.Fatal("different ids collide")
	}
}

func TestSecretKeyFromDerivedSeed(t *testing.T) {
	master := make([]byte, 64)
	rand.Read(master)
	seed, _ := deriveSeed(master, entityGroup, "platform")
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

func TestServePublicKey(t *testing.T) {
	master := make([]byte, 64)
	rand.Read(master)
	s := &Server{cfg: &Config{}, seed: master}

	for _, pq := range []bool{false, true} {
		s.cfg.PostQuantum = pq
		req := httptest.NewRequest("GET", "/xpk/group/cloud-engineering/.well-known/xipher", nil)
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
		req := httptest.NewRequest("GET", "/xpk/user/alice@example.com/.well-known/xipher", nil)
		req.SetPathValue("id", "alice@example.com")
		rec := httptest.NewRecorder()
		s.cfg.PostQuantum = false
		s.servePublicKey(rec, req, entityUser, "User")
		return rec
	}
	if mkReq().Body.String() != mkReq().Body.String() {
		t.Fatal("served public key not deterministic")
	}
}

func TestCallbackAllowed(t *testing.T) {
	s := &Server{cfg: &Config{}}
	s.cfg.AllowedCallbackURLs = []string{"https://xipher.org", "https://xipher.int.example.com"}

	cases := map[string]bool{
		"https://xipher.org/callback":         true,
		"https://xipher.int.example.com/x":    true,
		"https://evil.com":                    false,
		"http://xipher.org":                   false, // scheme mismatch
		"not-a-url":                           false,
	}
	for url, want := range cases {
		if got := s.callbackAllowed(url); got != want {
			t.Errorf("callbackAllowed(%q) = %v, want %v", url, got, want)
		}
	}
}
