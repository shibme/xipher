package kms

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

// securityHeaders wraps a handler and applies a strict, locked-down set of
// security headers to every response. The consent page sets its own
// per-request CSP (with a script nonce) and so is exempted from the default
// CSP here; everything else gets the restrictive default.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		// The consent page is the only HTML document served; it sets its own
		// CSP with a nonce. JSON/text endpoints get a maximally strict CSP that
		// forbids loading or executing anything.
		if r.URL.Path != "/consent" {
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

// allowPublicCORS sets permissive CORS headers for the public /xpk/ public-key
// endpoints so any origin's browser JS (e.g. the xipher web app) may read them.
// Public keys carry no authentication, so credentials are never allowed.
func allowPublicCORS(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	h.Set("Vary", "Origin")
}

// nonceB64 returns 16 random bytes as standard base64, suitable for a CSP
// script nonce.
func nonceB64() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// scriptSafeJSON escapes a JSON byte string for safe embedding inside an
// inline <script> block. JSON is valid JS, but a literal "<", ">", or "&" can
// prematurely close the script element or be reinterpreted by the HTML parser,
// so they are replaced with unicode escapes that JSON parses back unchanged.
func scriptSafeJSON(b []byte) string {
	r := strings.NewReplacer(
		"<", "\\u003c",
		">", "\\u003e",
		"&", "\\u0026",
	)
	return r.Replace(string(b))
}
