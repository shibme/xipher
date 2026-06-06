package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"xipher.org/xipher"
)

const (
	keyURLPrefix     = "https://"
	wellKnownKeyPath = "/.well-known/xipher"
	maxKeyRespBytes  = 8 << 10 // 8 KiB is plenty for an XPK_ string.
	maxKeyNameLen    = 64
	keyFetchTimeout  = 10 * time.Second
	maxKeyRedirects  = 5
	keyCacheTTL      = 60 * time.Second
)

var (
	errInsecureKeyURL   = errors.New("only https:// URLs are supported for public key resolution")
	errBadKeyResponse   = errors.New("the URL did not serve a valid public key")
	errKeyResponseLarge = errors.New("public key response exceeded the size limit")
)

// publishedKey is the JSON document a host may serve to publish its public key
// along with a friendly, display-only name.
type publishedKey struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

// domainRegex matches a bare host (optionally with a path) that has no URL
// scheme, e.g. "alice.com" or "alice.com/keys". It requires at least one dot in
// the host and a valid TLD-like label so ordinary passwords are not misread as
// domains.
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?$`)

// schemeRegex matches a leading URL scheme such as "http://" or "https://".
var schemeRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// isKeyURL reports whether raw is an https:// key-serving URL reference.
func isKeyURL(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), keyURLPrefix)
}

// hasScheme reports whether raw already carries a URL scheme (e.g. "http://",
// "https://", "ftp://").
func hasScheme(raw string) bool {
	return schemeRegex.MatchString(strings.TrimSpace(raw))
}

// looksLikeDomain reports whether raw is a schemeless host that could be fetched
// as an https key URL (e.g. "alice.com" or "alice.com/keys"). It is used to
// decide whether to prompt the user; it never auto-fetches.
func looksLikeDomain(raw string) bool {
	raw = strings.TrimSpace(raw)
	return !hasScheme(raw) && domainRegex.MatchString(raw)
}

// schemelessHost extracts the host (without port or path) from a schemeless
// authority string such as "localhost:8771/path" or "127.0.0.1".
func schemelessHost(raw string) string {
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw = raw[:i]
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return raw
}

// normaliseKeyURL prepends a scheme to a schemeless host so it can be fetched:
// "http://" for loopback hosts (local development) and "https://" otherwise. An
// input that already has a scheme is returned unchanged (and is rejected later
// if its scheme is not allowed).
func normaliseKeyURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if hasScheme(raw) {
		return raw
	}
	if isLoopbackHost(schemelessHost(raw)) {
		return "http://" + raw
	}
	return keyURLPrefix + raw
}

type keyCacheEntry struct {
	pubKey  string
	name    string
	expires time.Time
}

var (
	keyCacheMu sync.Mutex
	keyCache   = make(map[string]keyCacheEntry)
)

var keyFetchClient = &http.Client{
	Timeout: keyFetchTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxKeyRedirects {
			return fmt.Errorf("stopped after %d redirects", maxKeyRedirects)
		}
		if !isSchemeAllowed(req.URL) {
			return errInsecureKeyURL
		}
		return nil
	},
}

// isLoopbackHost reports whether host is a loopback address (localhost,
// 127.0.0.0/8, or ::1), for which plain http is permitted (local development).
func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isSchemeAllowed reports whether u may be fetched: https everywhere, or http
// when the host is a loopback address (for local development/testing).
func isSchemeAllowed(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return true
	}
	return false
}

// keyURLCandidates validates the scheme of rawURL (https, or http for loopback
// hosts) and returns the URLs to try, in order:
//   - A bare host (no path) yields a single candidate at the well-known key path
//     (RFC 8615), e.g. "alice.com" -> "https://alice.com/.well-known/xipher".
//   - A path-bearing URL is tried verbatim first, then with the well-known path
//     appended, e.g. "alice.com/shib" -> ["https://alice.com/shib",
//     "https://alice.com/shib/.well-known/xipher"]. This lets a URL point either
//     directly at a key file or at a path that hosts one under .well-known.
func keyURLCandidates(rawURL string) ([]string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid public key URL: %w", err)
	}
	if !isSchemeAllowed(u) {
		return nil, errInsecureKeyURL
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = wellKnownKeyPath
		return []string{u.String()}, nil
	}
	verbatim := u.String()
	wk := *u
	wk.Path = strings.TrimRight(u.Path, "/") + wellKnownKeyPath
	return []string{verbatim, wk.String()}, nil
}

// sanitiseName trims, strips control characters from, and length-caps an
// untrusted display name served by a remote host.
func sanitiseName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	if len(name) > maxKeyNameLen {
		// Cap by runes to avoid splitting a multi-byte character.
		runes := []rune(name)
		if len(runes) > maxKeyNameLen {
			runes = runes[:maxKeyNameLen]
		}
		name = string(runes)
	}
	return name
}

// parsePublishedKey extracts an XPK_ public key (and optional display name) from
// a fetched response body. It tries the JSON document form first and falls back
// to treating the whole body as a bare XPK_ string.
func parsePublishedKey(body []byte) (pubKey, name string, err error) {
	var doc publishedKey
	if jsonErr := json.Unmarshal(body, &doc); jsonErr == nil {
		if pk := strings.TrimSpace(doc.PublicKey); xipher.IsPubKeyStr(pk) {
			return pk, sanitiseName(doc.Name), nil
		}
	}
	if pk := strings.TrimSpace(string(body)); xipher.IsPubKeyStr(pk) {
		return pk, "", nil
	}
	return "", "", errBadKeyResponse
}

// fetchOneURL fetches and parses the public key at a single resolved URL.
func fetchOneURL(resolvedURL string) (pubKey, name string, err error) {
	keyCacheMu.Lock()
	if entry, ok := keyCache[resolvedURL]; ok && time.Now().Before(entry.expires) {
		keyCacheMu.Unlock()
		return entry.pubKey, entry.name, nil
	}
	keyCacheMu.Unlock()

	resp, err := keyFetchClient.Get(resolvedURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch public key from %s: %w", resolvedURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("failed to fetch public key from %s: unexpected status %s", resolvedURL, resp.Status)
	}

	// Read one byte past the limit so we can detect oversize responses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyRespBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("failed to read public key from %s: %w", resolvedURL, err)
	}
	if len(body) > maxKeyRespBytes {
		return "", "", errKeyResponseLarge
	}

	pubKey, name, err = parsePublishedKey(body)
	if err != nil {
		return "", "", err
	}

	keyCacheMu.Lock()
	keyCache[resolvedURL] = keyCacheEntry{pubKey: pubKey, name: name, expires: time.Now().Add(keyCacheTTL)}
	keyCacheMu.Unlock()

	return pubKey, name, nil
}

// fetchPublicKey resolves an https:// URL to the XPK_ public key it serves, along
// with an optional display name. A bare host is probed at the well-known path; a
// path-bearing URL is tried verbatim and then with the well-known path appended.
// It hard-errors on any failure and never falls back to other interpretations of
// the input.
func fetchPublicKey(rawURL string) (pubKey, name string, err error) {
	candidates, err := keyURLCandidates(rawURL)
	if err != nil {
		return "", "", err
	}
	for _, candidate := range candidates {
		// Try each candidate (e.g. the well-known fallback) in turn; the last
		// candidate's error is the one returned if none succeed.
		pubKey, name, err = fetchOneURL(candidate)
		if err == nil {
			return pubKey, name, nil
		}
	}
	return "", "", err
}

// LooksLikeDomain reports whether raw is a schemeless host (e.g. "alice.com")
// that could be fetched as an https key URL. Callers use this to decide whether
// to ask the user before treating the input as a URL rather than a password.
func LooksLikeDomain(raw string) bool {
	return looksLikeDomain(raw)
}

// FetchPublicKeyFromURL fetches the public key served at rawURL, prepending
// "https://" when the input has no scheme. It is the explicit, no-guessing entry
// point used when the caller already knows the input is a URL (e.g. a --url
// flag or a confirmed prompt). A non-https scheme is rejected.
func FetchPublicKeyFromURL(rawURL string) (pubKey, name string, err error) {
	return fetchPublicKey(normaliseKeyURL(rawURL))
}
