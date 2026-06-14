package kms

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"xipher.org/xipher"
)

const (
	// OIDC code-flow round-trip carries the opaque provider-state id in the
	// oauth2 "state" parameter.
	queryState = "state"

	// xipher provider params (incoming from the xipher app to /login).
	providerParamXPK = "xpk"
	providerParamSt  = "state"
	providerParamXCB = "xcb"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// handleLogin initiates the OIDC code flow for the browser provider flow. It
// validates the xipher callback (xcb) against the allowlist, stores the
// provider params server-side, and redirects to the IdP.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	xpk := q.Get(providerParamXPK)
	xst := q.Get(providerParamSt)
	xcb := q.Get(providerParamXCB)

	if xpk == "" || xcb == "" {
		http.Error(w, "missing xpk or xcb", http.StatusBadRequest)
		return
	}
	if !xipher.IsPubKeyStr(xpk) {
		http.Error(w, "invalid xpk", http.StatusBadRequest)
		return
	}
	if !s.callbackAllowed(xcb) {
		http.Error(w, "callback url not allowed", http.StatusBadRequest)
		return
	}

	id, err := s.putState(providerState{xpk: xpk, state: xst, xcb: xcb})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.auth.oauth2.AuthCodeURL(id), http.StatusFound)
}

// handleCallback completes the OIDC code exchange, then redirects the browser
// to the consent page with the id token in the URL fragment (never sent to
// the server) along with the provider-state id.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	stateID := r.URL.Query().Get(queryState)
	if code == "" || stateID == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	oauth2Token, err := s.auth.oauth2.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "code exchange failed", http.StatusBadGateway)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "no id_token in token response", http.StatusBadGateway)
		return
	}
	if _, err := s.auth.verify(ctx, rawIDToken); err != nil {
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}

	// Pass token + state to the consent page via fragment only.
	frag := url.Values{}
	frag.Set("token", rawIDToken)
	frag.Set(queryState, stateID)
	http.Redirect(w, r, "/consent#"+frag.Encode(), http.StatusFound)
}

// handleConsent serves the embedded consent page with the claim mapping
// injected so the page knows which claims map to which entity type. A fresh
// per-request nonce authorizes the two inline scripts under a strict CSP, so
// the page allows no other inline or remote script to execute.
func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	nonce, err := nonceB64()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	claims, _ := json.Marshal(map[string]string{
		"user":    s.cfg.Claims.User,
		"group":   s.cfg.Claims.Group,
		"service": s.cfg.Claims.Service,
	})

	// Tag the page's own inline <script> with the nonce so it is allowed by CSP.
	page := strings.Replace(string(consentPage), "<script>", `<script nonce="`+nonce+`">`, 1)
	inject := `<script nonce="` + nonce + `">window.__XKMS_CLAIMS__=` + scriptSafeJSON(claims) + `;</script>` + "\n"

	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; "+
			"script-src 'nonce-"+nonce+"'; "+
			"style-src 'unsafe-inline'; "+
			"connect-src 'self'; "+
			"img-src 'self' data:; "+
			"base-uri 'none'; "+
			"frame-ancestors 'none'; "+
			"form-action 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(inject))
	w.Write([]byte(page))
}

// --- Credential endpoints -------------------------------------------------

func (s *Server) handleCredentialUser(w http.ResponseWriter, r *http.Request) {
	s.serveCredential(w, r, entityUser, "")
}

func (s *Server) handleCredentialService(w http.ResponseWriter, r *http.Request) {
	s.serveCredential(w, r, entityService, "")
}

func (s *Server) handleCredentialGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		http.Error(w, "missing group name", http.StatusBadRequest)
		return
	}
	s.serveCredential(w, r, entityGroup, name)
}

// --- Public key endpoints (unauthenticated) -------------------------------

// handlePublicKeyPreflight answers CORS preflight for the public /xpk/ tree.
func (s *Server) handlePublicKeyPreflight(w http.ResponseWriter, r *http.Request) {
	allowPublicCORS(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePublicKeyUser(w http.ResponseWriter, r *http.Request) {
	s.servePublicKey(w, r, entityUser, "User")
}

func (s *Server) handlePublicKeyGroup(w http.ResponseWriter, r *http.Request) {
	s.servePublicKey(w, r, entityGroup, "Group")
}

func (s *Server) handlePublicKeyService(w http.ResponseWriter, r *http.Request) {
	s.servePublicKey(w, r, entityService, "Service")
}

// servePublicKey derives the entity's secret key from its identity (taken
// straight from the path, no auth) and serves the corresponding public key in
// the xipher resolver JSON format. The key kind (ECC vs post-quantum hybrid)
// follows the post_quantum config. Public keys are safe to expose openly.
func (s *Server) servePublicKey(w http.ResponseWriter, r *http.Request, entityType, label string) {
	allowPublicCORS(w)

	entityID := r.PathValue("id")
	if entityID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	seed, err := deriveSeed(s.seed, entityType, entityID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sk, err := secretKeyFromSeed(seed)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pub, err := sk.PublicKey(s.cfg.PostQuantum)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pubStr, err := pub.String()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"name":      label + " - " + entityID,
		"publicKey": pubStr,
	})
}

// serveCredential validates the JWT, resolves the requested identity, derives
// the credential, and either seals+redirects (browser provider flow when xpk
// is present) or returns the credential JSON directly (direct service flow).
func (s *Server) serveCredential(w http.ResponseWriter, r *http.Request, entityType, groupName string) {
	ctx := r.Context()

	rawToken := s.extractToken(r)
	if rawToken == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	claims, err := s.auth.verify(ctx, rawToken)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Resolve the requested entity id from the token claims.
	entityID, name, err := s.resolveEntityID(claims, entityType, groupName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	seed, err := deriveSeed(s.seed, entityType, entityID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	cred, err := s.buildCredential(seed, entityType, entityID, name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Browser provider flow: a provider-state id seals the credential to the
	// ephemeral xpk and returns a redirect URL back to the xipher app (xcb).
	if stateID := r.URL.Query().Get(queryState); stateID != "" {
		s.respondSealed(w, stateID, cred)
		return
	}

	// Direct service/API flow: return the credential JSON.
	writeJSON(w, http.StatusOK, cred)
}

// resolveEntityID returns the entity id (and display name) for the requested
// type, verifying it is present in the token claims.
func (s *Server) resolveEntityID(claims map[string]any, entityType, groupName string) (string, string, error) {
	name := stringClaim(claims, "name")
	switch entityType {
	case entityUser:
		v := stringClaim(claims, s.cfg.Claims.User)
		if v == "" {
			return "", "", fmt.Errorf("token has no user identity")
		}
		return v, name, nil
	case entityService:
		v := stringClaim(claims, s.cfg.Claims.Service)
		if v == "" {
			return "", "", fmt.Errorf("token has no service identity")
		}
		return v, name, nil
	case entityGroup:
		groups := stringSliceClaim(claims, s.cfg.Claims.Group)
		if !slices.Contains(groups, groupName) {
			return "", "", fmt.Errorf("token is not a member of group %q", groupName)
		}
		return groupName, name, nil
	default:
		return "", "", fmt.Errorf("unknown entity type")
	}
}

// buildCredential encodes the derived seed per the configured credential type.
func (s *Server) buildCredential(seed []byte, entityType, entityID, name string) (*credential, error) {
	cred := &credential{Type: entityType, ID: entityID, Name: name}
	t := s.cfg.Credential.Type
	if t == credTypeSeed || t == credTypeBoth {
		cred.Seed = base64.StdEncoding.EncodeToString(seed)
	}
	if t == credTypeKey || t == credTypeBoth {
		sk, err := secretKeyFromSeed(seed)
		if err != nil {
			return nil, err
		}
		keyStr, err := sk.String()
		if err != nil {
			return nil, err
		}
		cred.Key = keyStr
	}
	return cred, nil
}

// respondSealed seals the credential JSON to the ephemeral xpk stored under
// stateID and returns the xipher-app redirect URL (xcb#xck=...&state=...).
func (s *Server) respondSealed(w http.ResponseWriter, stateID string, cred *credential) {
	st, ok := s.takeState(stateID)
	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	payload, err := json.Marshal(cred)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	pub, err := xipher.ParsePublicKeyStr(st.xpk)
	if err != nil {
		http.Error(w, "invalid xpk", http.StatusBadRequest)
		return
	}
	sealed, err := pub.Encrypt(payload, true, true)
	if err != nil {
		http.Error(w, "sealing failed", http.StatusInternalServerError)
		return
	}

	frag := url.Values{}
	frag.Set("xck", string(sealed))
	if st.state != "" {
		frag.Set("state", st.state)
	}
	redirect := strings.TrimRight(st.xcb, "/") + "#" + frag.Encode()
	writeJSON(w, http.StatusOK, map[string]string{"redirect": redirect})
}

// extractToken pulls the raw OIDC JWT from the configured auth header.
func (s *Server) extractToken(r *http.Request) string {
	v := r.Header.Get(s.cfg.AuthHeader.Name)
	if v == "" {
		return ""
	}
	if s.cfg.AuthHeader.Type == authHeaderBearer {
		if after, ok := strings.CutPrefix(v, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
		return ""
	}
	return strings.TrimSpace(v)
}

// callbackAllowed reports whether xcb matches one of the configured allowed
// callback URLs by origin (scheme + host) prefix.
func (s *Server) callbackAllowed(xcb string) bool {
	u, err := url.Parse(xcb)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	for _, allowed := range s.cfg.AllowedCallbackURLs {
		a, err := url.Parse(allowed)
		if err != nil {
			continue
		}
		if u.Scheme == a.Scheme && u.Host == a.Host {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
