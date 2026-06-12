package commands

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"xipher.org/xipher"
	"xipher.org/xipher/internal/utils"
)

const (
	webAuthTimeout          = 3 * time.Minute
	webAuthParamKey         = "xck"
	webAuthParamState       = "state"
	webAuthParamPubKey      = "xwa"
	webAuthParamCB          = "cb"
	webAuthParamAppName     = "appName"
	webAuthParamAppURL      = "appURL"
	xipherWebBaseDefault    = "https://xipher.org"
	xipherAppURL            = "https://xipher.org"
)

// getSecretKeyFromWebAuth starts the browser-assisted unlock flow. It generates
// an ephemeral keypair, opens the browser to baseURL with the public half,
// waits for the web app to seal the user's key and deliver it back, then returns
// the plaintext XSK_ secret key. If baseURL is empty, xipherWebBaseDefault is used.
func getSecretKeyFromWebAuth(baseURL string) (string, error) {
	if baseURL == "" {
		baseURL = xipherWebBaseDefault
	}
	// Strip any trailing slash so URL construction is consistent.
	baseURL = strings.TrimRight(baseURL, "/")
	sk, err := xipher.NewSecretKey()
	if err != nil {
		return "", fmt.Errorf("generating ephemeral key: %w", err)
	}
	ephemeralSecret, err := sk.String()
	if err != nil {
		return "", fmt.Errorf("encoding ephemeral key: %w", err)
	}
	ephemeralPubKey, _, err := utils.GetPublicKey(ephemeralSecret, false)
	if err != nil {
		return "", fmt.Errorf("deriving ephemeral public key: %w", err)
	}

	// 8 random bytes -> 16 hex chars: short enough to compare by eye, still 64
	// bits of entropy (unguessable within the single-use 3-minute window).
	state, err := randomWebAuthToken(8)
	if err != nil {
		return "", fmt.Errorf("generating state token: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("starting local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	cbURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	ctx, cancel := context.WithTimeout(context.Background(), webAuthTimeout)
	defer cancel()

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}

	// The web app is served from baseURL; only that exact origin may call the
	// loopback endpoints cross-origin. setCORS echoes it and answers preflight.
	allowedOrigin := baseURL
	setCORS := func(w http.ResponseWriter) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}

	mux.HandleFunc("/deliver", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.FormValue(webAuthParamState) != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			select {
			case errCh <- fmt.Errorf("state mismatch - possible CSRF"):
			default:
			}
			return
		}
		sealedKey := r.FormValue(webAuthParamKey)
		if sealedKey == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			select {
			case errCh <- fmt.Errorf("no key delivered"):
			default:
			}
			return
		}
		plaintext, err := utils.DecryptData(ephemeralSecret, sealedKey)
		if err != nil {
			http.Error(w, "decryption failed", http.StatusBadRequest)
			select {
			case errCh <- fmt.Errorf("decrypting delivered key: %w", err):
			default:
			}
			return
		}
		xsk := strings.TrimSpace(string(plaintext))
		w.WriteHeader(http.StatusNoContent)
		select {
		case resultCh <- xsk:
		default:
		}
		cancel()
	})

	mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.FormValue(webAuthParamState) != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		select {
		case errCh <- fmt.Errorf("web auth request declined"):
		default:
		}
		cancel()
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, webAuthWaitingPage())
	})

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			select {
			case errCh <- fmt.Errorf("local server error: %w", err):
			default:
			}
		}
	}()
	defer func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutCancel()
		srv.Shutdown(shutCtx) //nolint:errcheck
	}()

	// Identify the requesting app. For CLI, use "Xipher" and the Xipher web app URL.
	appName := "Xipher"
	appURL := xipherAppURL

	browserURL := fmt.Sprintf(
		"%s/web-auth/?%s=%s&%s=%s&%s=%s&%s=%s&%s=%s",
		baseURL,
		webAuthParamPubKey, ephemeralPubKey,
		webAuthParamState, state,
		webAuthParamCB, cbURL,
		webAuthParamAppName, url.QueryEscape(appName),
		webAuthParamAppURL, url.QueryEscape(appURL),
	)

	fmt.Fprintln(os.Stderr, "Opening browser for web authentication...")
	fmt.Fprintf(os.Stderr, "If the browser doesn't open, visit:\n  %s\n", color.New(color.Underline).Sprint(browserURL))
	// Show the state token so the user can confirm the browser page displays the
	// same value before approving - guards against a spoofed/look-alike page.
	fmt.Fprintf(os.Stderr, "\nVerification code: %s\n", color.New(color.Bold).Sprint(state))
	fmt.Fprintln(os.Stderr, "Make sure this matches the code shown in the browser before approving.")

	if err := openBrowser(browserURL); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open browser automatically: %v\n", err)
	}

	select {
	case xsk := <-resultCh:
		return xsk, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("web auth timed out after %s", webAuthTimeout)
	}
}

// randomWebAuthToken returns a hex string of 2*n chars (n random bytes). Hex
// keeps the state token to [0-9a-f] only, so it carries no special characters
// that could trip up display, copy/paste, or URL handling.
func randomWebAuthToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Start()
}

func webAuthWaitingPage() string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Xipher · Authenticating</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;
justify-content:center;min-height:100vh;background:#0a0a0a;color:#e5e5e5}
.card{text-align:center;padding:2.5rem 2rem;border-radius:14px;background:#141414;
border:1px solid #2a2a2a;max-width:380px;width:90%}
h1{font-size:1.3rem;font-weight:600;margin-bottom:.6rem}
p{color:#888;font-size:.9rem;line-height:1.5}
</style></head><body>
<div class="card">
  <h1>Xipher Web Auth</h1>
  <p>Waiting for authentication in your browser&hellip;</p>
</div></body></html>`
}
