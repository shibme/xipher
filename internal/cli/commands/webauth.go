package commands

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
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
	webAuthTimeout         = 3 * time.Minute
	webAuthParamKey        = "xck"
	webAuthParamState      = "state"
	webAuthParamPubKey     = "xwa"
	webAuthParamCB         = "cb"
	xipherWebBaseDefault   = "https://xipher.org"
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

	state, err := randomWebAuthToken(18)
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

	mux.HandleFunc("/deliver", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get(webAuthParamState) != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			select {
			case errCh <- fmt.Errorf("state mismatch — possible CSRF"):
			default:
			}
			return
		}
		sealedKey := q.Get(webAuthParamKey)
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, webAuthSuccessPage(q.Get("theme") == "dark"))
		select {
		case resultCh <- xsk:
		default:
		}
		cancel()
	})

	mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(webAuthParamState) != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, webAuthCancelledPage(r.URL.Query().Get("theme") == "dark"))
		select {
		case errCh <- fmt.Errorf("cancelled"):
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

	browserURL := fmt.Sprintf(
		"%s/web-auth/?%s=%s&%s=%s&%s=%s",
		baseURL,
		webAuthParamPubKey, ephemeralPubKey,
		webAuthParamState, state,
		webAuthParamCB, cbURL,
	)

	fmt.Fprintln(os.Stderr, "Opening browser for web authentication...")
	fmt.Fprintf(os.Stderr, "If the browser doesn't open, visit:\n  %s\n", color.HiCyanString(browserURL))

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

func randomWebAuthToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
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

func webAuthSuccessPage(dark bool) string {
	theme := "light"
	bg, surface, border, text, muted := "#eef2f7", "#ffffff", "#d7dee8", "#1c2430", "#5a6677"
	if dark {
		theme = "dark"
		bg, surface, border, text, muted = "#0b0e14", "#151a23", "#2a323f", "#e7ecf3", "#a3afc0"
	}
	return fmt.Sprintf(`<!DOCTYPE html><html lang="en" data-theme="%s"><head><meta charset="utf-8">
<title>Xipher · Done</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;
justify-content:center;min-height:100vh;background:%s;color:%s}
.card{text-align:center;padding:2.5rem 2rem;border-radius:14px;background:%s;
border:1px solid %s;max-width:380px;width:90%%}
.check{font-size:2.5rem;margin-bottom:1rem;color:#1faa53}
h1{font-size:1.3rem;font-weight:600;margin-bottom:.6rem}
p{color:%s;font-size:.9rem;line-height:1.5}
</style></head><body>
<div class="card">
  <div class="check">&#10003;</div>
  <h1>Authenticated</h1>
  <p>Your key has been delivered to the CLI.<br>You can close this tab.</p>
</div></body></html>`, theme, bg, text, surface, border, muted)
}

func webAuthCancelledPage(dark bool) string {
	bg, surface, border, text, muted := "#eef2f7", "#ffffff", "#d7dee8", "#1c2430", "#5a6677"
	if dark {
		bg, surface, border, text, muted = "#0b0e14", "#151a23", "#2a323f", "#e7ecf3", "#a3afc0"
	}
	return fmt.Sprintf(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Xipher · Cancelled</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;
justify-content:center;min-height:100vh;background:%s;color:%s}
.card{text-align:center;padding:2.5rem 2rem;border-radius:14px;background:%s;
border:1px solid %s;max-width:380px;width:90%%}
.icon{font-size:2.5rem;margin-bottom:1rem}
h1{font-size:1.3rem;font-weight:600;margin-bottom:.6rem}
p{color:%s;font-size:.9rem;line-height:1.5}
</style></head><body>
<div class="card">
  <div class="icon">✕</div>
  <h1>Cancelled</h1>
  <p>The CLI web auth request was cancelled.<br>You can close this tab.</p>
</div></body></html>`, bg, text, surface, border, muted)
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
