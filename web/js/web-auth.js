// web-auth.js - self-contained script for the /web-auth/ page.
// Handles the CLI key-delivery flow: validates ?xwa= params, loads WASM,
// then lets the user deliver their key to the CLI via passkey or stored key.

const WA_PARAM_PUBKEY = "xwa";
const WA_PARAM_STATE  = "state";
const WA_PARAM_CB     = "cb";

const PRELOADER_FADE_MS    = 400;
const TOAST_DEFAULT_DURATION = 2600;
const TOAST_FADE_MS        = 300;

/* ==========================================================================
   Theme (mirrors ui.js - this page doesn't load ui.js)
   ========================================================================== */

function loadTheme() {
    const stored = localStorage.getItem("theme");
    const theme = stored || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
}

const themeToggleBtn = document.getElementById("theme-toggle");
themeToggleBtn && themeToggleBtn.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
});

/* ==========================================================================
   Toast (mirrors ui.js)
   ========================================================================== */

const toastContainer = document.getElementById("toast-container");

function showToast(message, type = "info", duration = TOAST_DEFAULT_DURATION) {
    if (!toastContainer) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    const icons = { success: "✅", error: "⚠️", info: "ℹ️" };
    const icon = document.createElement("span");
    icon.className = "toast-icon";
    icon.textContent = icons[type] || icons.info;
    const text = document.createElement("span");
    text.textContent = message;
    toast.appendChild(icon);
    toast.appendChild(text);
    toastContainer.appendChild(toast);
    void toast.offsetWidth;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), TOAST_FADE_MS);
    }, duration);
}

/* ==========================================================================
   Preloader
   ========================================================================== */

const preloader = document.getElementById("preloader");

function hidePreloader() {
    preloader.classList.add("hidden");
    setTimeout(() => preloader.remove(), PRELOADER_FADE_MS);
}

/* ==========================================================================
   DOM refs
   ========================================================================== */

const innerEl        = document.getElementById("web-auth-inner");
const errorEl        = document.getElementById("web-auth-error");
const errorMsg       = document.getElementById("wa-error-message");
const statusEl       = document.getElementById("wa-status");
const allowBtn       = document.getElementById("wa-allow");
const denyBtn        = document.getElementById("wa-deny");
const verifyEl       = document.getElementById("wa-verify");
const verifyCodeEl   = document.getElementById("wa-verify-code");
const resultEl       = document.getElementById("web-auth-result");
const resultIconEl   = document.getElementById("wa-result-icon");
const resultTitleEl  = document.getElementById("wa-result-title");
const resultMsgEl    = document.getElementById("wa-result-message");

// Swaps the request card for a terminal result card (Approved / Declined).
function showResult(kind, title, message) {
    innerEl.hidden = true;
    errorEl.hidden = true;
    resultIconEl.textContent = kind === "ok" ? "✓" : "✕";
    resultIconEl.className = "web-auth-result-icon " + (kind === "ok" ? "ok" : "declined");
    resultTitleEl.textContent = title;
    resultMsgEl.textContent = message;
    resultEl.hidden = false;
}

/* ==========================================================================
   Helpers
   ========================================================================== */

// isLoopbackHost mirrors the same function in main.js.
function isLoopbackHost(host) {
    host = (host || "").toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
}

// canonicalLoopback maps a parsed hostname to a fixed loopback literal, or
// returns "" if it isn't a recognised loopback host. Returning a constant (not
// the input) means callers build redirect URLs purely from trusted literals.
function canonicalLoopback(host) {
    switch ((host || "").toLowerCase()) {
        case "localhost":  return "localhost";
        case "127.0.0.1":  return "127.0.0.1";
        case "::1":
        case "[::1]":      return "[::1]";
        default:           return "";
    }
}

function parseParams() {
    const p = new URLSearchParams(window.location.search);
    const pubKey = p.get(WA_PARAM_PUBKEY);
    const state  = p.get(WA_PARAM_STATE);
    const cb     = p.get(WA_PARAM_CB);
    if (!pubKey || !state || !cb) return null;
    if (!pubKey.startsWith("XPK_")) return null;
    let cbUrl;
    try { cbUrl = new URL(cb); } catch (e) { return null; }
    if (cbUrl.protocol !== "http:") return null;
    // Map the parsed host to a fixed canonical literal - the redirect base is then
    // built entirely from constants (scheme + literal host) plus a numeric port,
    // so no user-controlled string ever flows into window.location. Anything that
    // isn't an exact loopback match is rejected.
    const host = canonicalLoopback(cbUrl.hostname);
    if (!host) return null;
    // Port must be a plain integer in range; reject anything else.
    const portNum = cbUrl.port === "" ? 0 : Number(cbUrl.port);
    if (!Number.isInteger(portNum) || portNum < 0 || portNum > 65535) return null;
    const cbBase = "http://" + host + (portNum ? ":" + portNum : "");
    return { pubKey, state, cbBase };
}

function setStatus(msg) {
    statusEl.textContent = msg;
}

function setBusy(busy) {
    allowBtn.disabled = busy;
    denyBtn.disabled = busy;
}

function resetButtons() {
    setBusy(false);
}

function showError(msg) {
    errorMsg.textContent = msg || "This page must be opened by the Xipher CLI.";
    errorEl.hidden = false;
    hidePreloader();
}

// POSTs to a loopback endpoint on the CLI. Body is form-encoded so the CLI reads
// it with r.FormValue. The sealed key never appears in a URL (no history, no
// Referer, no access log). Throws on a non-2xx response.
async function postToCli(cbBase, path, fields) {
    const body = new URLSearchParams(fields);
    const res = await fetch(new URL(path, cbBase).href, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
    });
    if (!res.ok) {
        throw new Error("CLI responded with " + res.status);
    }
}

async function deliverKey(params, xsk) {
    const sealed = await encryptStr(params.pubKey, xsk);
    await postToCli(params.cbBase, "/deliver", {
        xck: sealed,
        state: params.state,
    });
}

/* ==========================================================================
   Main
   ========================================================================== */

async function main() {
    loadTheme();

    const params = parseParams();
    // Remove params from the address bar so a refresh can't replay the flow.
    history.replaceState(null, "", window.location.pathname);

    if (!params) {
        showError("This page must be opened by the Xipher CLI (missing or invalid parameters).");
        return;
    }

    await loadXipherWASM();

    // Idle-expiry: drop a stored key/identity unused for over a week, same as the
    // main app. A wiped browser then has no credential to deliver and falls into
    // the "no credential configured" branch below.
    enforceIdleExpiry();

    const existingKey = await getExistingXipherSecret();
    const identity    = getIdentity();

    // A passkey leaves provider="passkey" in storage but no stored key (the
    // derived key is never persisted): Allow re-derives it via the authenticator.
    // Any other credential (stored key, password, provider) is also resolvable on
    // Allow. Only a truly blank browser has nothing to deliver.
    const passkeyIdentity = identity.provider === "passkey";
    const hasCredential   = !!existingKey || passkeyIdentity;

    if (!hasCredential) {
        showError("No credential is configured in this browser. Set one up at xipher.org first.");
        return;
    }

    // Surface the state token so the user can compare it with the one the CLI
    // printed in the terminal before approving - a spoofed page won't know it.
    verifyCodeEl.textContent = params.state;
    verifyEl.hidden = false;

    allowBtn.hidden = false;
    setStatus("Approve the CLI to use your key, or decline the request.");

    // Deny: tell the CLI the request was declined, then show the declined result.
    denyBtn.addEventListener("click", async () => {
        setBusy(true);
        setStatus("Declining…");
        try {
            await postToCli(params.cbBase, "/cancel", { state: params.state });
        } catch (err) {
            // The CLI may have already shut down; the decline still stands.
        }
        showResult("declined", "Declined", "The request was declined. You can close this tab.");
    });

    // Allow: resolve the configured credential to an XSK_ and deliver it.
    allowBtn.addEventListener("click", async () => {
        setBusy(true);
        try {
            let xsk;
            if (existingKey) {
                // Stored key/password/persisted passkey/provider: use it directly.
                setStatus("Retrieving your key…");
                xsk = existingKey;
            } else {
                // Non-persisted passkey: re-derive from the authenticator. Use the
                // stored credential ID when known, else the discoverable picker.
                setStatus("Waiting for your passkey…");
                const prfOutput = await authenticatePasskey(getStoredCredentialId());
                xsk = await seedKeyFromPrf(prfOutput);
            }
            setStatus("Delivering to CLI…");
            await deliverKey(params, xsk);
            showResult("ok", "Approved", "Your key has been delivered to the CLI. You can close this tab.");
        } catch (err) {
            if (err && err.name === "PRFNotSupported") {
                setStatus("That passkey can't derive a key. Try your device's built-in passkey (Touch ID / Windows Hello).");
                showToast("Authenticator doesn't support key derivation (PRF).", "error", 4000);
            } else if (err && err.name === "NotAllowedError") {
                setStatus("Passkey cancelled.");
            } else {
                showToast("Failed to deliver key.", "error");
                setStatus("Failed: " + (err.message || "unknown error"));
            }
            resetButtons();
        }
    });

    innerEl.hidden = false;
    hidePreloader();
}

main();
