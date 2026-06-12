// web-auth.js — self-contained script for the /web-auth/ page.
// Handles the CLI key-delivery flow: validates ?xwa= params, loads WASM,
// then lets the user deliver their key to the CLI via passkey or stored key.

const WA_PARAM_PUBKEY = "xwa";
const WA_PARAM_STATE  = "state";
const WA_PARAM_CB     = "cb";

const PRELOADER_FADE_MS    = 400;
const TOAST_DEFAULT_DURATION = 2600;
const TOAST_FADE_MS        = 300;

/* ==========================================================================
   Theme (mirrors ui.js — this page doesn't load ui.js)
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
const useCurrentBtn  = document.getElementById("wa-use-current");
const usePasskeyBtn  = document.getElementById("wa-use-passkey");
const cancelBtn      = document.getElementById("wa-cancel");

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
    // Map the parsed host to a fixed canonical literal — the redirect base is then
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
    useCurrentBtn.disabled = busy;
    usePasskeyBtn.disabled = busy;
    if (cancelBtn) cancelBtn.disabled = busy;
}

function resetButtons() {
    setBusy(false);
}

function showError(msg) {
    errorMsg.textContent = msg || "This page must be opened by the Xipher CLI.";
    errorEl.hidden = false;
    hidePreloader();
}

async function deliverKey(params, xsk) {
    const sealed = await encryptStr(params.pubKey, xsk);
    const theme = document.documentElement.getAttribute("data-theme") || "light";
    const url = new URL("/deliver", params.cbBase);
    url.searchParams.set("xck", sealed);
    url.searchParams.set("state", params.state);
    url.searchParams.set("theme", theme);
    window.location.replace(url.href);
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

    const existingKey = await getExistingXipherSecret();
    const passkeyOk   = await isPlatformAuthenticatorAvailable();

    if (!existingKey && !passkeyOk) {
        showError("No key or passkey found in this browser. Set one up at xipher.org first.");
        return;
    }

    useCurrentBtn.hidden = !existingKey;
    usePasskeyBtn.hidden = !passkeyOk;

    setStatus(existingKey
        ? "Use your current browser key, or authenticate with a different passkey."
        : "Authenticate with your passkey to send your key to the CLI.");

    cancelBtn && cancelBtn.addEventListener("click", () => {
        const theme = document.documentElement.getAttribute("data-theme") || "light";
        const url = new URL("/cancel", params.cbBase);
        url.searchParams.set("state", params.state);
        url.searchParams.set("theme", theme);
        window.location.replace(url.href);
    });

    useCurrentBtn.addEventListener("click", async () => {
        setBusy(true);
        setStatus("Retrieving your key…");
        try {
            const xsk = await getExistingXipherSecret();
            if (!xsk) throw new Error("No key found.");
            setStatus("Delivering to CLI…");
            await deliverKey(params, xsk);
        } catch (err) {
            showToast("Failed to deliver key.", "error");
            setStatus("Failed: " + (err.message || "unknown error"));
            resetButtons();
        }
    });

    usePasskeyBtn.addEventListener("click", async () => {
        setBusy(true);
        setStatus("Waiting for your passkey…");
        try {
            const prfOutput = await authenticatePasskey(getStoredCredentialId());
            const xsk = await seedKeyFromPrf(prfOutput);
            setStatus("Delivering to CLI…");
            await deliverKey(params, xsk);
        } catch (err) {
            if (err && err.name === "PRFNotSupported") {
                setStatus("That passkey can't derive a key. Try your device's built-in passkey (Touch ID / Windows Hello).");
                showToast("Authenticator doesn't support key derivation (PRF).", "error", 4000);
            } else if (err && err.name === "NotAllowedError") {
                setStatus("Passkey cancelled.");
            } else {
                setStatus("Passkey failed: " + (err.message || "unknown error"));
                showToast("Passkey authentication failed.", "error");
            }
            resetButtons();
        }
    });

    innerEl.hidden = false;
    hidePreloader();
}

main();
