// provider.js powers the optional "credential provider" flow: an external
// auth/credential provider can authenticate a user and hand their xipher secret
// key back to this app. This is an opt-in managed-identity path; self-generated
// keys remain the default. See the docs for the wire protocol.
//
// The exchange follows the OAuth Authorization Code shape, repurposed to deliver
// a secret key instead of a token:
//
//   1. Initiate. The app is opened with ?provider=<url>. We generate a fresh
//      ephemeral keypair, store its SECRET half locally bound to a random state
//      (see createProviderExchange in datastore.js), then prompt for consent
//      naming the destination host and redirect to the provider with the
//      ephemeral PUBLIC key, the state, and our callback URL.
//   2. The provider authenticates the user, checks our callback against its
//      pre-registered allowlist, seals the user's secret key to our public key,
//      and redirects back to the callback with the sealed blob and the same state.
//   3. Return. We look up the state (single-use; absent/expired is rejected),
//      decrypt the blob with the matching ephemeral secret, prompt a second time
//      to warn the key will replace the existing one (offering to back it up),
//      and store it as the active identity.
//
// The return payload travels in the URL fragment (#...), which is never sent to
// servers or leaked via Referer, and the whole flow uses top-level navigation,
// so it needs no relaxation of the app's strict connect-src CSP.

// Query parameters we send to the provider.
const PROVIDER_REQ_PUBKEY = "xipher_public_key";
const PROVIDER_REQ_STATE = "state";
const PROVIDER_REQ_CALLBACK = "xipher_callback";

// Fragment parameters the provider returns on the callback URL.
const PROVIDER_RES_KEY = "xck"; // sealed secret key (XCT_…)
const PROVIDER_RES_ERR = "xperr"; // failure reason code
const PROVIDER_RES_STATE = "state";

// Largest outbound provider URL we send with the hybrid public key before
// falling back to the compact X25519 key. Browsers allow far more, but provider
// servers/proxies commonly cap the request line at 4 KB or 8 KB; staying under
// 4 KB keeps us comfortably within the stricter tier.
const PROVIDER_URL_BUDGET = 4000;

// callbackUrl is the absolute app URL the provider must redirect back to (and
// pre-register). It is the current page without any query string or fragment.
function callbackUrl() {
    return window.location.origin + window.location.pathname;
}

// buildProviderUrl constructs the outbound redirect URL carrying the ephemeral
// public key, the state, and our callback. Existing query parameters on the
// provider URL are preserved.
function buildProviderUrl(providerUrl, publicKey, state) {
    const target = new URL(providerUrl);
    target.searchParams.set(PROVIDER_REQ_PUBKEY, publicKey);
    target.searchParams.set(PROVIDER_REQ_STATE, state);
    target.searchParams.set(PROVIDER_REQ_CALLBACK, callbackUrl());
    return target.toString();
}

// normalizeProviderUrl applies the same scheme rules as key URLs (see main.js):
// https anywhere, http only for loopback hosts, bare domains promoted to https.
// Returns the absolute URL string, or null if not permitted.
function normalizeProviderUrl(value) {
    if (!value) {
        return null;
    }
    value = value.trim();
    if (isFetchableUrl(value)) {
        return value;
    }
    if (!SCHEME_REGEX.test(value)) {
        const host = value.split("/")[0].split(":")[0];
        if (isLoopbackHost(host)) {
            return "http://" + value;
        }
        if (DOMAIN_REGEX.test(value)) {
            return "https://" + value;
        }
    }
    return null;
}

// Maps a provider-returned error code to a user-facing message.
function providerErrorMessage(reason) {
    switch (reason) {
        case "denied":
            return "The credential provider denied the request.";
        case "auth":
            return "Authentication with the credential provider failed.";
        case "callback":
            return "The provider rejected this app's callback URL. It may not be registered with the provider.";
        default:
            return "The credential provider could not issue a key.";
    }
}

/* ==========================================================================
   Consent modal (shared by the before-redirect and after-return prompts)
   ========================================================================== */

const providerModal = document.getElementById("provider-modal");
const providerModalTitle = document.getElementById("provider-modal-title");
const providerModalMessage = document.getElementById("provider-modal-message");
const providerModalDetail = document.getElementById("provider-modal-detail");
const providerModalDetailValue = document.getElementById("provider-modal-detail-value");
const providerModalDetailCopy = document.getElementById("provider-modal-detail-copy");
const providerModalConfirm = document.getElementById("provider-modal-confirm");
const providerModalCancel = document.getElementById("provider-modal-cancel");
const providerModalClose = document.getElementById("provider-modal-close");

// Opens the consent modal and resolves to true (confirmed) or false (cancelled).
// opts: { title, message, confirmLabel, confirmClass, detailLabel, detailValue }.
function askProviderConsent(opts) {
    return new Promise((resolve) => {
        providerModalTitle.textContent = opts.title;
        providerModalMessage.textContent = opts.message;
        providerModalConfirm.textContent = opts.confirmLabel || "Continue";
        providerModalConfirm.className = "app-button " + (opts.confirmClass || "encrypt-button");
        if (opts.detailValue) {
            providerModalDetailValue.value = opts.detailValue;
            providerModalDetailValue.setAttribute("aria-label", opts.detailLabel || "Details");
            providerModalDetail.hidden = false;
        } else {
            providerModalDetailValue.value = "";
            providerModalDetail.hidden = true;
        }

        const cleanup = () => {
            providerModal.hidden = true;
            document.body.style.overflow = "";
            providerModalConfirm.removeEventListener("click", onConfirm);
            providerModalCancel.removeEventListener("click", onCancel);
            providerModalClose.removeEventListener("click", onCancel);
            providerModal.removeEventListener("click", onBackdrop);
            document.removeEventListener("keydown", onKeydown);
        };
        const onConfirm = () => { cleanup(); resolve(true); };
        const onCancel = () => { cleanup(); resolve(false); };
        const onBackdrop = (event) => { if (event.target === providerModal) { onCancel(); } };
        const onKeydown = (event) => { if (event.key === "Escape") { onCancel(); } };

        providerModalConfirm.addEventListener("click", onConfirm);
        providerModalCancel.addEventListener("click", onCancel);
        providerModalClose.addEventListener("click", onCancel);
        providerModal.addEventListener("click", onBackdrop);
        document.addEventListener("keydown", onKeydown);

        providerModalDetailCopy.onclick = () => {
            copyToClipboard(providerModalDetailValue.value, providerModalDetailCopy, "Copied.");
        };

        providerModal.hidden = false;
        document.body.style.overflow = "hidden";
    });
}

/* ==========================================================================
   Flow steps
   ========================================================================== */

// Removes the provider query/fragment from the address bar without reloading, so
// a refresh can't reprocess a (already consumed) return or re-trigger a redirect.
function clearProviderUrl() {
    history.replaceState(null, "", callbackUrl());
}

// initiateProviderFlow runs when the app is opened with ?provider=<url>. When
// forceEcc is true the request uses the compact X25519 key directly. Returns
// "redirecting" if it navigates away to the provider, otherwise null.
async function initiateProviderFlow(rawProviderUrl, forceEcc) {
    const providerUrl = normalizeProviderUrl(rawProviderUrl);
    if (!providerUrl) {
        showToast("That credential provider URL is not valid.", "error");
        clearProviderUrl();
        return null;
    }

    const host = new URL(providerUrl).host;
    const ok = await askProviderConsent({
        title: "Get a key from a credential provider?",
        message: `You'll be sent to ${host} to sign in. It will issue a xipher secret key for this browser. ` +
            `Only continue if you trust this provider; it will be able to read secrets sent to you.`,
        confirmLabel: "Continue to provider",
        detailLabel: "Provider",
        detailValue: providerUrl,
    });
    if (!ok) {
        clearProviderUrl();
        return null;
    }

    // Fresh ephemeral keypair for THIS exchange only. We prefer the hybrid
    // (post-quantum) public key so the sealed long-term secret resists
    // harvest-now, decrypt-later attacks against a recorded URL. The hybrid key
    // is ~2.5 KB though, pushing the outbound URL to ~2.7 KB. Browsers handle
    // that easily, but a provider behind a strict proxy/WAF may cap the request
    // line, so we fall back to the compact X25519 key when the hybrid URL would
    // exceed PROVIDER_URL_BUDGET (or when the provider requested ECC via
    // ?provider_ecc). The same secret decrypts a blob sealed to either key (the
    // algorithm is carried in the ciphertext), so the return path is unchanged.
    const ephemeralSecretKey = await genXipherSecretKey();
    const state = await createProviderExchange(providerUrl, ephemeralSecretKey);

    let pubKey = await genXipherPublicKey(ephemeralSecretKey, !forceEcc);
    let target = buildProviderUrl(providerUrl, pubKey, state);
    // When the provider didn't already ask for ECC, downgrade only if the hybrid
    // URL is too long for a typical server to accept.
    if (!forceEcc && target.length > PROVIDER_URL_BUDGET) {
        pubKey = await genXipherPublicKey(ephemeralSecretKey, false);
        target = buildProviderUrl(providerUrl, pubKey, state);
        showToast(
            "This provider needs a shorter request, so quantum-safe sealing was disabled for it.",
            "info",
            4000
        );
    }
    window.location.replace(target);
    return "redirecting";
}

// parseProviderReturn reads the return parameters from the URL fragment. Returns
// { state, key, err } or null if this isn't a provider return.
function parseProviderReturn() {
    const fragment = window.location.hash.substring(1);
    if (!fragment || (fragment.indexOf(PROVIDER_RES_KEY + "=") === -1 &&
        fragment.indexOf(PROVIDER_RES_ERR + "=") === -1)) {
        return null;
    }
    const params = new URLSearchParams(fragment);
    const key = params.get(PROVIDER_RES_KEY);
    const err = params.get(PROVIDER_RES_ERR);
    if (!key && !err) {
        return null;
    }
    return { state: params.get(PROVIDER_RES_STATE), key, err };
}

// completeProviderReturn validates the returned state, decrypts the sealed key,
// and (after consent) installs it as the active identity.
async function completeProviderReturn(ret) {
    // Single-use: this reads AND deletes the record before we touch its contents.
    const exchange = await consumeProviderExchange(ret.state);
    // Always strip the payload from the address bar once we've taken it in hand.
    clearProviderUrl();

    if (!exchange) {
        showToast("That credential response is invalid or expired. Start again from your provider.", "error");
        return;
    }
    if (ret.err) {
        showToast(providerErrorMessage(ret.err), "error");
        return;
    }

    let sealedPayload;
    try {
        sealedPayload = await decryptStr(exchange.ephemeralSecretKey, ret.key);
    } catch (error) {
        showToast("Couldn't open the key from the provider (it wasn't sealed to this session).", "error");
        return;
    }
    // The provider seals a JSON document {"key","name","id"} (name/id optional).
    // For backward compatibility we also accept a bare XSK_ string.
    const delivered = parseSealedIdentity(sealedPayload);
    if (!delivered.key || !(await isValidSecretKey(delivered.key))) {
        showToast("The provider returned something that isn't a valid secret key.", "error");
        return;
    }

    const existing = await getExistingXipherSecret();
    const host = (() => { try { return new URL(exchange.providerUrl).host; } catch (e) { return "the provider"; } })();
    const ok = await askProviderConsent({
        title: "Use the key from your provider?",
        // The existing key is never revealed here: this consent runs in a context
        // reached by an external redirect, so showing or backing up the secret
        // would widen its exposure. The user manages their own key in the profile.
        message: existing
            ? `Accepting this key from ${host} will REPLACE the secret key already in this browser. ` +
              `Anything encrypted to your current key will no longer be readable here.`
            : `Set the secret key issued by ${host} as this browser's identity?`,
        confirmLabel: existing ? "Replace my key" : "Use this key",
        confirmClass: existing ? "decrypt-button" : "encrypt-button",
    });
    if (!ok) {
        showToast("Kept your existing key. The provider's key was discarded.", "info");
        return;
    }

    await setProviderIdentity(delivered.key, host, delivered.name, delivered.id);
    if (typeof refreshIdentity === "function") {
        await refreshIdentity();
    }
    showToast(
        delivered.name ? `You're now signed in as ${delivered.name}.` : "Your key from the provider is now active.",
        "success"
    );
}

// parseSealedIdentity reads the decrypted provider payload. It prefers a JSON
// document { key, name, id: { name, value } } (name and id optional) and falls
// back to a bare XSK_ string. Returns { key, name, id } where id is a labelled
// identifier object or null.
function parseSealedIdentity(payload) {
    const trimmed = (payload || "").trim();
    if (trimmed.startsWith("{")) {
        try {
            const doc = JSON.parse(trimmed);
            if (doc && typeof doc.key === "string") {
                let id = null;
                if (doc.id && typeof doc.id === "object" && typeof doc.id.value === "string") {
                    id = {
                        name: typeof doc.id.name === "string" ? doc.id.name : "",
                        value: doc.id.value,
                    };
                }
                return {
                    key: doc.key.trim(),
                    name: typeof doc.name === "string" ? doc.name : "",
                    id,
                };
            }
        } catch (error) {
            // Not JSON; fall through to the bare-string form.
        }
    }
    return { key: trimmed, name: "", id: null };
}

// handleProviderFlow is the entry point called from main() after the WASM loads.
// Returns "redirecting" when navigating away (caller should stop initializing),
// otherwise null. A provider return is handled inline; the app then continues to
// initialize normally with the (possibly new) identity.
async function handleProviderFlow() {
    const ret = parseProviderReturn();
    if (ret) {
        await completeProviderReturn(ret);
        return null;
    }
    const params = new URLSearchParams(window.location.search);
    const rawProviderUrl = params.get("provider");
    if (rawProviderUrl) {
        // provider_ecc lets a provider that knows it has a strict URL-length cap
        // ask for the compact X25519 key up front, skipping the hybrid attempt.
        return await initiateProviderFlow(rawProviderUrl, isTruthyFlag(params.get("provider_ecc")));
    }
    return null;
}

// isTruthyFlag interprets a query-param flag. Present with no value (?flag) or a
// common affirmative value counts as true; absent or "0"/"false"/"no" is false.
function isTruthyFlag(value) {
    if (value === null) {
        return false;
    }
    const v = value.trim().toLowerCase();
    return v === "" || v === "1" || v === "true" || v === "yes";
}
