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
const PROVIDER_REQ_PUBKEY = "xpk";
const PROVIDER_REQ_STATE = "state";
const PROVIDER_REQ_CALLBACK = "xcb";

// Fragment parameters the provider returns on the callback URL.
const PROVIDER_RES_KEY = "xck"; // sealed secret key (XCT_…)
const PROVIDER_RES_ERR = "xe"; // failure reason code
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

// normalizeProviderUrl resolves a provider reference to an absolute URL the app
// will redirect to. A scheme is optional: a schemeless host is promoted to
// https (http for loopback hosts during local development), so "shib.me" and
// "shib.me/issue" both work. If a scheme IS given it must be https, since the
// provider receives the ephemeral public key and we never want it sent in the
// clear; the only exception is http to a loopback host for development.
// Returns { url } on success or { error } with a short reason otherwise.
function normalizeProviderUrl(value) {
    if (!value) {
        return { error: "invalid" };
    }
    value = value.trim();

    if (SCHEME_REGEX.test(value)) {
        let u;
        try {
            u = new URL(value);
        } catch (e) {
            return { error: "invalid" };
        }
        if (u.protocol === "https:" || (u.protocol === "http:" && isLoopbackHost(u.hostname))) {
            return { url: value };
        }
        // A scheme was supplied but it isn't allowed (e.g. http to a public host).
        return { error: "insecure" };
    }

    // Schemeless: promote to a scheme. Loopback hosts use http for local dev;
    // everything else uses https.
    const host = value.split("/")[0].split(":")[0];
    if (isLoopbackHost(host)) {
        return { url: "http://" + value };
    }
    if (DOMAIN_REGEX.test(value)) {
        return { url: "https://" + value };
    }
    return { error: "invalid" };
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
const providerModalInputRow = document.getElementById("provider-modal-input-row");
const providerModalInput = document.getElementById("provider-modal-input");
const providerModalInputHint = document.getElementById("provider-modal-input-hint");
const providerModalDetail = document.getElementById("provider-modal-detail");
const providerModalDetailValue = document.getElementById("provider-modal-detail-value");
const providerModalDetailCopy = document.getElementById("provider-modal-detail-copy");
const providerModalConfirm = document.getElementById("provider-modal-confirm");
const providerModalCancel = document.getElementById("provider-modal-cancel");
const providerModalClose = document.getElementById("provider-modal-close");
const providerModalToggleRow = document.getElementById("provider-modal-toggle-row");
const providerModalToggle = document.getElementById("provider-modal-toggle");
const providerModalToggleLabel = document.getElementById("provider-modal-toggle-label");
const providerModalToggleNote = document.getElementById("provider-modal-toggle-note");
const providerModalToggleDocs = document.getElementById("provider-modal-toggle-docs");
const providerModalDurationRow = document.getElementById("provider-modal-duration-row");
const providerModalDurationValue = document.getElementById("provider-modal-duration-value");
const providerModalDurationUnit = document.getElementById("provider-modal-duration-unit");
const providerModalDurationHint = document.getElementById("provider-modal-duration-hint");

// Opens the consent modal and resolves to true (confirmed) or false (cancelled).
// opts: { title, message, confirmLabel, confirmClass, detailLabel, detailValue }.
//
// When opts.toggle is provided ({ label, note, checked }) an opt-in switch is
// shown and the promise resolves to an object { confirmed, checked } on every
// path, so the caller can read the switch state.
//
// When opts.input is provided ({ label, value, placeholder, hint, validate }) an
// editable text field is shown and the promise resolves with { value }.
//
// When opts.duration is provided ({ valueMs }) a number+unit "session timeout"
// field is shown, prefilled from valueMs, and Confirm stays disabled until the
// entered duration is valid (0 < ms <= MAX_TIMEOUT_MS). Every path then resolves
// to an object that also carries { durationMs } (the chosen value, or null on a
// non-confirm path).
//
// With neither toggle nor duration the legacy boolean (or dismissValue) is
// returned unchanged.
function askProviderConsent(opts) {
    return new Promise((resolve) => {
        // The provider flow runs during startup while the preloader is still up
        // (z-index 2000). Hide it first so this modal (z-index 1500) is actually
        // visible and clickable, otherwise the consent sits behind the loader.
        if (typeof hidePreloader === "function") {
            hidePreloader();
        }
        providerModalTitle.textContent = opts.title;
        providerModalMessage.textContent = "";
        const inputRequested = !!opts.input;
        const inputAvailable = !!(providerModalInputRow && providerModalInput && providerModalInputHint);
        if (inputRequested && !inputAvailable) {
            showToast("Refresh this page before entering a credential provider URL.", "error", 5000);
            resolve({ confirmed: false, value: "" });
            return;
        }
        if (Array.isArray(opts.messageParts)) {
            opts.messageParts.forEach((part) => {
                if (part && part.strong) {
                    const strong = document.createElement("strong");
                    strong.textContent = part.text || "";
                    providerModalMessage.appendChild(strong);
                } else {
                    providerModalMessage.appendChild(document.createTextNode(part && part.text ? part.text : ""));
                }
            });
        } else {
            providerModalMessage.textContent = opts.message;
        }
        providerModalConfirm.textContent = opts.confirmLabel || "Continue";
        providerModalConfirm.className = "app-button " + (opts.confirmClass || "encrypt-button");
        providerModalCancel.textContent = opts.cancelLabel || "Cancel";
        const hasInput = inputRequested && inputAvailable;
        const inputDefaultHint = hasInput ? (opts.input.hint || "") : "";
        if (hasInput) {
            const label = providerModalInputRow.querySelector("label");
            label.textContent = opts.input.label || "Value";
            providerModalInput.value = opts.input.value || "";
            providerModalInput.placeholder = opts.input.placeholder || "";
            providerModalInputHint.textContent = inputDefaultHint;
            providerModalInputHint.hidden = !inputDefaultHint;
            providerModalInputRow.hidden = false;
        } else if (inputAvailable) {
            providerModalInput.value = "";
            providerModalInputRow.hidden = true;
            providerModalInputHint.textContent = "";
            providerModalInputHint.hidden = true;
        }
        if (opts.detailValue) {
            providerModalDetailValue.value = opts.detailValue;
            providerModalDetailValue.setAttribute("aria-label", opts.detailLabel || "Details");
            providerModalDetail.hidden = false;
        } else {
            providerModalDetailValue.value = "";
            providerModalDetail.hidden = true;
        }

        const hasToggle = !!opts.toggle;
        if (hasToggle) {
            providerModalToggleLabel.textContent = opts.toggle.label || "";
            providerModalToggleNote.textContent = opts.toggle.note || "";
            providerModalToggle.checked = !!opts.toggle.checked;
            // Optional docs link (opens in a new tab) next to the toggle label.
            if (opts.toggle.docsHref) {
                providerModalToggleDocs.href = opts.toggle.docsHref;
                providerModalToggleDocs.title = opts.toggle.docsTitle || "Learn more";
                providerModalToggleDocs.setAttribute("aria-label", opts.toggle.docsTitle || "Learn more");
                providerModalToggleDocs.hidden = false;
            } else {
                providerModalToggleDocs.hidden = true;
            }
            providerModalToggleRow.hidden = false;
        } else {
            providerModalToggleRow.hidden = true;
            providerModalToggleDocs.hidden = true;
            providerModalToggle.checked = false;
        }

        // Reads the current duration field as ms, or null when invalid (blank,
        // non-positive, or above the 7-day ceiling).
        const readDuration = () => {
            const value = parseInt(providerModalDurationValue.value, 10);
            if (!Number.isFinite(value) || value <= 0) {
                return null;
            }
            const ms = value * (TIMEOUT_UNIT_MS[providerModalDurationUnit.value] || 0);
            if (ms <= 0 || ms > MAX_TIMEOUT_MS) {
                return null;
            }
            return ms;
        };
        // Confirm stays disabled while the duration field is invalid.
        const syncDurationValidity = () => {
            syncConfirmValidity();
        };

        const readInput = () => providerModalInput.value.trim();
        const inputError = () => {
            if (!hasInput) {
                return "";
            }
            if (!readInput()) {
                return opts.input.requiredMessage || "Enter a value to continue.";
            }
            if (typeof opts.input.validate === "function") {
                return opts.input.validate(readInput()) || "";
            }
            return "";
        };
        const syncInputValidity = () => {
            const error = inputError();
            providerModalInputHint.textContent = error || inputDefaultHint;
            providerModalInputHint.hidden = !(error || inputDefaultHint);
            providerModalInput.classList.toggle("text-error", !!error);
            syncConfirmValidity();
        };
        const syncConfirmValidity = () => {
            providerModalConfirm.disabled =
                (hasDuration && readDuration() === null) ||
                (hasInput && !!inputError());
        };

        const hasDuration = !!opts.duration;
        if (hasDuration) {
            const { value, unit } = splitDuration(opts.duration.valueMs);
            providerModalDurationValue.value = String(value);
            providerModalDurationUnit.value = unit;
            // Caller-supplied hint; the profile-edit flow drops the "Maximum 7
            // days" note since there the real ceiling is the current value (the
            // consent message already says it can only be shortened). Empty hides.
            const hint = opts.duration.hint !== undefined
                ? opts.duration.hint
                : "The stored key clears after this much inactivity. Maximum 7 days.";
            providerModalDurationHint.textContent = hint;
            providerModalDurationHint.hidden = !hint;
            providerModalDurationRow.hidden = false;
            providerModalDurationValue.addEventListener("input", syncDurationValidity);
            providerModalDurationUnit.addEventListener("change", syncDurationValidity);
        } else {
            providerModalDurationRow.hidden = true;
        }
        if (hasInput) {
            providerModalInput.addEventListener("input", syncInputValidity);
        }
        syncConfirmValidity();

        const cleanup = () => {
            providerModal.hidden = true;
            if (typeof syncBodyScrollLock === "function") {
                syncBodyScrollLock();
            } else {
                document.body.classList.remove("no-scroll");
            }
            providerModalConfirm.disabled = false;
            if (inputAvailable) {
                providerModalInput.classList.remove("text-error");
                providerModalInput.removeEventListener("input", syncInputValidity);
            }
            providerModalConfirm.removeEventListener("click", onConfirm);
            providerModalCancel.removeEventListener("click", onCancel);
            providerModalClose.removeEventListener("click", onDismiss);
            providerModal.removeEventListener("click", onBackdrop);
            document.removeEventListener("keydown", onKeydown, true);
            providerModalDurationValue.removeEventListener("input", syncDurationValidity);
            providerModalDurationUnit.removeEventListener("change", syncDurationValidity);
        };
        const dismissValue = opts.dismissValue !== undefined ? opts.dismissValue : false;
        // With a toggle or duration, every path returns an object; without either,
        // the legacy boolean/dismissValue is preserved. durationMs is the chosen
        // value on confirm, null otherwise.
        const wrap = (confirmed, fallback, durationMs, value) => {
            if (!hasToggle && !hasDuration && !hasInput) {
                return fallback;
            }
            const result = { confirmed };
            if (hasToggle) {
                result.checked = providerModalToggle.checked;
            }
            if (hasDuration) {
                result.durationMs = durationMs;
            }
            if (hasInput) {
                result.value = value || "";
            }
            return result;
        };
        const onConfirm = () => {
            // Guard against a confirm slipping through while invalid (e.g. Enter).
            if ((hasDuration && readDuration() === null) || (hasInput && inputError())) {
                return;
            }
            const durationMs = hasDuration ? readDuration() : null;
            const value = hasInput ? readInput() : "";
            cleanup();
            resolve(wrap(true, true, durationMs, value));
        };
        const onCancel = () => { cleanup(); resolve(wrap(false, false, null, "")); };
        const onDismiss = () => { cleanup(); resolve(wrap(false, dismissValue, null, "")); };
        const onBackdrop = (event) => { if (event.target === providerModal) { onDismiss(); } };
        const onKeydown = (event) => {
            if (event.key === "Escape") {
                event.preventDefault();
                event.stopImmediatePropagation();
                onDismiss();
            }
        };

        providerModalConfirm.addEventListener("click", onConfirm);
        providerModalCancel.addEventListener("click", onCancel);
        // The close (X) button dismisses: it's a "back out" action, distinct from
        // the explicit Cancel button. onDismiss returns dismissValue so callers can
        // tell an abort apart from an active Cancel (e.g. passkey naming aborts on
        // dismiss but uses the default name on Cancel). Matches the cleanup remover.
        providerModalClose.addEventListener("click", onDismiss);
        providerModal.addEventListener("click", onBackdrop);
        document.addEventListener("keydown", onKeydown, true);

        providerModalDetailCopy.onclick = () => {
            copyToClipboard(providerModalDetailValue.value, providerModalDetailCopy, "Copied.");
        };

        providerModal.hidden = false;
        document.body.classList.add("no-scroll");
        if (hasInput) {
            providerModalInput.focus();
            providerModalInput.select();
        }
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

// providerHostFromUrl returns the host used for same-provider decisions. Invalid
// stored metadata is treated as "no match" rather than blocking the flow.
function providerHostFromUrl(providerUrl) {
    try {
        return new URL(providerUrl).host;
    } catch (e) {
        return "";
    }
}

// initiateProviderFlow runs when the app is opened with ?provider=<url>. When
// forceEcc is true the request uses the compact X25519 key directly. When
// autoReauth is true the flow was started silently (re-fetching an ephemeral or
// expired key on load, not by an explicit user action); priorProviderUrl carries
// the pre-expiry provider when active identity metadata was already wiped.
// Returns "redirecting" if it navigates away to the provider, otherwise null.
async function initiateProviderFlow(rawProviderUrl, forceEcc, autoReauth, priorProviderUrl, trustAlreadyConfirmed) {
    const resolved = normalizeProviderUrl(rawProviderUrl);
    if (resolved.error) {
        showToast(
            resolved.error === "insecure"
                ? "Credential providers must use https. That provider URL was rejected."
                : "That credential provider URL is not valid.",
            "error"
        );
        clearProviderUrl();
        return null;
    }
    const providerUrl = resolved.url;

    const host = new URL(providerUrl).host;
    const identity = getIdentity();
    const configuredProviderUrl = priorProviderUrl || (
        identity.managed && identity.provider !== "passkey" ? identity.provider : ""
    );
    const priorProviderHost = providerHostFromUrl(configuredProviderUrl);
    const sameConfiguredProvider = priorProviderHost === host;
    if (sameConfiguredProvider && await hasXipherSession()) {
        const ok = await askProviderConsent({
            title: "Session already exists",
            messageParts: [
                { text: "You're already signed in with " },
                { text: host, strong: true },
                { text: ". Changing credentials will replace the key for this browser." },
            ],
            confirmLabel: "Change credential",
            cancelLabel: "Cancel re-auth",
            confirmClass: "decrypt-button",
            detailLabel: "Provider",
            detailValue: providerUrl,
        });
        if (!ok) {
            clearProviderUrl();
            return null;
        }
    }

    if (!trustAlreadyConfirmed && !getTrustedProviderHosts().includes(host)) {
        const result = await askProviderConsent({
            title: "Get a key from a credential provider?",
            message: `You'll be sent to ${host} to sign in. It will issue a xipher secret key for this browser. ` +
                `Only continue if you trust this provider; it will be able to read secrets sent to you.`,
            confirmLabel: "Continue to provider",
            detailLabel: "Provider",
            detailValue: providerUrl,
            toggle: {
                label: "Remember this provider",
                note: "Skip this confirmation next time you use the same provider.",
                checked: false,
            },
        });
        if (!result || !result.confirmed) {
            clearProviderUrl();
            return null;
        }
        if (result.checked) {
            addTrustedProviderHost(host);
        }
    }

    // Fresh ephemeral keypair for THIS exchange only. We prefer the hybrid
    // (post-quantum) public key so the sealed long-term secret resists
    // harvest-now, decrypt-later attacks against a recorded URL. The hybrid key
    // is ~2.5 KB though, pushing the outbound URL to ~2.7 KB. Browsers handle
    // that easily, but a provider behind a strict proxy/WAF may cap the request
    // line, so we fall back to the compact X25519 key when the hybrid URL would
    // exceed PROVIDER_URL_BUDGET (or when the provider requested ECC via
    // ?xecc). The same secret decrypts a blob sealed to either key (the
    // algorithm is carried in the ciphertext), so the return path is unchanged.
    const ephemeralSecretKey = await genXipherSecretKey();
    const state = await createProviderExchange(providerUrl, ephemeralSecretKey, autoReauth === true, priorProviderHost);

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
    // Hand off to the delayed-redirect overlay: it shows "Redirecting to <host>…"
    // with a countdown plus Continue/Cancel actions, then navigates when the
    // countdown elapses or Continue is clicked. If the user cancels, drop the
    // pending exchange (its ephemeral secret would otherwise sit unused in
    // sessionStorage) and return null so the caller falls through to the normal
    // identity gate.
    if (typeof redirectWithCancel === "function") {
        const outcome = await redirectWithCancel(
            target,
            "Redirecting to ",
            () => {
                discardProviderExchange(state);
                showToast("Redirect cancelled. You can set a key manually instead.", "info");
            },
            host
        );
        return outcome === "redirecting" ? "redirecting" : null;
    }
    // Fallback if the overlay helper isn't present (defensive): redirect at once.
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
        return false;
    }
    if (ret.err) {
        showToast(providerErrorMessage(ret.err), "error");
        return false;
    }

    let sealedPayload;
    try {
        sealedPayload = await decryptStr(exchange.ephemeralSecretKey, ret.key);
    } catch (error) {
        showToast("Couldn't open the key from the provider (it wasn't sealed to this session).", "error");
        return false;
    }
    // The provider seals a JSON document {"key"|"seed","name","id","type","timeout"}
    // (only the secret material is required). For backward compatibility we also
    // accept a bare XSK_ string. The secret may be a ready key or a seed it is
    // derived from; key wins when both are present. `timeout` is the key's
    // relative validity in SECONDS (capped at 7 days; 0 = ephemeral, tab-only).
    const delivered = parseSealedIdentity(sealedPayload);
    // timeoutMs: 0 => ephemeral (key lives only while the tab is open, like a
    // passkey) - this is the default when timeout is absent or invalid; otherwise
    // the provider's relative validity window, capped at the 7-day ceiling.
    const durationMs = delivered.timeoutMs;
    let deliveredKey;
    try {
        deliveredKey = await resolveDeliveredKey(delivered);
    } catch (error) {
        showToast("The provider returned a seed that couldn't be converted to a key.", "error");
        return false;
    }
    if (!deliveredKey || !(await isValidSecretKey(deliveredKey))) {
        showToast("The provider returned something that isn't a valid secret key.", "error");
        return false;
    }

    const existing = await getExistingXipherSecret();
    const host = providerHostFromUrl(exchange.providerUrl) || "the provider";
    const sameProvider = !!exchange.priorProviderHost && exchange.priorProviderHost === providerHostFromUrl(exchange.providerUrl);
    // Auto-reauth (an ephemeral or expired provider key being silently
    // re-fetched on load) carries no new decision for the user: they already
    // consented to this provider when first adopting it, and the redirect
    // happened without them clicking anything. First-time installs and same-
    // provider refreshes also carry no replacement decision, so prompt only when
    // a different provider would replace an existing local credential.
    if (!exchange.autoReauth && existing && !sameProvider) {
        const ok = await askProviderConsent({
            title: "Use the key from your provider?",
            // The existing key is never revealed here: this consent runs in a context
            // reached by an external redirect, so showing or backing up the secret
            // would widen its exposure. The user manages their own key in the profile.
            message: `Accepting this key from ${host} will REPLACE the secret key already in this browser. ` +
                `Anything encrypted to your current key will no longer be readable here.`,
            confirmLabel: "Replace my key",
            confirmClass: "decrypt-button",
        });
        if (!ok) {
            showToast("Kept your existing key. The provider's key was discarded.", "info");
            return false;
        }
    }

    // Store the full provider URL (not just `host`, which is only the consent
    // sentence's short label) so the profile shows exactly where the redirect
    // goes and auto-reauth can revisit the same scheme/host/path.
    await setProviderIdentity(deliveredKey, exchange.providerUrl, delivered.name, delivered.id, delivered.type, true, durationMs);
    if (typeof refreshIdentity === "function") {
        await refreshIdentity();
    }
    showToast(
        delivered.name ? `You're now signed in as ${delivered.name}.` : "Your key from the provider is now active.",
        "success"
    );
    return true;
}

// parseSealedIdentity reads the decrypted provider payload. It prefers a JSON
// document { key, seed, name, id, type } (all but the secret material optional)
// and falls back to a bare XSK_ string. The secret may be supplied either as a
// ready XSK_ key or as a seed it is derived from; if both are given, key takes
// precedence. Returns { key, seed, name, id, type } where key/seed/id are
// strings ("" if absent) and type is "user" | "group" | "service" ("" for a
// missing or unrecognised value; the id still stores, just without a typed
// label). timeoutMs defaults to 0 (ephemeral) when timeout is absent or invalid.
function parseSealedIdentity(payload) {
    const trimmed = (payload || "").trim();
    if (trimmed.startsWith("{")) {
        try {
            const doc = JSON.parse(trimmed);
            const hasKey = typeof doc.key === "string" && doc.key.trim();
            const hasSeed = typeof doc.seed === "string" && doc.seed.trim();
            if (doc && (hasKey || hasSeed)) {
                const id = typeof doc.id === "string" ? doc.id : "";
                const type = doc.type === "user" || doc.type === "group" || doc.type === "service" ? doc.type : "";
                return {
                    key: hasKey ? doc.key.trim() : "",
                    seed: hasSeed ? doc.seed.trim() : "",
                    name: typeof doc.name === "string" ? doc.name : "",
                    id,
                    type,
                    timeoutMs: parseTimeoutSeconds(doc.timeout),
                };
            }
        } catch (error) {
            // Not JSON; fall through to the bare-string form.
        }
    }
    return { key: trimmed, seed: "", name: "", id: "", type: "", timeoutMs: 0 };
}

// parseTimeoutSeconds reads the optional provider `timeout` field (relative
// validity in SECONDS) and returns it in milliseconds, clamped to the 7-day
// ceiling. Returns 0 when absent/invalid, which means an ephemeral, tab-lifetime
// key (never written to storage) - so omitting timeout opts into the safest
// default rather than a long-lived persisted key.
function parseTimeoutSeconds(value) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
        return 0;
    }
    return Math.min(value * 1000, MAX_TIMEOUT_MS);
}

// decodeSeed decodes a standard- or url-safe base64 seed string into the raw
// 64 bytes the key is derived from. Throws if the input isn't valid base64 or
// doesn't decode to exactly 64 bytes.
function decodeSeed(seedB64) {
    // Accept base64url and missing padding by normalising before atob.
    let b64 = seedB64.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) {
        b64 += "=";
    }
    let binary;
    try {
        binary = atob(b64);
    } catch (e) {
        throw new Error("seed is not valid base64");
    }
    if (binary.length !== 64) {
        throw new Error("seed must decode to exactly 64 bytes, got " + binary.length);
    }
    const bytes = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// resolveDeliveredKey turns a parsed payload into a concrete XSK_ secret key. A
// ready key is used directly; otherwise the base64 seed is decoded to 64 bytes
// and converted with the WASM helper. key takes precedence when both are
// present. Throws if the seed is malformed or conversion fails.
async function resolveDeliveredKey(delivered) {
    if (delivered.key) {
        return delivered.key;
    }
    if (delivered.seed) {
        return await genXipherSecretKeyFromSeed(decodeSeed(delivered.seed));
    }
    return "";
}

// handleProviderFlow is the entry point called from main() after the WASM loads.
// Returns:
//   "redirecting"   - navigating away to the provider; caller should stop init.
//   "return-failed" - a provider return came back as an error/cancel, or the
//                     user declined the returned key; caller should NOT auto-
//                     reauth this load (that would bounce straight back) and
//                     should open the Setup/Profile gate instead.
//   null            - nothing special (no return, or a return that succeeded).
// A provider return is handled inline; the app then continues to initialize
// normally with the (possibly new) identity.
async function handleProviderFlow() {
    const ret = parseProviderReturn();
    if (ret) {
        const ok = await completeProviderReturn(ret);
        return ok ? null : "return-failed";
    }
    const params = new URLSearchParams(window.location.search);
    const rawProviderUrl = params.get("provider");
    if (rawProviderUrl) {
        // xecc lets a provider that knows it has a strict URL-length cap
        // ask for the compact X25519 key up front, skipping the hybrid attempt.
        return await initiateProviderFlow(rawProviderUrl, isTruthyFlag(params.get("xecc")));
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
