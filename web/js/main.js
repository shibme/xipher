// Browsers reliably handle URLs up to ~2000 chars; longer ciphertext is shared as-is.
const MAX_SHAREABLE_URL_LENGTH = 2000;
// Must match the preloader fade-out transition in base.css.
const PRELOADER_FADE_MS = 400;

const preLoader = document.getElementById("preloader");
const textInput = document.getElementById("text");
const fileInput = document.getElementById("file");
const textActionButton = document.getElementById("text-action-button");
const fileDisplay = document.getElementById("file-display");
const fileNameElement = document.getElementById("file-name");
const fileSizeElement = document.getElementById("file-size");
const actionButton = document.getElementById("action-button");
const linkSection = document.getElementById("link-section");
const linkLabel = document.getElementById("link-label");
const linkViewbox = document.getElementById("link-viewbox");
const shareableLink = document.getElementById("shareable-link");
const textCopyButton = document.getElementById("text-copy-button");
const textShareButton = document.getElementById("text-share-button");
const publinkCopyButton = document.getElementById("publink-copy-button");
const publinkShareButton = document.getElementById("publink-share-button");
const modeBadge = document.getElementById("mode-badge");
const modeBadgeText = document.getElementById("mode-badge-text");
const appContainer = document.querySelector(".app-container");
const selfEncryptPanel = document.getElementById("self-encrypt-panel");
const selfEncryptToggle = document.getElementById("self-encrypt-toggle");
const selfEncryptDivider = document.getElementById("self-encrypt-divider");

// Matches a bare host (optionally with a port/path) that has no URL scheme,
// e.g. "alice.com" or "alice.com/keys". Mirrors domainRegex in resolver.go.
const DOMAIN_REGEX = /^([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s]*)?$/;
const SCHEME_REGEX = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

// isLoopbackHost reports whether host is a loopback address, for which plain
// http is permitted (local development). Mirrors isLoopbackHost in resolver.go.
function isLoopbackHost(host) {
    host = (host || "").toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
}

// isFetchableUrl reports whether s is a key URL we may fetch: https anywhere, or
// http when the host is a loopback address.
function isFetchableUrl(s) {
    if (typeof s !== "string") {
        return false;
    }
    try {
        const u = new URL(s);
        if (u.protocol === "https:") {
            return true;
        }
        return u.protocol === "http:" && isLoopbackHost(u.hostname);
    } catch (e) {
        return false;
    }
}

// redirectToResolver hands a key URL off to the /resolve/ page, which can fetch
// it (the main app's CSP forbids external connections).
function redirectToResolver(url) {
    window.location.replace("resolve/?xu=" + encodeURIComponent(url));
}

// classifyKeyRef decides what a URL-supplied key reference is. It returns
// { pubKey } for a public key, { url } for a fetchable URL (https, or http for
// loopback) or a bare domain (normalised to https://), or null for anything
// else. Secret keys, passwords, and disallowed schemes are all rejected; only
// public material may travel here.
function classifyKeyRef(value) {
    if (!value) {
        return null;
    }
    if (value.startsWith("XPK_")) {
        return { pubKey: value };
    }
    if (isFetchableUrl(value)) {
        return { url: value };
    }
    if (!SCHEME_REGEX.test(value)) {
        // A schemeless loopback host uses http; a bare domain uses https.
        const host = value.split("/")[0].split(":")[0];
        if (isLoopbackHost(host)) {
            return { url: "http://" + value };
        }
        if (DOMAIN_REGEX.test(value)) {
            return { url: "https://" + value };
        }
    }
    return null;
}

function initParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const xt = urlParams.get("xt");
    const xn = urlParams.get("xn"); // display name resolved by the /resolve/ page
    const queryRef = classifyKeyRef(urlParams.get("xk"));
    if (queryRef || xt) {
        if (queryRef && queryRef.url) {
            redirectToResolver(queryRef.url);
            return { xk: null, xt: null, xn: null, redirecting: true };
        }
        return { xk: queryRef ? queryRef.pubKey : null, xt, xn };
    }
    const fragment = window.location.hash.substring(1);
    if (fragment) {
        if (fragment.startsWith("XCT_")) {
            return { xk: null, xt: fragment };
        }
        const fragRef = classifyKeyRef(fragment);
        if (fragRef) {
            if (fragRef.url) {
                redirectToResolver(fragRef.url);
                return { xk: null, xt: null, xn: null, redirecting: true };
            }
            // A bare public key in the fragment may be paired with a ?xn= name
            // (added by getXipherPublicKeyUrl) so the sender sees the recipient.
            return { xk: fragRef.pubKey, xt: null, xn };
        }
    }
    return { xk: null, xt: null };
}

// Resolve URL params now that initParams and the regexes/helpers it relies on are
// all declared. (Calling it earlier hit the const temporal dead zone for the
// regexes, throwing on bare-domain refs like ?xk=shib.me and halting startup.)
const { xk, xt, xn, redirecting } = initParams();

function getEncryptionTarget() {
    if (!xk) {
        return "with your Key";
    }
    // xk is always a public key here (initParams rejects secret keys/passwords).
    // Use "for {name}" when the recipient is a person (reads naturally and
    // matches the "Encrypting for {xn}" mode badge), but "with {key}" when it's
    // a raw key, since you encrypt *with* a key but *for* someone.
    return xn ? `for ${xn}` : `with ${xk.substring(0, 16)}..`;
}

const ICON_LOCK_OPEN = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="action-button-icon"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>`;
const ICON_LOCK_CLOSED = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="action-button-icon"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`;

function disableActionButton(placeholderText) {
    actionButton.disabled = true;
    actionButton.innerHTML = `<span>${placeholderText}</span>`;
    actionButton.className = "app-button grey-button";
}

function enableActionButton(isDecryptMode) {
    actionButton.disabled = false;
    const label = isDecryptMode ? "Decrypt with Your Key" : "Encrypt (" + getEncryptionTarget() + ")";
    actionButton.innerHTML = `${isDecryptMode ? ICON_LOCK_OPEN : ICON_LOCK_CLOSED}<span>${label}</span>`;
    actionButton.className = `app-button ${isDecryptMode ? "decrypt-button" : "encrypt-button"}`;
    actionButton.hidden = false;
}

function toggleAttachment() {
    const textActionButtonText = textActionButton.textContent.trim();
    if (textActionButtonText === "Pick a file") {
        fileInput.click();
    } else {
        resetView();
    }
}

textActionButton.addEventListener("click", toggleAttachment);

function humanReadableFileSize(size) {
    if (size === 0) {
        return "0 Bytes";
    }
    const i = Math.floor(Math.log(size) / Math.log(1024));
    const units = ["Bytes", "KiB", "MiB", "GiB", "TiB"];
    const value = size / Math.pow(1024, i);
    const formattedValue = i === 0 ? value.toFixed(0) : value.toFixed(2);
    return `${formattedValue} ${units[i]}`;
}

function setPublicLink(url) {
    shareableLink.value = url;
}

publinkCopyButton.addEventListener("click", () => {
    copyToClipboard(shareableLink.value, publinkCopyButton, "Link copied to clipboard.");
});

function shareLink(url) {
    if (navigator.share) {
        navigator.share({ url }).catch((error) => {
            if (error && error.name !== "AbortError") {
                console.error("Error sharing link:", error);
            }
        });
    } else {
        copyToClipboard(url, null, "Sharing unavailable, link copied instead.");
    }
}

publinkShareButton.addEventListener("click", () => shareLink(shareableLink.value));

function handleFileSelect() {
    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const fileSize = humanReadableFileSize(file.size);
        textInput.value = "";
        textInput.setAttribute("readonly", true);
        textInput.placeholder = "Click to switch back to text mode";
        fileNameElement.textContent = file.name;
        fileNameElement.title = file.name;
        fileSizeElement.textContent = fileSize;
        fileDisplay.hidden = false;
        textActionButton.textContent = "Reset";
        textActionButton.className = "app-button reset-content-button";
        updateView();
    }
}

fileInput.addEventListener("change", handleFileSelect);

function resetView() {
    textCopyButton.hidden = true;
    textShareButton.hidden = true;
    fileInput.value = "";
    textInput.value = "";
    textInput.classList.remove("text-error", "text-success");
    textInput.removeAttribute("readonly");
    textInput.placeholder = "Type or paste text here, or drag & drop a file to encrypt / decrypt";
    textActionButton.textContent = "Pick a file";
    textActionButton.className = "app-button select-file-button";
    fileDisplay.hidden = true;
    updateView();
    // Clear any ciphertext from the URL (fragment or ?xt= param) so the address
    // bar goes back to the clean home state and a refresh doesn't re-trigger.
    const cleanUrl = window.location.pathname + window.location.search.replace(/[?&]xt=[^&]*/g, "").replace(/^&/, "?").replace(/\?$/, "");
    history.replaceState(null, "", cleanUrl || window.location.pathname);
    // In self-view, collapsing back returns the screen to its minimal,
    // link-focused default once the user is done.
    if (!xk) {
        collapseSelfEncryptPanel();
    }
}

function setReadableTextView(text, enableShareButton, disabledActionButtonLabel) {
    if (text) {
        fileInput.value = "";
        textInput.value = text;
        textInput.setAttribute("readonly", true);
        textCopyButton.hidden = false;
        if (enableShareButton) {
            textShareButton.hidden = false;
        }
        textActionButton.textContent = "Reset";
        textActionButton.className = "app-button reset-content-button";
        disableActionButton(disabledActionButtonLabel);
    }
}

function showActivityErrorInView(error, disabledActionButtonLabel) {
    textInput.value = error;
    textInput.classList.remove("text-success");
    textInput.classList.add("text-error");
    textInput.setAttribute("readonly", true);
    textActionButton.textContent = "Reset";
    textActionButton.className = "app-button reset-content-button";
    disableActionButton(disabledActionButtonLabel);
}

function showActivitySuccessInView(message, disabledActionButtonLabel) {
    textInput.value = message;
    textInput.classList.remove("text-error");
    textInput.classList.add("text-success");
    textInput.setAttribute("readonly", true);
    textActionButton.textContent = "Reset";
    textActionButton.className = "app-button reset-content-button";
    disableActionButton(disabledActionButtonLabel);
}

textInput.addEventListener("click", () => {
    if (fileInput.files.length > 0) {
        resetView();
    }
});

function isCT(possibleCt) {
    if (!possibleCt) {
        return false;
    }
    let ct = possibleCt;
    if (ct.startsWith("http")) {
        try {
            const url = new URL(ct);
            ct = url.searchParams.get("xt") || url.hash.substring(1) || possibleCt;
        } catch (error) {
            console.error("Failed to parse url: ", error);
        }
    }
    return ct.startsWith("XCT_");
}

function updateView() {
    const text = textInput.value.trim();
    const file = fileInput.files[0];
    if (text || file) {
        const decryptMode = (file && file.name.endsWith(".xipher")) || isCT(text);
        enableActionButton(decryptMode);
    } else if (xk) {
        disableActionButton("Encrypt (" + getEncryptionTarget() + ")");
    } else {
        disableActionButton("Waiting for input");
    }
}

textInput.addEventListener("input", updateView);

textCopyButton.addEventListener("click", () => {
    copyToClipboard(textInput.value.trim(), textCopyButton, "Result copied to clipboard.");
});

function shareText() {
    const text = textInput.value.trim();
    if (!text) {
        showToast("There's nothing to share.", "error");
        return;
    }
    if (navigator.share) {
        navigator.share({ text }).catch((error) => {
            if (error && error.name !== "AbortError") {
                console.error("Error sharing:", error);
            }
        });
    } else {
        copyToClipboard(text, null, "Sharing unavailable, copied instead.");
    }
}

textShareButton.addEventListener("click", shareText);

async function encryptStrToUrlCT(key, str) {
    const ct = await encryptStr(key, str);
    const url = window.location.href.split("?")[0];
    const urlWithoutFragment = url.split("#")[0];
    const urlCT = `${urlWithoutFragment}#${ct}`;
    if (urlCT.length < MAX_SHAREABLE_URL_LENGTH) {
        return urlCT;
    } else {
        return ct;
    }
}

let currentProcessor = null;

async function cancelCurrentStreamProcessing() {
    if (currentProcessor) {
        currentProcessor.cancel();
        while (!currentProcessor.isEnded()) {
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }
}

async function getFilePickHandlerOutStream(fileName) {
    const outputFileOpts = {
        suggestedName: fileName,
        types: [{
            description: 'Encrypted Files',
            accept: { 'application/octet-stream': ['.xipher'] }
        }]
    };
    const filePickerHandle = await window.showSaveFilePicker(outputFileOpts);
    return await filePickerHandle.createWritable();
}

async function handleFileEncryption(key, file, compress) {
    const fileSize = file.size;
    const outFileName = file.name.endsWith('.xipher') ? file.name : file.name + '.xipher';
    let fileOutStream = null;
    try {
        fileOutStream = await getFilePickHandlerOutStream(outFileName);
    } catch (error) {
        fileOutStream = streamSaver.createWriteStream(outFileName, {
            size: fileSize
        });
    }
    actionButton.classList.add("animate");
    const progressCallback = (processedSize, status) => {
        if (status === XipherStreamStatus.PROCESSING) {
            actionButton.textContent = "Encrypting (" + Math.floor((processedSize / fileSize) * 100) + "%)";
        } else if (status === XipherStreamStatus.COMPLETED) {
            showActivitySuccessInView("Encrypted as: " + outFileName, "Encryption Complete");
            const isSelfEncryption = !xk;
            const msg = isSelfEncryption
                ? "File encrypted. Store the .xipher file anywhere."
                : `File encrypted. Send the .xipher file to ${xn || "the recipient"}.`;
            showToast(msg, "success");
        } else if (status === XipherStreamStatus.FAILED) {
            showActivityErrorInView("Encryption Failed!", "Encryption Failed!");
            showToast("Encryption failed.", "error");
        } else if (status === XipherStreamStatus.CANCELLING) {
            showActivityErrorInView("Canceling Encryption...", "Canceling Encryption...");
        } else if (status === XipherStreamStatus.CANCELLED) {
            showActivityErrorInView("Encryption Cancelled!", "Encryption Cancelled!");
        } else {
            console.error("Unknown status: ", status);
        }
    };
    const encrypter = new FileEncrypter(key, file, fileOutStream, compress, progressCallback);
    currentProcessor = encrypter;
    await encrypter.start();
    actionButton.classList.remove("animate");
    return encrypter;
}

async function handleFileDecryption(key, file) {
    const fileSize = file.size;
    const outFileName = file.name.replace(/\.xipher$/, '');
    let fileOutStream = null;
    try {
        fileOutStream = await getFilePickHandlerOutStream(outFileName);
    } catch (error) {
        fileOutStream = streamSaver.createWriteStream(outFileName, {
            size: fileSize
        });
    }
    actionButton.classList.add("animate");
    const progressCallback = (processedSize, status) => {
        if (status === XipherStreamStatus.PROCESSING) {
            actionButton.textContent = "Decrypting (" + Math.floor((processedSize / fileSize) * 100) + "%)";
        } else if (status === XipherStreamStatus.COMPLETED) {
            showActivitySuccessInView("Decrypted as: " + outFileName, "Decryption Complete");
            showToast("File decrypted successfully.", "success");
        } else if (status === XipherStreamStatus.FAILED) {
            showActivityErrorInView("Decryption Failed!", "Decryption Failed!");
            showToast("Decryption failed. Check your key or password.", "error");
        } else if (status === XipherStreamStatus.CANCELLING) {
            showActivityErrorInView("Canceling Decryption...", "Canceling Decryption...");
        } else if (status === XipherStreamStatus.CANCELLED) {
            showActivityErrorInView("Decryption Cancelled!", "Decryption Cancelled!");
        } else {
            console.error("Unknown status: ", status);
        }
    };
    const decrypter = new FileDecrypter(key, file, fileOutStream, progressCallback);
    currentProcessor = decrypter;
    await decrypter.start();
    actionButton.classList.remove("animate");
    return decrypter;
}

async function handleAction() {
    const text = textInput.value.trim();
    const file = fileInput.files[0];
    if (file) {
        if (file.name.endsWith(".xipher")) {
            const key = await getXipherSecret();
            await handleFileDecryption(key, file);
        } else {
            const key = xk ? xk : await getXipherSecret();
            await handleFileEncryption(key, file, false);
        }
    } else if (text) {
        if (isCT(text)) {
            try {
                const key = await getXipherSecret();
                const pt = await decryptStr(key, text);
                setReadableTextView(pt, false, "Decrypted with your Key");
                showToast("Decrypted successfully.", "success");
            } catch (error) {
                showActivityErrorInView("Decryption Failed!", "Decryption Failed!");
                showToast("Decryption failed. Check your key or password.", "error");
            }
        } else {
            try {
                const key = xk ? xk : await getXipherSecret();
                const ct = await encryptStrToUrlCT(key, text);
                setReadableTextView(ct, true, "Encrypted (" + getEncryptionTarget() + ")");
                const isUrl = ct.startsWith("http://") || ct.startsWith("https://");
                const isSelfEncryption = !xk;
                let toastMsg;
                if (isSelfEncryption) {
                    toastMsg = isUrl ? "Encrypted. Store the link anywhere." : "Encrypted. Store the text anywhere.";
                } else {
                    const recipientName = xn || "recipient";
                    toastMsg = isUrl ? `Encrypted. Copy the link and send it to ${recipientName}.` : `Encrypted. Copy the text and send it to ${recipientName}.`;
                }
                showToast(toastMsg, "success");
            } catch (error) {
                showActivityErrorInView("Encryption Failed: " + error, "Encryption Failed!");
                showToast("Encryption failed.", "error");
            }
        }
    }
}

actionButton.addEventListener("click", handleAction);

async function getXipherPublicKeyUrl() {
    const url = window.location.href.split("?")[0];
    const urlWithoutFragment = url.split("#")[0];
    const publicKey = await getPublicKey();
    // Carry the identity's display name along with the bare public key so the
    // sender's "Encrypting for {name}" badge can show who they're encrypting for.
    // The key itself stays in the fragment (never sent to a server); the name
    // rides in the query string, so it is visible to anyone who sees the link.
    const name = (getIdentity().name || "").trim();
    const query = name ? `?xn=${encodeURIComponent(name)}` : "";
    return `${urlWithoutFragment}${query}#${publicKey}`;
}

// Re-derive and display the public link for the current identity, and refresh
// the profile button. Called after the key or password is changed via the
// key-management modal, after the provider flow installs a key, and on load.
//
// With no session yet (Setup not completed), there is no key to derive from, so
// the receive-link stays hidden and only the profile button is refreshed; the
// link is revealed once a key is set. In the sender view (xk present) the link
// section is irrelevant and handled by setupModeUI, so it's left untouched here.
// Tracks whether a local key is set, so the synchronous panel-collapse logic
// knows whether the receive-link may be shown. Updated by refreshIdentity.
let localIdentityReady = false;

async function refreshIdentity() {
    if (typeof renderProfileButton === "function") {
        renderProfileButton();
    }
    localIdentityReady = await hasXipherSession();
    if (!localIdentityReady) {
        if (linkSection && !xk) {
            linkSection.hidden = true;
        }
        return;
    }
    const pubKeyUrl = await getXipherPublicKeyUrl();
    setPublicLink(pubKeyUrl);
    // Reveal the receive-link only in the collapsed self-view. When the workspace
    // is expanded (e.g. decrypting a ciphertext URL after a just-completed Setup),
    // the link is irrelevant and must stay hidden - expandSelfEncryptPanel hid it,
    // and a key-set triggered refreshIdentity must not un-hide it here.
    if (linkSection && !xk && selfEncryptPanel.hidden) {
        linkSection.hidden = false;
    }
}

// Reveal the encrypt/decrypt workspace (self-view). `animate` plays the reveal
// transition; it's skipped when expanding silently (e.g. a pre-filled URL).
function expandSelfEncryptPanel(animate = true) {
    selfEncryptPanel.hidden = false;
    selfEncryptToggle.hidden = true;
    selfEncryptDivider.hidden = true;
    // The shareable receive-link (and its quantum-safe toggle) isn't relevant
    // while encrypting/decrypting in the workspace, so hide it for focus.
    if (linkSection) {
        linkSection.hidden = true;
    }
    selfEncryptToggle.setAttribute("aria-expanded", "true");
    appContainer.classList.remove("is-collapsed");
    if (animate) {
        selfEncryptPanel.classList.add("is-revealing");
        selfEncryptPanel.addEventListener("animationend", () => {
            selfEncryptPanel.classList.remove("is-revealing");
        }, { once: true });
    }
    textInput.focus();
}

// Collapse back to the minimal receive-link view (self-view only).
function collapseSelfEncryptPanel() {
    selfEncryptPanel.hidden = true;
    selfEncryptToggle.hidden = false;
    selfEncryptDivider.hidden = false;
    selfEncryptToggle.setAttribute("aria-expanded", "false");
    appContainer.classList.add("is-collapsed");
    // Restore the receive-link view we hid on expand -but only once a local key
    // is set. Before Setup completes there's no key to build a link from, so it
    // stays hidden behind the mandatory Setup modal.
    if (linkSection) {
        linkSection.hidden = !localIdentityReady;
    }
}

function setupModeUI() {
    if (xk) {
        // The visitor opened someone else's public-key link: they're the sender.
        modeBadgeText.textContent = xn
            ? `Encrypting for ${xn}`
            : "Encrypting for the recipient";
        modeBadge.hidden = false;
        // Reflect the recipient in the page title so the tab is identifiable,
        // preferring the resolved name when the key URL provided one.
        if (xn) {
            document.title = `Encrypting for ${xn} · Xipher`;
        } else {
            document.title = "Encrypting a secret · Xipher";
        }
        // The visitor's own receive-link is not relevant in this flow; the
        // workspace is always shown and the toggle stays hidden.
        if (linkSection) {
            linkSection.hidden = true;
        }
        selfEncryptPanel.hidden = false;
        selfEncryptToggle.hidden = true;
        selfEncryptDivider.hidden = true;
    } else {
        // Default (receiver) view: the badge would just restate what the intro
        // and link label already say, so leave it hidden to save vertical space.
        modeBadge.hidden = true;
        if (linkLabel) {
            linkLabel.textContent = "Share this link to receive a secret";
        }
        // Show only the shareable link; reveal the workspace on demand.
        collapseSelfEncryptPanel();
    }
}

selfEncryptToggle.addEventListener("click", () => expandSelfEncryptPanel());

// Maps a resolver failure reason (the xe value) to a user-facing message.
function keyResolveErrorMessage(reason) {
    switch (reason) {
        case "network":
            return "Couldn't reach that key URL. The host must serve the key over HTTPS and allow cross-origin requests (CORS).";
        case "status":
            return "The key URL returned an error. Check the address and that a key is published there.";
        case "badkey":
            return "That URL didn't serve a valid public key.";
        case "toolarge":
            return "The key URL response was too large.";
        case "timeout":
            return "The key URL took too long to respond.";
        case "invalid":
            return "That public key URL is not valid.";
        default:
            return "Couldn't resolve a public key from that link.";
    }
}

function initApp() {
    const xe = new URLSearchParams(window.location.search).get("xe");
    if (xe) {
        showToast(keyResolveErrorMessage(xe), "error");
    }
    setupModeUI();
    if (!xk) {
        disableActionButton("Waiting for input");
    } else {
        disableActionButton("Encrypt (" + getEncryptionTarget() + ")");
    }
    if (isCT(xt)) {
        // Arrived with ciphertext to decrypt: reveal the workspace and pre-fill it.
        // Decryption itself is fired later (see autoDecryptIfCT) only after the
        // identity gate has a key, so a fresh browser sees Setup first instead of
        // a spurious "Decryption Failed!" toast.
        if (!xk) {
            expandSelfEncryptPanel(false);
        }
        textInput.value = xt;
        updateView();
    }
}

// Fires the automatic decryption for a ciphertext URL. Called after the identity
// gate (ensureLocalIdentity) so a key/passkey is in place; otherwise the decrypt
// would fail and toast before the user ever got to Setup.
async function autoDecryptIfCT() {
    if (isCT(xt)) {
        await handleAction();
    }
}

// pendingAutoReauthUrl returns the provider URL the startup gate would redirect
// to for an automatic re-auth (an ephemeral or expired provider key whose secret
// is gone), or null when no redirect is pending. Pure: reads state without
// consuming it, so main() can decide whether to keep the preloader up BEFORE the
// gate runs. The gate (ensureLocalIdentity) re-derives the same value and owns
// the actual redirect; this only mirrors its detection.
async function pendingAutoReauthUrl() {
    if (await hasXipherSession()) {
        return null;
    }
    const identity = getIdentity();
    return (identity.managed && identity.provider !== "passkey")
        ? identity.provider        // ephemeral: xipherProviderStoreId still holds the URL
        : getLastProviderUrl();    // expiry: stashed before clearStoredIdentity wiped it
}

// Drives the startup identity gate for the receiver view. Three cases:
//  1. A session already exists (persisted key, or in-memory passkey key) -nothing
//     to do.
//  2. A passkey is registered (its key is never persisted): invoke the
//     authenticator directly to re-derive the key. If the user cancels or it
//     fails, fall back to the mandatory Setup modal.
//  3. Nothing set yet: open the mandatory Setup modal so the user picks a method.
async function ensureLocalIdentity(skipReauth = false) {
    if (await hasXipherSession()) {
        return;
    }

    // Auto-reauth: detect a provider-backed identity whose key is gone —
    // either an ephemeral (timeout=0) key that doesn't survive reload, or a
    // credential that expired and was wiped (provider URL stashed before wipe).
    // Shared with main()'s pre-gate check so the loader stays up across the
    // redirect (same detection, single source of truth). skipReauth is set when
    // we just came back from a failed/cancelled provider return — re-redirecting
    // would bounce the user straight back, so we fall through to Setup instead.
    const reauthUrl = skipReauth ? null : await pendingAutoReauthUrl();
    if (reauthUrl) {
        // The stored value is the full provider URL captured at setup time, so it
        // already carries the right scheme (http for loopback dev, https otherwise)
        // and path. Pass it through unchanged; initiateProviderFlow re-validates it.
        clearLastProviderUrl(); // consume stash regardless of flow outcome
        // autoReauth=true: this redirect happens without an explicit user click,
        // so the return path skips the "use this key?" consent.
        const result = await initiateProviderFlow(reauthUrl, false, true, reauthUrl);
        // "redirecting" means the overlay committed the navigation; the page is
        // tearing down, so return without opening any modal (it would flash over
        // the redirect). Anything else — invalid URL, declined trust, or the user
        // hitting Cancel on the countdown — falls through to the Setup modal so a
        // key can still be set manually.
        if (result === "redirecting") {
            return;
        }
        await openKeyModal(true);
        return;
    }

    // Passkey auto-unlock.
    if (typeof hasPasskeyConfigured === "function" && hasPasskeyConfigured()) {
        try {
            await unlockWithPasskey();
            await refreshIdentity();
            showToast("Key derived from your passkey.", "success");
            return;
        } catch (err) {
            let statusMessage = null;
            if (typeof handlePasskeyError === "function") {
                statusMessage = handlePasskeyError(err, "unlock");
            }
            await openKeyModal(true, statusMessage);
            return;
        }
    }

    // Fresh browser: mandatory Setup.
    await openKeyModal(true);
}

function hidePreloader() {
    preLoader.classList.remove("preloader-redirecting");
    preLoader.classList.add("hidden");
    setTimeout(() => preLoader.remove(), PRELOADER_FADE_MS);
}

// Seconds the redirect overlay stays up, counting down, before navigating. Long
// enough to read the destination and hit Cancel; short enough not to feel stuck.
const REDIRECT_DELAY_SECONDS = 3;

// showRedirecting keeps the preloader up (or brings it back) and swaps its text
// to tell the user a navigation to an external credential provider is underway,
// so the brief blank moment before window.location.replace isn't unexplained.
function renderRedirectingText(text, prefix, highlight, suffix) {
    if (!text) {
        return;
    }
    text.textContent = "";
    text.append(document.createTextNode(prefix || "Redirecting to "));
    if (highlight) {
        const strong = document.createElement("strong");
        strong.className = "preloader-text-strong";
        strong.textContent = highlight;
        text.append(strong);
    }
    if (suffix) {
        text.append(document.createTextNode(suffix));
    }
}

function showRedirecting(message, highlight, suffix) {
    if (!preLoader) {
        return;
    }
    if (!preLoader.isConnected) {
        document.body.appendChild(preLoader);
    }
    preLoader.classList.remove("hidden");
    const text = preLoader.querySelector(".preloader-text");
    if (text) {
        if (highlight) {
            renderRedirectingText(text, message, highlight, suffix || "");
        } else {
            text.textContent = message || "Redirecting…";
        }
    }
}

// redirectWithCancel shows the redirect overlay with a live countdown plus
// Continue/Cancel actions, then navigates to `target` when the countdown elapses
// or Continue is clicked. Returns a promise that resolves "redirecting" once
// navigation is committed, or "cancelled" if the user backs out (the caller then
// cleans up and falls through to the normal gate). `label` is the message shown
// above the countdown (e.g. "Redirecting to provider.example…").
function redirectWithCancel(target, label, onCancel, highlight) {
    return new Promise((resolve) => {
        const text = preLoader && preLoader.querySelector(".preloader-text");
        const actions = document.getElementById("preloader-actions");
        const continueBtn = document.getElementById("preloader-continue");
        const cancelBtn = document.getElementById("preloader-cancel");
        if (preLoader) {
            preLoader.classList.add("preloader-redirecting");
        }
        showRedirecting(label, highlight);

        let remaining = REDIRECT_DELAY_SECONDS;
        let timer = null;

        const render = () => {
            if (text) {
                if (highlight) {
                    renderRedirectingText(text, label, highlight, ` (${remaining})`);
                } else {
                    text.textContent = `${label} (${remaining})`;
                }
            }
        };

        const cleanup = (keepReservedSpace) => {
            if (timer !== null) {
                clearInterval(timer);
                timer = null;
            }
            if (!keepReservedSpace && preLoader) {
                preLoader.classList.remove("preloader-redirecting");
            }
            if (actions) {
                actions.hidden = true;
            }
            if (continueBtn) {
                continueBtn.onclick = null;
            }
            if (cancelBtn) {
                cancelBtn.onclick = null;
            }
        };

        const commitNavigation = () => {
            // Commit the navigation now. Drop the countdown suffix and keep the
            // action row hidden while the browser leaves the page.
            cleanup(true);
            if (text) {
                if (highlight) {
                    renderRedirectingText(text, label, highlight);
                } else {
                    text.textContent = label;
                }
            }
            window.location.replace(target);
            resolve("redirecting");
        };

        if (actions) {
            actions.hidden = false;
        }
        if (continueBtn) {
            continueBtn.onclick = commitNavigation;
        }
        if (cancelBtn) {
            cancelBtn.onclick = () => {
                cleanup(false);
                if (typeof onCancel === "function") {
                    onCancel();
                }
                resolve("cancelled");
            };
        }

        render();
        timer = setInterval(() => {
            remaining -= 1;
            if (remaining > 0) {
                render();
                return;
            }
            commitNavigation();
        }, 1000);
    });
}

async function main() {
    if (redirecting) {
        // We're navigating to the /resolve/ page; don't initialize the app.
        return;
    }
    loadTheme();
    await loadXipherWASM();

    // Per-credential timeout: wipe a stored key/identity whose sliding deadline
    // has passed (or is implausibly far out, i.e. tampered), and slide the
    // deadline forward on a normal visit. Runs before the provider flow so a key
    // freshly delivered in this same load (which writes after this point) is
    // never collected.
    const timeoutResult = await enforceCredentialTimeout();
    if (timeoutResult === "expired") {
        showToast("Your session timed out and the stored key was cleared.", "info", 4000);
    } else if (timeoutResult === "suspicious") {
        showToast("Suspicious activity detected: the stored session looked tampered, so it was cleared.", "error", 5000);
    }

    // The credential-provider flow may redirect away (when initiating) or update
    // the stored identity in place (on return). Run it before deriving the public
    // key so a freshly delivered key is reflected immediately.
    const providerFlow = await handleProviderFlow();
    if (providerFlow === "redirecting") {
        return;
    }
    // A failed/cancelled provider return (the provider or user declined). The
    // stored identity may still point at that provider, so auto-reauth would
    // immediately bounce the user straight back into the flow they just left.
    // Suppress auto-reauth for THIS load and let the gate open Setup/Profile
    // instead; a later deliberate reload can retry.
    const skipReauth = providerFlow === "return-failed";
    await refreshIdentity();
    initApp();
    // Passkey UI needs WASM loaded (genXipherSecretKeyFromSeed) and a platform
    // authenticator check. Run it before the gate so the Setup modal's passkey tab
    // is ready when the user interacts with it.
    if (typeof initPasskeyUI === "function") {
        initPasskeyUI();
    }
    // Decide the redirect BEFORE touching the preloader. When an automatic
    // provider re-auth is pending, the gate will navigate away to the provider;
    // keep the loader up and swap its text to "Redirecting…" so the home page
    // never flashes in the gap before navigation (which could invite a stray
    // click). Otherwise hide it: ensureLocalIdentity may block on the mandatory
    // Setup modal, which can only be completed once visible — leaving the loader
    // up there would cover the modal and deadlock the load. (openKeyModal also
    // hides it defensively, covering provider-flow declines that fall to Setup.)
    const reauthUrl = (!xk && !skipReauth) ? await pendingAutoReauthUrl() : null;
    if (reauthUrl) {
        let host = "your provider";
        try { host = new URL(reauthUrl).host; } catch (e) { /* keep fallback */ }
        showRedirecting("Redirecting to ", host, "…");
    } else {
        hidePreloader();
    }
    // Gate the receiver view on having a key: a fresh browser must consciously
    // set one (no silently-generated random secret). A non-persisted passkey
    // identity must be re-unlocked on every open, since its key lives only in
    // memory. The sender view (xk present) encrypts with the recipient's public
    // key and needs no local key, so it's exempt.
    //
    // The gate runs BEFORE auto-decryption so a ciphertext URL opened in a fresh
    // browser shows Setup (or the passkey-unlock prompt) first, then decrypts once
    // a key exists - rather than firing decryption immediately and failing.
    if (!xk) {
        await ensureLocalIdentity(skipReauth);
    }
    await autoDecryptIfCT();
}

if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/js/service-worker.js')
            .then(registration => {
                console.log('ServiceWorker registered: ', registration);
            })
            .catch(error => {
                console.log('ServiceWorker registration failed: ', error);
            });
    });
}

window.addEventListener("beforeunload", function (e) {
    if (currentProcessor && !currentProcessor.isEnded()) {
        e.preventDefault();
    }
});

// The URL params (xk/xt/xn) are resolved once at load, so pasting a new fragment
// link into the address bar of an already-open app wouldn't switch the view
// (encrypt vs decrypt) on its own. A fragment change is only ever user-driven
// here - programmatic resets use history.replaceState, which doesn't fire
// hashchange - so reloading lets the normal load flow re-resolve everything.
// If a file transfer is mid-flight, leave it alone rather than interrupting it.
window.addEventListener("hashchange", function () {
    if (currentProcessor && !currentProcessor.isEnded()) {
        return;
    }
    window.location.reload();
});

main();
