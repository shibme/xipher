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
            return { xk: fragRef.pubKey, xt: null };
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

function disableActionButton(placeholderText) {
    actionButton.disabled = true;
    actionButton.textContent = placeholderText;
    actionButton.className = "app-button grey-button";
}

function enableActionButton(isDecryptMode) {
    actionButton.disabled = false;
    actionButton.textContent = isDecryptMode ? "Decrypt with Your Key" : "Encrypt (" + getEncryptionTarget() + ")";
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
        fileDisplay.style.display = "flex";
        textActionButton.textContent = "Reset";
        textActionButton.className = "app-button reset-content-button";
        updateView();
    }
}

fileInput.addEventListener("change", handleFileSelect);

function resetView() {
    textCopyButton.style.display = "none";
    textShareButton.style.display = "none";
    fileInput.value = "";
    textInput.value = "";
    textInput.classList.remove("text-error", "text-success");
    textInput.removeAttribute("readonly");
    textInput.placeholder = "Type or paste text here, or drag & drop a file to encrypt / decrypt";
    textActionButton.textContent = "Pick a file";
    textActionButton.className = "app-button select-file-button";
    fileDisplay.style.display = "none";
    updateView();
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
        textCopyButton.style.display = "inline-flex";
        if (enableShareButton) {
            textShareButton.style.display = "inline-flex";
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
    return `${urlWithoutFragment}#${publicKey}`;
}

// Re-derive and display the public link for the current identity, and refresh
// the profile button. Called after the key or password is changed via the
// key-management modal, after the provider flow installs a key, and on load.
async function refreshIdentity() {
    const pubKeyUrl = await getXipherPublicKeyUrl();
    setPublicLink(pubKeyUrl);
    if (typeof renderProfileButton === "function") {
        renderProfileButton();
    }
}

// Reveal the encrypt/decrypt workspace (self-view). `animate` plays the reveal
// transition; it's skipped when expanding silently (e.g. a pre-filled URL).
function expandSelfEncryptPanel(animate = true) {
    selfEncryptPanel.hidden = false;
    selfEncryptToggle.hidden = true;
    selfEncryptDivider.hidden = true;
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
}

function setupModeUI() {
    if (xk) {
        // The visitor opened someone else's public-key link: they're the sender.
        modeBadgeText.textContent = xn
            ? `Encrypting for ${xn}`
            : "Encrypting for the shared recipient";
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
        // Arrived with ciphertext to decrypt: reveal the workspace immediately
        // (no reveal animation, since it's the landing state) and pre-fill it.
        if (!xk) {
            expandSelfEncryptPanel(false);
        }
        textInput.value = xt;
        updateView();
    }
}

function hidePreloader() {
    preLoader.classList.add("hidden");
    setTimeout(() => preLoader.remove(), PRELOADER_FADE_MS);
}

async function main() {
    if (redirecting) {
        // We're navigating to the /resolve/ page; don't initialize the app.
        return;
    }
    loadTheme();
    await loadXipherWASM();
    // The credential-provider flow may redirect away (when initiating) or update
    // the stored identity in place (on return). Run it before deriving the public
    // key so a freshly delivered key is reflected immediately.
    if (await handleProviderFlow() === "redirecting") {
        return;
    }
    await refreshIdentity();
    initApp();
    hidePreloader();
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

main();
