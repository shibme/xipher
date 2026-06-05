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
const { xk, xt } = initParams();

function initParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const xk = urlParams.get("xk");
    const xt = urlParams.get("xt");
    if (xk || xt) {
        return { xk, xt };
    }
    const fragment = window.location.hash.substring(1);
    if (fragment) {
        if (fragment.startsWith("XCT_")) {
            return { xk: null, xt: fragment };
        } else if (fragment.startsWith("XPK_") || fragment.startsWith("XSK_")) {
            return { xk: fragment, xt: null };
        }
    }
    return { xk: null, xt: null };
}

function getEncryptionTarget() {
    if (!xk) {
        return "with your Key";
    }
    if (xk.startsWith("XPK_")) {
        return `with ${xk.substring(0, 16)}..`;
    } else {
        return "with given Secret Key";
    }
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
            showToast("File encrypted successfully.", "success");
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
                showToast("Encrypted successfully.", "success");
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

// Re-derive and display the public link for the current identity. Called after
// the key or password is changed via the key-management modal.
async function refreshIdentity() {
    const pubKeyUrl = await getXipherPublicKeyUrl();
    setPublicLink(pubKeyUrl);
}

function setupModeUI() {
    if (xk) {
        // The visitor opened someone else's public-key link: they're the sender.
        modeBadgeText.textContent = "Encrypting for the shared recipient";
        modeBadge.hidden = false;
        // The visitor's own receive-link is not relevant in this flow.
        if (linkSection) {
            linkSection.hidden = true;
        }
    } else {
        modeBadgeText.textContent = "Your private workspace · keys stay in this browser";
        modeBadge.hidden = false;
        if (linkLabel) {
            linkLabel.textContent = "Share this link so others can send you a secret";
        }
    }
}

function initApp() {
    setupModeUI();
    if (!xk) {
        disableActionButton("Waiting for input");
    } else {
        disableActionButton("Encrypt (" + getEncryptionTarget() + ")");
    }
    if (isCT(xt)) {
        textInput.value = xt;
        updateView();
    }
}

function hidePreloader() {
    preLoader.classList.add("hidden");
    setTimeout(() => preLoader.remove(), PRELOADER_FADE_MS);
}

async function main() {
    loadTheme();
    await loadXipherWASM();
    const pubKeyUrl = await getXipherPublicKeyUrl();
    setPublicLink(pubKeyUrl);
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
