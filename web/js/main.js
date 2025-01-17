const preLoader = document.getElementById("preloader");
const textInput = document.getElementById("text");
const fileInput = document.getElementById("file");
const textActionButton = document.getElementById("text-action-button");
const fileDisplay = document.getElementById("file-display");
const fileNameElement = document.getElementById("file-name");
const fileSizeElement = document.getElementById("file-size");
const actionButton = document.getElementById("action-button");
const formTitle = document.getElementById("form-title");
const urlParams = new URLSearchParams(window.location.search);
const xk = urlParams.get("xk");
const xt = urlParams.get("xt");
const linkViewbox = document.getElementById("link-viewbox");
const shareableLink = document.getElementById("shareable-link");
const textCopyButton = document.getElementById("text-copy-button");
const textShareButton = document.getElementById("text-share-button");
const publinkCopyButton = document.getElementById("publink-copy-button");

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

// Disable the button with a specific text
function disableActionButton(placeholderText) {
    actionButton.disabled = true;
    actionButton.textContent = placeholderText;
    actionButton.className = "app-button grey-button";
}

// Enable the button with appropriate styles
function enableActionButton(isDecryptMode) {
    actionButton.disabled = false;
    actionButton.textContent = isDecryptMode ? "Decrypt with Your Key" : "Encrypt (" + getEncryptionTarget() + ")";
    actionButton.className = `app-button ${isDecryptMode ? "decrypt-button" : "encrypt-button"}`;
    actionButton.hidden = false;
}

// Toggle attachment logic
function toggleAttachment() {
    const textActionButtonText = textActionButton.textContent.trim();
    if (textActionButtonText === "Pick File") {
        fileInput.click();
    } else {
        resetView();
    }
}

// Utility: Convert file size to human-readable format
function humanReadableFileSize(size) {
    const i = Math.floor(Math.log(size) / Math.log(1024));
    const units = ["Bytes", "KiB", "MiB", "GiB", "TiB"];
    const value = size / Math.pow(1024, i);
    const formattedValue = i === 0 ? value.toFixed(0) : value.toFixed(2);
    return `${formattedValue} ${units[i]}`;
}

function truncateFileName(name, length) {
    if (name.length > length) {
        return name.substring(0, length) + "...";
    }
    return name;
}

function setPublicLink(url) {
    shareableLink.value = url;
    linkViewbox.style.display = "flex";
}

function copyPublicKeyLinkToClipboard() {
    navigator.clipboard.writeText(shareableLink.value).then(() => {
        publinkCopyButton.classList.add("icon-button-fade");
        setTimeout(() => {
            publinkCopyButton.classList.remove("icon-button-fade");
            setTimeout(() => (copyMessage.hidden = true), 300);
        }, 2000);
    }).catch((err) => {
        console.error("Failed to copy Public Key URL: ", err);
    });
}

function sharePublicKeyLink() {
    if (navigator.share) {
        navigator
            .share({
                url: shareableLink.value,
            })
            .catch((error) => console.error("Error sharing link:", error));
    } else {
        alert("Sharing is not supported in this browser.");
    }
}

function handleFileSelect() {
    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const fileSize = humanReadableFileSize(file.size);
        textInput.value = "";
        textInput.setAttribute("readonly", true);
        textInput.placeholder = "Click to switch to text mode";
        const truncatedName = truncateFileName(file.name, 25);
        fileNameElement.textContent = truncatedName;
        fileNameElement.title = file.name;
        fileSizeElement.textContent = fileSize;
        fileDisplay.style.display = "flex";
        textActionButton.textContent = "Reset";
        textActionButton.className = "app-button reset-content-button";
        updateView();
    }
}

function resetView() {
    textCopyButton.style.display = "none";
    textShareButton.style.display = "none";
    fileInput.value = "";
    textInput.value = "";
    textInput.classList.remove("text-error");
    textInput.removeAttribute("readonly");
    textInput.placeholder = "Type your text here or drag/drop a file";
    textActionButton.textContent = "Pick File";
    textActionButton.className = "app-button select-file-button";
    fileDisplay.style.display = "none";
    updateView();
}

function setReadableTextView(text, enableShareButton, disabledActionButtonLabel) {
    if (text) {
        fileInput.value = "";
        textInput.value = text;
        textInput.setAttribute("readonly", true);
        textCopyButton.style.display = "block";
        if (enableShareButton) {
            textShareButton.style.display = "block";
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

function showActivitySuccessInView(error, disabledActionButtonLabel) {
    textInput.value = error;
    textInput.classList.remove("text-error");
    textInput.classList.add("text-success");
    textInput.setAttribute("readonly", true);
    textActionButton.textContent = "Reset";
    textActionButton.className = "app-button reset-content-button";
    disableActionButton(disabledActionButtonLabel);
}

// Reset attachment on textarea click
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
            ct = url.searchParams.get("xt") || possibleCt;
        } catch (error) {
            console.error("Failed to parse url: ", error);
        }
    }
    return ct.startsWith("XCT_");
}

// Update view based on input field changes
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

function copyTextToClipboard() {
    const text = textInput.value.trim();
    if (!text) {
        alert("There's no text to copy.");
        return;
    }
    navigator.clipboard.writeText(text).then(() => {
        textCopyButton.classList.add("icon-button-fade");
        setTimeout(() => {
            textCopyButton.classList.remove("icon-button-fade");
            setTimeout(() => (copyMessage.hidden = true), 300);
        }, 2000);
    }).catch((err) => {
        console.error("Failed to copy text: ", err);
    });
}

function shareText() {
    const text = textInput.value.trim();
    if (!text) {
        alert("There's no text to share.");
        return;
    }
    if (navigator.share) {
        navigator
            .share({
                text: text,
            })
            .catch((error) => console.error("Error sharing:", error));
    } else {
        alert("Sharing is not supported in this browser.");
    }
}

async function encryptStrToUrlCT(key, str) {
    const ct = await encryptStr(key, str);
    const url = window.location.href.split("?")[0];
    const urlCT = `${url}?xt=${ct}`;
    if (urlCT.length < 2000) {
        return urlCT;
    } else {
        return ct;
    }
}

async function decryptStrFromUrlCt(key, urlCT) {
    let ct = urlCT;
    if (ct.startsWith("http")) {
        const url = new URL(urlCT);
        ct = url.searchParams.get("xt") || urlCT;
    }
    return await decryptStr(key, ct);
}

let currentProcessor = null;

async function cancelCurrentStreamProcessing() {
    if (currentProcessor) {
        currentProcessor.cancel();
        while (!currentProcessor.isEnded()) {
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }
    console.log("Processing cancelled!");
}

async function handleFileEncryption(key, file, compress) {
    const fileSize = file.size;
    const outFileName = file.name.endsWith('.xipher') ? file.name : file.name + '.xipher';
    const fileOutStream = streamSaver.createWriteStream(outFileName, {
        size: fileSize
    });
    actionButton.classList.add("animate");
    const progressCallback = (processedSize, status) => {
        if (status === XipherStreamStatus.PROCESSING) {
            actionButton.textContent = "Encrypting (" + Math.floor((processedSize / fileSize) * 100) + "%)";
        } else if (status === XipherStreamStatus.COMPLETED) {
            showActivitySuccessInView("Encrypted as: " + outFileName, "Encryption Complete");
        } else if (status === XipherStreamStatus.FAILED) {
            showActivityErrorInView("Encryption Failed!", "Encryption Failed!");
        } else if (status === XipherStreamStatus.CANCELLING) {
            showActivityErrorInView("Canceling Encryption...", "Encryption Canceling...");
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
    const fileOutStream = streamSaver.createWriteStream(outFileName, {
        size: fileSize
    });
    actionButton.classList.add("animate");
    const progressCallback = (processedSize, status) => {
        if (status === XipherStreamStatus.PROCESSING) {
            actionButton.textContent = "Decrypting (" + Math.floor((processedSize / fileSize) * 100) + "%)";
        } else if (status === XipherStreamStatus.COMPLETED) {
            showActivitySuccessInView("Decrypted as: " + outFileName, "Decryption Complete");
        } else if (status === XipherStreamStatus.FAILED) {
            showActivityErrorInView("Decryption Failed!", "Decryption Failed!");
        } else if (status === XipherStreamStatus.CANCELLING) {
            showActivityErrorInView("Canceling Decryption...", "Decryption Canceling...");
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
                const pt = await decryptStrFromUrlCt(key, text);
                setReadableTextView(pt, false, "Decrypted with your Key");
            } catch (error) {
                showActivityErrorInView("Decryption Failed!", "Decryption Failed!");
            }
        } else {
            try {
                const key = xk ? xk : await getXipherSecret();
                const ct = await encryptStrToUrlCT(key, text);
                setReadableTextView(ct, true, "Encrypted (" + getEncryptionTarget() + ")");
            } catch (error) {
                showActivityErrorInView("Encryption Failed: " + error, "Encryption Failed!");
            }
        }
    }
}

async function getXipherPublicKeyUrl() {
    const url = window.location.href.split("?")[0];
    const publicKey = await getPublicKey();
    return `${url}?xk=${publicKey}`;
}

function initApp() {
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

async function main() {
    loadTheme();
    await loadXipherWASM();
    const pubKeyUrl = await getXipherPublicKeyUrl();
    setPublicLink(pubKeyUrl);
    initApp();
    preLoader.remove();
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