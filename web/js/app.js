const loader = document.getElementById("loader");
const loaderText = document.getElementById("loader-text");
const textInput = document.getElementById("text");
const fileInput = document.getElementById("file");
const textActionButton = document.getElementById("text-action-button");
const fileDisplay = document.getElementById("file-display");
const fileNameElement = document.getElementById("file-name");
const fileSizeElement = document.getElementById("file-size");
const dropArea = document.getElementById("drop-area");
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

// Toggle theme
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);

    const toggleCircle = document.querySelector(".theme-toggle .toggle-circle");
    if (newTheme === "dark") {
        toggleCircle.setAttribute("title", "Switch to Light Mode");
    } else {
        toggleCircle.setAttribute("title", "Switch to Dark Mode");
    }
}

// Load persisted theme
function loadTheme() {
    const storedTheme = localStorage.getItem("theme");
    const theme = storedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
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

// Disable the button with a specific text
function disableActionButton(placeholderText) {
    actionButton.disabled = true;
    actionButton.textContent = placeholderText;
    actionButton.className = "regular-button grey-button";
}

// Enable the button with appropriate styles
function enableActionButton(isDecryptMode) {
    actionButton.disabled = false;
    actionButton.textContent = isDecryptMode ? "Decrypt with Your Key" : "Encrypt (" + getEncryptionTarget() + ")";
    actionButton.className = `regular-button ${isDecryptMode ? "decrypt-button" : "encrypt-button"}`;
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

// Utility: Truncate file name
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
        textActionButton.className = "regular-button reset-content-button";

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
    textActionButton.className = "regular-button select-file-button";
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
        textActionButton.className = "regular-button reset-content-button";
        disableActionButton(disabledActionButtonLabel);
    }
}

function showActivityErrorInView(error, disabledActionButtonLabel) {
    textInput.value = error;
    textInput.classList.add("text-error");
    textInput.setAttribute("readonly", true);
    textActionButton.textContent = "Reset";
    textActionButton.className = "regular-button reset-content-button";
    disableActionButton(disabledActionButtonLabel);
}

function showActivitySuccessInView(error, disabledActionButtonLabel) {
    textInput.value = error;
    textInput.classList.add("text-success");
    textInput.setAttribute("readonly", true);
    textActionButton.textContent = "Reset";
    textActionButton.className = "regular-button reset-content-button";
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

// Handle drag-and-drop functionality
dropArea.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropArea.classList.add("dragover");
});

dropArea.addEventListener("dragleave", () => {
    dropArea.classList.remove("dragover");
});

dropArea.addEventListener("drop", (event) => {
    event.preventDefault();
    dropArea.classList.remove("dragover");

    const droppedFiles = event.dataTransfer.files;
    if (droppedFiles.length > 0) {
        fileInput.files = droppedFiles;
        handleFileSelect();
    }
});

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

async function handleFileEncryption(key, file, compress) {
    const outputFileOpts = {
        suggestedName: file.name.endsWith('.xipher') ? file.name : file.name + '.xipher',
        types: [{
            description: 'Encrypted Files',
            accept: {'application/octet-stream': ['.xipher']}
        }]
    };
    let filePickerHandle;
    try {
        filePickerHandle = await window.showSaveFilePicker(outputFileOpts);
    } catch (error) {
        showActivityErrorInView("File operations not supported on this device.", "Operation Failed!");
        return;
    }
    const outStream = await filePickerHandle.createWritable();
    const fileSize = file.size;
    actionButton.classList.add("animate");
    const progressCallback = (processedSize, status) => {
        if (status === XipherStreamStatus.PROCESSING) {
            actionButton.textContent = "Encrypting (" + Math.floor((processedSize / fileSize) * 100) + "%)";
        } else if (status === XipherStreamStatus.COMPLETED) {
            showActivitySuccessInView("Encrypted as: " + outFileName, "Encryption Complete");
        } else if (status === XipherStreamStatus.FAILED) {
            showActivityErrorInView("Encryption Failed! Please remove the incomplete file (" + outFileName + ")", "Encryption Failed!");
        }
    };
    await encryptFile(key, file, compress, outStream, progressCallback);
    actionButton.classList.remove("animate");
}

async function handleFileDecryption(key, file) {
    const outputFileOpts = {
        suggestedName: file.name.replace(/\.xipher$/, ''),
    };
    let filePickerHandle;
    try {
        filePickerHandle = await window.showSaveFilePicker(outputFileOpts);
    } catch (error) {
        showActivityErrorInView("File operations not supported on this device.", "Operation Failed!");
        return;
    }
    outFileName = filePickerHandle.name;
    const outStream = await filePickerHandle.createWritable();
    const fileSize = file.size;
    actionButton.classList.add("animate");
    const progressCallback = (processedSize, status) => {
        if (status === XipherStreamStatus.PROCESSING) {
            actionButton.textContent = "Decrypting (" + Math.floor((processedSize / fileSize) * 100) + "%)";
        } else if (status === XipherStreamStatus.COMPLETED) {
            showActivitySuccessInView("Decrypted as: " + outFileName, "Decryption Complete");
        } else if (status === XipherStreamStatus.FAILED) {
            showActivityErrorInView("Decryption Failed! Please remove the incomplete file (" + outFileName + ")", "Decryption Failed!");
        }
    };
    await decryptFile(key, file, outStream, progressCallback);
    actionButton.classList.remove("animate");
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
    const publicKey = await getXipherPublicKey();
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
    loader.remove();
}

main();