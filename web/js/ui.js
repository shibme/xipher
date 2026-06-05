/* ==========================================================================
   Theme
   ========================================================================== */

const themeToggleBtn = document.getElementById("theme-toggle");

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
}

themeToggleBtn.addEventListener("click", toggleTheme);

function loadTheme() {
    const storedTheme = localStorage.getItem("theme");
    const theme = storedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
}

/* ==========================================================================
   Toast notifications
   ========================================================================== */

const toastContainer = document.getElementById("toast-container");

const TOAST_DEFAULT_DURATION = 2600;
// Delay before removing the toast; covers its fade-out transition in objects.css (0.25s).
const TOAST_FADE_MS = 300;
// How long the copy icon stays faded as success feedback.
const COPY_FEEDBACK_MS = 1500;

function showToast(message, type = "info", duration = TOAST_DEFAULT_DURATION) {
    if (!toastContainer) {
        return;
    }
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
    // Force reflow so the transition runs.
    void toast.offsetWidth;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), TOAST_FADE_MS);
    }, duration);
}

// Copy helper shared across the app.
async function copyToClipboard(value, button, successMessage) {
    if (!value) {
        showToast("Nothing to copy.", "error");
        return;
    }
    try {
        await navigator.clipboard.writeText(value);
        if (button) {
            button.classList.add("icon-button-fade");
            setTimeout(() => button.classList.remove("icon-button-fade"), COPY_FEEDBACK_MS);
        }
        showToast(successMessage || "Copied to clipboard.", "success");
    } catch (err) {
        console.error("Copy failed:", err);
        showToast("Copy failed. Please copy manually.", "error");
    }
}

/* ==========================================================================
   Drag & drop
   ========================================================================== */

const dropArea = document.getElementById("drop-area");

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

/* ==========================================================================
   Key / password management modal
   ========================================================================== */

const keyModal = document.getElementById("key-modal");
const keySettingsButton = document.getElementById("key-settings-button");
const keyModalClose = document.getElementById("key-modal-close");
const keyModalCancel = document.getElementById("key-modal-cancel");
const keySaveButton = document.getElementById("key-save-button");
const keyCurrentPubkey = document.getElementById("key-current-pubkey");
const keyPubkeyCopy = document.getElementById("key-pubkey-copy");
const keyTabs = Array.from(document.querySelectorAll(".key-tab"));
const keyPanels = Array.from(document.querySelectorAll(".key-panel"));
const keyPasswordInput = document.getElementById("key-password-input");
const keyPasswordConfirm = document.getElementById("key-password-confirm");
const keyPasswordReveal = document.getElementById("key-password-reveal");
const keySecretKeyInput = document.getElementById("key-secretkey-input");
const keyGenerateRandom = document.getElementById("key-generate-random");
const generatedKeyBox = document.getElementById("generated-key-box");
const generatedKeyValue = document.getElementById("generated-key-value");
const generatedKeyCopy = document.getElementById("generated-key-copy");
const quantumSafeToggle = document.getElementById("quantum-safe-toggle");

let activeKeyTab = "password";

function setActiveKeyTab(tab) {
    activeKeyTab = tab;
    keyTabs.forEach((t) => t.classList.toggle("is-active", t.dataset.tab === tab));
    keyPanels.forEach((p) => p.classList.toggle("is-active", p.dataset.panel === tab));
}

keyTabs.forEach((tab) => {
    tab.addEventListener("click", () => setActiveKeyTab(tab.dataset.tab));
});

async function openKeyModal() {
    // Reset transient inputs.
    keyPasswordInput.value = "";
    keyPasswordConfirm.value = "";
    keySecretKeyInput.value = "";
    keyPasswordInput.type = "password";
    generatedKeyBox.hidden = true;
    generatedKeyValue.value = "";
    setActiveKeyTab("password");
    quantumSafeToggle.checked = isQuantumSafe();
    try {
        keyCurrentPubkey.value = await getPublicKey();
    } catch (error) {
        keyCurrentPubkey.value = "";
    }
    keyModal.hidden = false;
    document.body.style.overflow = "hidden";
}

function closeKeyModal() {
    keyModal.hidden = true;
    document.body.style.overflow = "";
}

keySettingsButton.addEventListener("click", openKeyModal);
keyModalClose.addEventListener("click", closeKeyModal);
keyModalCancel.addEventListener("click", closeKeyModal);

keyModal.addEventListener("click", (event) => {
    if (event.target === keyModal) {
        closeKeyModal();
    }
});

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !keyModal.hidden) {
        closeKeyModal();
    }
});

keyPasswordReveal.addEventListener("click", () => {
    const reveal = keyPasswordInput.type === "password";
    keyPasswordInput.type = reveal ? "text" : "password";
    keyPasswordConfirm.type = reveal ? "text" : "password";
});

keyPubkeyCopy.addEventListener("click", () => {
    copyToClipboard(keyCurrentPubkey.value, keyPubkeyCopy, "Public key copied.");
});

generatedKeyCopy.addEventListener("click", () => {
    copyToClipboard(generatedKeyValue.value, generatedKeyCopy, "Secret key copied.");
});

keyGenerateRandom.addEventListener("click", async () => {
    try {
        const newKey = await genXipherSecretKey();
        generatedKeyValue.value = newKey;
        generatedKeyBox.hidden = false;
        showToast("New key generated. Save it, then click Save & apply.", "info", 3200);
    } catch (error) {
        showToast("Failed to generate key.", "error");
    }
});

// Basic password strength check mirroring the CLI policy intent.
function validatePassword(pwd) {
    if (pwd.length < 8) {
        return "Use at least 8 characters for your password.";
    }
    return null;
}

async function handleKeySave() {
    keySaveButton.disabled = true;
    try {
        let newSecret = null;
        if (activeKeyTab === "password") {
            const pwd = keyPasswordInput.value;
            const confirm = keyPasswordConfirm.value;
            if (!pwd) {
                showToast("Enter a password.", "error");
                return;
            }
            const err = validatePassword(pwd);
            if (err) {
                showToast(err, "error");
                return;
            }
            if (pwd !== confirm) {
                showToast("Passwords do not match.", "error");
                return;
            }
            newSecret = pwd;
        } else if (activeKeyTab === "secretkey") {
            const sk = keySecretKeyInput.value.trim();
            if (!sk) {
                showToast("Paste a secret key.", "error");
                return;
            }
            if (!(await isValidSecretKey(sk))) {
                showToast("That doesn't look like a valid secret key (XSK_…).", "error");
                return;
            }
            newSecret = sk;
        } else if (activeKeyTab === "random") {
            const gk = generatedKeyValue.value.trim();
            if (!gk) {
                showToast("Generate a key first.", "error");
                return;
            }
            newSecret = gk;
        }

        const quantumChanged = setQuantumSafe(quantumSafeToggle.checked);

        if (newSecret !== null) {
            await setXipherSecret(newSecret);
        } else if (!quantumChanged) {
            showToast("Nothing to update.", "info");
            return;
        }

        // Refresh the shareable link and app state with the new identity.
        if (typeof refreshIdentity === "function") {
            await refreshIdentity();
        }
        showToast("Your key has been updated.", "success");
        closeKeyModal();
    } catch (error) {
        console.error("Failed to save key:", error);
        showToast("Failed to update key.", "error");
    } finally {
        keySaveButton.disabled = false;
    }
}

keySaveButton.addEventListener("click", handleKeySave);
