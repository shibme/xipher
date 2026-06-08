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
const keySettingsButton = document.getElementById("settings-button");
const keyModalClose = document.getElementById("key-modal-close");
const keyModalCancel = document.getElementById("key-modal-cancel");
const keySaveButton = document.getElementById("key-save-button");
const keyCurrentPubkey = document.getElementById("key-current-pubkey");
const keyPubkeyCopy = document.getElementById("key-pubkey-copy");
const keySecretInput = document.getElementById("key-secret-input");
const keySecretReveal = document.getElementById("key-secret-reveal");
const keySecretGenerate = document.getElementById("key-secret-generate");
const quantumSafeToggle = document.getElementById("quantum-safe-toggle");
const profileButton = document.getElementById("settings-button");
const profileButtonName = document.getElementById("profile-button-name");
const profileButtonInitials = document.getElementById("profile-button-initials");
const identityName = document.getElementById("identity-name");
const identityContact = document.getElementById("identity-contact");
const identityProvider = document.getElementById("identity-provider");
const identityNameInput = document.getElementById("identity-name-input");
const identityNameManaged = document.getElementById("identity-name-managed");

// Derives up to two uppercase initials from a display name (e.g. "Alice Example"
// -> "AE", "shibme" -> "S"). Falls back to "" when there's nothing usable.
function initialsFromName(name) {
    const words = (name || "").trim().split(/\s+/).filter(Boolean);
    if (words.length === 0) {
        return "";
    }
    const first = Array.from(words[0])[0] || "";
    const last = words.length > 1 ? (Array.from(words[words.length - 1])[0] || "") : "";
    return (first + last).toUpperCase();
}

// Reflects the current identity onto the topbar profile button. With a name set,
// the button shows the name beside the icon on wider screens; on narrow viewports
// it collapses to a round badge with the initials (see the has-name styles). With
// no name it stays the plain round icon button.
function renderProfileButton() {
    const { name } = getIdentity();
    if (name) {
        profileButtonName.textContent = name;
        profileButtonName.hidden = false;
        profileButtonInitials.textContent = initialsFromName(name);
        profileButton.classList.add("has-name");
        profileButton.setAttribute("title", `${name} · open profile`);
    } else {
        profileButtonName.textContent = "";
        profileButtonName.hidden = true;
        profileButtonInitials.textContent = "";
        profileButton.classList.remove("has-name");
        profileButton.setAttribute("title", "Your profile: identity, key, password, and encryption options");
    }
}

// Fills the identity summary and name field in the modal from stored metadata.
function renderIdentityCard() {
    const identity = getIdentity();
    identityName.textContent = identity.name || "Unnamed identity";
    if (identity.id) {
        identityContact.textContent = `${identity.id.name}: ${identity.id.value}`;
        identityContact.hidden = false;
    } else {
        identityContact.textContent = "";
        identityContact.hidden = true;
    }
    identityProvider.textContent = identity.managed
        ? `Issued by ${identity.provider}`
        : `Self-managed · ${identity.provider}`;

    // The name is editable only for self-issued identities; a provider-managed
    // one is the org's source of truth, so the field is locked.
    identityNameInput.value = identity.name;
    identityNameInput.disabled = identity.managed;
    identityNameManaged.hidden = !identity.managed;
}

async function openKeyModal() {
    // Reset transient inputs. The field stays empty (we never load the saved
    // secret back); the masked placeholder just signals that one is set, and
    // leaving it blank keeps the current key.
    keySecretInput.value = "";
    keySecretInput.type = "password";
    keySecretInput.placeholder = "••••••••••••  (leave blank to keep current)";
    quantumSafeToggle.checked = isQuantumSafe();
    renderIdentityCard();
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

keySecretReveal.addEventListener("click", () => {
    keySecretInput.type = keySecretInput.type === "password" ? "text" : "password";
});

keyPubkeyCopy.addEventListener("click", () => {
    copyToClipboard(keyCurrentPubkey.value, keyPubkeyCopy, "Public key copied.");
});

// Persist the display name as the user edits it (self-issued identities only;
// the field is disabled when provider-managed). Commit on blur and on Enter.
function commitSelfName() {
    if (identityNameInput.disabled) {
        return;
    }
    if (setSelfName(identityNameInput.value)) {
        const { name } = getIdentity();
        identityName.textContent = name || "Unnamed identity";
        identityNameInput.value = name; // reflect sanitisation
        renderProfileButton();
    }
}

identityNameInput.addEventListener("blur", commitSelfName);
identityNameInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
        commitSelfName();
        identityNameInput.blur();
    }
});

// Fill the input with a fresh random secret key, revealed so it's visible.
keySecretGenerate.addEventListener("click", async () => {
    keySecretGenerate.disabled = true;
    try {
        keySecretInput.value = await genXipherSecretKey();
        keySecretInput.type = "text";
        showToast("Random secret key generated. Click Save & apply to use it.", "info", 3200);
    } catch (error) {
        showToast("Failed to generate key.", "error");
    } finally {
        keySecretGenerate.disabled = false;
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
        const value = keySecretInput.value.trim();
        // Blank means "keep the current key" so the modal can be used just to
        // change the quantum-safe toggle (which already applied on change).
        if (!value) {
            closeKeyModal();
            return;
        }
        // A value with the secret-key prefix is validated as a key; anything
        // else is treated as a password and held to the strength policy.
        if (value.startsWith("XSK_")) {
            if (!(await isValidSecretKey(value))) {
                showToast("That doesn't look like a valid secret key (XSK_…).", "error");
                return;
            }
        } else {
            const err = validatePassword(value);
            if (err) {
                showToast(err, "error");
                return;
            }
        }

        await setXipherSecret(value);

        // Refresh the shareable link and the public key shown in the modal.
        keyCurrentPubkey.value = await getPublicKey();
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

// Quantum-safe is a standalone derivation preference, independent of the key
// setup above: the public key is always re-derived from the stored identity, so
// toggling it re-derives the current key immediately (no "Save & apply" needed).
quantumSafeToggle.addEventListener("change", async () => {
    quantumSafeToggle.disabled = true;
    try {
        setQuantumSafe(quantumSafeToggle.checked);
        keyCurrentPubkey.value = await getPublicKey();
        if (typeof refreshIdentity === "function") {
            await refreshIdentity();
        }
        showToast(
            quantumSafeToggle.checked ? "Quantum-safe encryption enabled." : "Quantum-safe encryption disabled.",
            "success"
        );
    } catch (error) {
        console.error("Failed to update quantum-safe mode:", error);
        showToast("Failed to update quantum-safe mode.", "error");
        // Revert the visual state to the actual stored preference.
        quantumSafeToggle.checked = isQuantumSafe();
    } finally {
        quantumSafeToggle.disabled = false;
    }
});
