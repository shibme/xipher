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
const keySaveButton = document.getElementById("key-save-button");
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
const identityNameEdit = document.getElementById("identity-name-edit");
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

// Fills the identity summary from stored metadata and resets the name row to
// its display (non-editing) state.
function renderIdentityCard() {
    const identity = getIdentity();
    identityName.textContent = identity.name || "Anonymous";
    if (identity.id) {
        identityContact.textContent = `${identity.id.name}: ${identity.id.value}`;
        identityContact.hidden = false;
    } else {
        identityContact.textContent = "";
        identityContact.hidden = true;
    }
    const backingLabel = (() => {
        if (identity.managed) {
            return identity.provider === "passkey" ? "Passkey" : `Provider · ${identity.provider}`;
        }
        const kind = localStorage.getItem("xipherSecretKind");
        return kind === "password" ? "Password" : "Secret key";
    })();
    identityProvider.innerHTML = `Backed by <strong class="identity-provider-label">${backingLabel}</strong>`;

    // The name is editable only for self-issued identities; for a provider-
    // managed one the pencil is hidden and a note explains why.
    exitNameEdit();
    identityNameEdit.hidden = identity.managed;
    identityNameManaged.hidden = !identity.managed;
}

// Switches the name row into edit mode: hide the text + pencil, show the input
// prefilled with the current name, and focus it. No-op for managed identities.
function enterNameEdit() {
    if (getIdentity().managed) {
        return;
    }
    identityNameInput.value = getIdentity().name || "";
    identityName.hidden = true;
    identityNameEdit.hidden = true;
    identityNameInput.hidden = false;
    identityNameInput.focus();
    identityNameInput.select();
}

// Switches the name row back to display mode (text + pencil).
function exitNameEdit() {
    identityNameInput.hidden = true;
    identityName.hidden = false;
    if (!getIdentity().managed) {
        identityNameEdit.hidden = false;
    }
}

// Setup mode: the modal is shown at startup because this browser has no key yet.
// It can't be dismissed (no close button, no Esc/backdrop) - the user must pick a
// method - and the footer "Cancel" becomes a non-closing label. Cleared once a
// key/password/passkey is committed.
let keyModalSetupMode = false;

const keyModalTitle = document.getElementById("key-modal-title");

// Resolver for the promise returned by a mandatory Setup open. ensureLocalIdentity
// awaits that promise so it only proceeds (e.g. to auto-decryption) once the user
// has actually committed a key via finishKeySetup. Null when no Setup is pending.
let setupResolve = null;

async function openKeyModal(setupMode = false) {
    keyModalSetupMode = setupMode;
    // In setup the modal is mandatory: title reads "Setup", and the dismiss
    // affordances are removed so no key gets chosen by default.
    keyModalTitle.textContent = setupMode ? "Setup" : "Profile";
    keyModalClose.hidden = setupMode;
    // Reset transient inputs. The field stays empty (we never load the saved
    // secret back); the masked placeholder just signals that one is set, and
    // leaving it blank keeps the current key.
    keySecretInput.value = "";
    keySecretInput.type = "password";
    keySecretInput.placeholder = setupMode ? "Set a password or secret key" : "Leave blank to keep current";
    quantumSafeToggle.checked = isQuantumSafe();
    renderIdentityCard();
    // Disable save button and set to Cancel since no changes have been made yet.
    setKeySaveReady(false);
    // Default to the method matching the current identity: passkey if this
    // browser's key came from a passkey (and passkeys are available), else the
    // password/key view.
    const usesPasskey = passkeyAvailable && getIdentity().provider === "passkey";
    selectMethod(usesPasskey ? "passkey" : "password");
    keyModal.hidden = false;
    document.body.classList.add("no-scroll");
    // A mandatory Setup resolves only when the user commits a key (finishKeySetup).
    // Non-setup (Profile) opens have nothing to await, so resolve immediately.
    if (setupMode) {
        return new Promise((resolve) => { setupResolve = resolve; });
    }
}

function closeKeyModal() {
    // A mandatory Setup can't be dismissed without choosing a method.
    if (keyModalSetupMode) {
        return;
    }
    keyModal.hidden = true;
    document.body.classList.remove("no-scroll");
}

// Marks a key as successfully set from the modal: leave setup mode and close.
// Called by the password/passkey save paths after they commit an identity.
function finishKeySetup() {
    keyModalSetupMode = false;
    keyModalClose.hidden = false;
    keyModalTitle.textContent = "Profile";
    keyModal.hidden = true;
    document.body.classList.remove("no-scroll");
    // Unblock any ensureLocalIdentity() awaiting this Setup.
    if (setupResolve) {
        setupResolve();
        setupResolve = null;
    }
}

keySettingsButton.addEventListener("click", () => openKeyModal(false));
keyModalClose.addEventListener("click", closeKeyModal);

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

function setKeySaveReady(ready) {
    keySaveButton.disabled = !ready;
    // In Setup the modal can't be dismissed, so the idle label is a disabled
    // "Set up" prompt rather than a "Cancel" that would close the modal.
    keySaveButton.textContent = ready ? "Ok" : (keyModalSetupMode ? "Set up" : "Cancel");
    keySaveButton.classList.toggle("encrypt-button", ready);
    keySaveButton.classList.toggle("grey-button", !ready);
}

keySecretInput.addEventListener("input", () => {
    setKeySaveReady(!!keySecretInput.value.trim());
});

quantumSafeToggle.addEventListener("change", () => {
    setKeySaveReady(true);
});


// Persist the display name from the inline editor (self-issued identities only),
// then return the row to display mode. Committed on blur and on Enter.
function commitSelfName() {
    if (setSelfName(identityNameInput.value)) {
        const { name } = getIdentity();
        identityName.textContent = name || "Anonymous";
        renderProfileButton();
    }
    exitNameEdit();
}

identityNameEdit.addEventListener("click", enterNameEdit);
identityName.addEventListener("click", () => {
    if (!getIdentity().managed) {
        enterNameEdit();
    }
});
identityNameInput.addEventListener("blur", commitSelfName);
identityNameInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
        identityNameInput.blur(); // triggers commitSelfName via blur handler
    } else if (event.key === "Escape") {
        event.preventDefault();
        identityNameInput.value = getIdentity().name || ""; // discard edits
        identityNameInput.blur();
    }
});

// Fill the input with a fresh random secret key, revealed so it's visible.
keySecretGenerate.addEventListener("click", async () => {
    keySecretGenerate.disabled = true;
    try {
        keySecretInput.value = await genXipherSecretKey();
        keySecretInput.type = "text";
        setKeySaveReady(true);
        showToast("Random secret key generated. Click Ok to use it.", "info", 3200);
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
    if (keySaveButton.textContent === "Continue") {
        pendingPasskeyAction === "unlock" ? runPasskeyUnlock() : runPasskeySetup();
        return;
    }
    if (keySaveButton.textContent === "Cancel") {
        closeKeyModal();
        return;
    }
    keySaveButton.disabled = true;
    try {
        const value = keySecretInput.value.trim();
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
        localStorage.setItem("xipherSecretKind", value.startsWith("XSK_") ? "key" : "password");

        const wasSetup = keyModalSetupMode;
        if (typeof refreshIdentity === "function") {
            await refreshIdentity();
        }
        showToast(wasSetup ? "Your key is set." : "Your key has been updated.", "success");
        if (wasSetup) {
            finishKeySetup();
        } else {
            closeKeyModal();
        }
    } catch (error) {
        console.error("Failed to save key:", error);
        showToast("Failed to update key.", "error");
        setKeySaveReady(true);
    }
}

keySaveButton.addEventListener("click", handleKeySave);

/* ==========================================================================
   Passkey UI
   ========================================================================== */

const methodTabPasskey = document.getElementById("method-tab-passkey");
const methodTabPassword = document.getElementById("method-tab-password");
const methodViewPasskey = document.getElementById("method-view-passkey");
const methodViewPassword = document.getElementById("method-view-password");
const passkeyUseButton = document.getElementById("passkey-use-button");
const passkeySetupButton = document.getElementById("passkey-setup-button");
const passkeyStatus = document.getElementById("passkey-status");
const passkeyStoreToggle = document.getElementById("passkey-store-toggle");
const passkeyUnsupported = document.getElementById("passkey-unsupported");

// Whether the platform authenticator check has passed. Determined once at
// startup; gates the passkey tab.
let passkeyAvailable = false;
// The default WebAuthn label when the user declines to set a name.
const PASSKEY_DEFAULT_NAME = "Xipher";

// Selects a method tab ("passkey" or "password") and shows its view.
function selectMethod(method) {
    const passkey = method === "passkey";
    methodTabPasskey.setAttribute("aria-selected", String(passkey));
    methodTabPassword.setAttribute("aria-selected", String(!passkey));
    methodTabPasskey.classList.toggle("is-active", passkey);
    methodTabPassword.classList.toggle("is-active", !passkey);
    methodViewPasskey.hidden = !passkey;
    methodViewPassword.hidden = passkey;
    if (passkey) {
        resetPasskeyView();
    } else {
        setKeySaveReady(false);
    }
}

// Resets the passkey view to its idle state.
function resetPasskeyView() {
    passkeyUnsupported.hidden = passkeyAvailable;
    passkeyUseButton.hidden = !passkeyAvailable;
    passkeySetupButton.hidden = !passkeyAvailable;
    passkeyUseButton.disabled = false;
    passkeySetupButton.disabled = false;
    passkeyUseButton.classList.remove("is-active");
    passkeySetupButton.classList.remove("is-active");
    passkeyStatus.textContent = passkeyAvailable ? "Use an existing passkey or set a new one." : "";
    setKeySaveReady(false);
    keySaveButton.hidden = false;
    keySaveButton.textContent = keyModalSetupMode ? "Set up" : "Cancel";
    keySaveButton.classList.remove("encrypt-button");
    keySaveButton.classList.add("grey-button");
    // In Setup the idle footer is a disabled prompt, not a dismiss button.
    keySaveButton.disabled = keyModalSetupMode;
}

// Initialises passkey availability. Called once after WASM loads (from main).
async function initPasskeyUI() {
    passkeyAvailable = await isPlatformAuthenticatorAvailable();
}

methodTabPasskey.addEventListener("click", () => selectMethod("passkey"));
methodTabPassword.addEventListener("click", () => selectMethod("password"));

let pendingPasskeyAction = "setup"; // "setup" | "unlock"

function activatePasskeyButton(action) {
    pendingPasskeyAction = action;
    passkeySetupButton.classList.toggle("is-active", action === "setup");
    passkeyUseButton.classList.toggle("is-active", action === "unlock");
    // Switch footer button to "Continue"
    keySaveButton.hidden = false;
    keySaveButton.disabled = false;
    keySaveButton.textContent = "Continue";
    keySaveButton.classList.add("encrypt-button");
    keySaveButton.classList.remove("grey-button");
}

passkeyUseButton.addEventListener("click", () => activatePasskeyButton("unlock"));
passkeySetupButton.addEventListener("click", () => activatePasskeyButton("setup"));

// Shared replace-key consent: returns true to proceed, false to abort.
async function confirmPasskeyReplace() {
    const existing = await getExistingXipherSecret();
    if (!existing) {
        return true;
    }
    return await askProviderConsent({
        title: "Replace your current key?",
        message: "Using your passkey will derive and replace the key stored in this browser. Anything encrypted to your current key will no longer be readable here.",
        confirmLabel: "Replace my key",
        confirmClass: "decrypt-button",
    });
}

async function resolvePasskeyName() {
    const { name, managed } = getIdentity();
    if (!managed && (name || "").trim()) {
        return name.trim();
    }
    // No name set -ask via consent popup.
    const result = await askProviderConsent({
        title: "Name this passkey?",
        message: "A name labels this passkey in your device or password manager. You can skip this and use the default name \"Xipher\".",
        confirmLabel: "Set a name",
        cancelLabel: "Use \"Xipher\"",
        confirmClass: "encrypt-button",
        dismissValue: null,
    });
    if (result === null) return null; // dismissed -abort entirely
    if (result === true) {
        enterNameEdit();
        return null; // user chose to set a name -abort, let them re-click Continue
    }
    return PASSKEY_DEFAULT_NAME;
}

async function runPasskeySetup() {
    const storeKey = passkeyStoreToggle.checked;
    const passkeyName = await resolvePasskeyName();
    if (passkeyName === null) {
        resetPasskeyView();
        return;
    }
    passkeyUseButton.disabled = true;
    passkeySetupButton.disabled = true;
    keySaveButton.disabled = true;
    if (!(await confirmPasskeyReplace())) {
        resetPasskeyView();
        return;
    }
    passkeyStatus.textContent = "Follow your passkey prompts (some providers ask twice)…";
    try {
        await setupPasskey(storeKey, passkeyName);
        const wasSetup = keyModalSetupMode;
        if (typeof refreshIdentity === "function") await refreshIdentity();
        showToast("Passkey set up. Your key is now derived from this passkey.", "success", 3500);
        resetPasskeyView();
        wasSetup ? finishKeySetup() : closeKeyModal();
    } catch (err) {
        handlePasskeyError(err, "setup");
    }
}

async function runPasskeyUnlock() {
    const storeKey = passkeyStoreToggle.checked;
    passkeyUseButton.disabled = true;
    passkeySetupButton.disabled = true;
    keySaveButton.disabled = true;
    if (!(await confirmPasskeyReplace())) {
        resetPasskeyView();
        return;
    }
    passkeyStatus.textContent = "Waiting for your passkey…";
    try {
        await unlockWithPasskey(storeKey);
        const wasSetup = keyModalSetupMode;
        if (typeof refreshIdentity === "function") await refreshIdentity();
        showToast("Key derived from your passkey.", "success");
        resetPasskeyView();
        wasSetup ? finishKeySetup() : closeKeyModal();
    } catch (err) {
        handlePasskeyError(err, "unlock");
    }
}

// Maps a passkey failure to user feedback. `phase` is "setup" or "unlock".
function handlePasskeyError(err, phase) {
    resetPasskeyView();
    if (err && err.name === "PRFNotSupported") {
        // The chosen authenticator completed but returned no PRF output. The
        // user picked something that can't derive keys (an older or misconfigured
        // password-manager extension, or a security key without PRF firmware).
        // Point them at an authenticator that works rather than implying the
        // whole device is unsupported.
        passkeyStatus.textContent = "That passkey can't derive a key. Try your device's built-in passkey (Touch ID / Windows Hello), or update your password manager.";
        showToast("That authenticator didn't return a derivation key (PRF). Try a different passkey.", "error", 5000);
    } else if (err && err.name === "NotAllowedError") {
        // User dismissed the OS prompt, or (on unlock) no matching passkey
        // existed and the picker timed out / was cancelled.
        passkeyStatus.textContent = phase === "setup"
            ? "Passkey setup was cancelled."
            : "No passkey was selected. Set one up if you don't have one yet.";
    } else if (err && (err.message === "Registration cancelled." || err.message === "Authentication cancelled.")) {
        passkeyStatus.textContent = "Cancelled.";
    } else {
        passkeyStatus.textContent = phase === "setup"
            ? "Passkey setup failed. Try again."
            : "Couldn't use a passkey. Try again or set one up.";
        showToast("Passkey operation failed.", "error");
    }
}


// The toggle lives on the homepage and is visible from load, so reflect the
// stored preference immediately (not just when the profile modal opens).
quantumSafeToggle.checked = isQuantumSafe();

// Quantum-safe is a standalone derivation preference, independent of the key
// setup above: the public key is always re-derived from the stored identity, so
// toggling it re-derives the current key immediately (no "Save & apply" needed).
quantumSafeToggle.addEventListener("change", async () => {
    quantumSafeToggle.disabled = true;
    try {
        setQuantumSafe(quantumSafeToggle.checked);
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
