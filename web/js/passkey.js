// passkey.js -derive a xipher secret key from a WebAuthn passkey using the
// PRF extension. The PRF output is a deterministic 32-byte HMAC computed
// inside the authenticator, scoped to this origin. We HKDF-expand it to the
// 64 bytes that xipher's seed path requires. No server is involved; the seed
// is derived client-side and never stored -it is re-derived from the passkey
// on every window open.
//
// Browser support: Chrome 108+, Safari 17+, Firefox 119+.
// Older browsers/devices that don't support PRF show a graceful error.

const PASSKEY_CREDENTIAL_ID_KEY = "xipherPasskeyCredentialId";

// The fixed PRF input string. Changing this would invalidate all existing keys.
const PRF_INPUT = new TextEncoder().encode("xipher");

// HKDF params to stretch 32-byte PRF output to 64-byte seed.
const HKDF_SALT = new TextEncoder().encode("xipher");
const HKDF_INFO = new TextEncoder().encode("xipher");

// Returns true when the browser exposes the WebAuthn API at all.
function isWebAuthnAvailable() {
    return !!(window.PublicKeyCredential && navigator.credentials);
}

// Returns true when a platform authenticator (Touch ID, Face ID, Windows
// Hello, etc.) is available. Used to decide whether to show the passkey UI.
async function isPlatformAuthenticatorAvailable() {
    if (!isWebAuthnAvailable()) {
        return false;
    }
    try {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (e) {
        return false;
    }
}

// Returns the stored credential ID as a Uint8Array, or null.
function getStoredCredentialId() {
    const stored = localStorage.getItem(PASSKEY_CREDENTIAL_ID_KEY);
    if (!stored) {
        return null;
    }
    try {
        const binary = atob(stored);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } catch (e) {
        return null;
    }
}

// Persists a credential ID (Uint8Array or ArrayBuffer) to localStorage.
function storeCredentialId(credentialId) {
    const bytes = new Uint8Array(credentialId);
    let binary = "";
    for (const b of bytes) {
        binary += String.fromCharCode(b);
    }
    localStorage.setItem(PASSKEY_CREDENTIAL_ID_KEY, btoa(binary));
}

// Clears the stored credential ID (e.g. when the user removes their passkey).
function clearStoredCredentialId() {
    localStorage.removeItem(PASSKEY_CREDENTIAL_ID_KEY);
}

// Byte-compares two credential IDs (Uint8Array). A null/length mismatch counts
// as not equal -used to detect when a different passkey was selected.
function credentialIdsEqual(a, b) {
    if (!a || !b || a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}

// Reports whether this browser has a passkey credential registered. The derived
// key is never persisted, so the secret lives only in memory and is gone after a
// reload -the user must re-derive it via the passkey on every window open.
function hasPasskeyConfigured() {
    return !!getStoredCredentialId();
}

// Stretches a 32-byte PRF output to a 64-byte xipher seed using HKDF-SHA-256.
async function hkdfExpand(prfOutput) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw", prfOutput, "HKDF", false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: HKDF_INFO },
        keyMaterial, 512
    );
    return new Uint8Array(bits);
}

// Builds a tagged error used when the chosen authenticator completes the
// ceremony but returns no usable PRF output.
function prfNotSupportedError() {
    const err = new Error("This passkey provider didn't return a key-derivation value (PRF extension not available).");
    err.name = "PRFNotSupported";
    return err;
}

// Registers a new passkey and returns { credentialId, prfOutput } or throws.
// Throws { name: "PRFNotSupported" } when the authenticator doesn't support PRF.
// `displayName` (optional) is used for the WebAuthn user.name/displayName so the
// credential is recognisable in the user's OS/password-manager passkey list
// (e.g. "Alice" rather than a generic label). It is NOT recoverable on login -
// WebAuthn never returns it to the relying party -so the caller also stores it
// locally as the identity name.
async function registerPasskey(displayName) {
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const label = (displayName || "").trim() || "Xipher user";

    const credential = await navigator.credentials.create({
        publicKey: {
            rp: {
                id: location.hostname,
                name: "Xipher",
            },
            user: {
                id: userId,
                name: label,
                displayName: label,
            },
            challenge,
            // ES256 first (most widely supported), then Ed25519, then RS256.
            // Including ES256 + RS256 silences the compatibility warning some
            // authenticators (e.g. Bitwarden) emit and avoids registration
            // failures on authenticators that don't do Ed25519.
            pubKeyCredParams: [
                { type: "public-key", alg: -7 },    // ES256
                { type: "public-key", alg: -8 },    // Ed25519
                { type: "public-key", alg: -257 },  // RS256
            ],
            authenticatorSelection: {
                residentKey: "required",
                userVerification: "required",
            },
            // Pass the PRF eval at create(). Some providers (notably Bitwarden)
            // only acknowledge PRF when eval is present here, and may return the
            // PRF output directly on registration. Those that don't evaluate at
            // create() still report support, and we fetch the output via the
            // follow-up get() below.
            extensions: {
                prf: { eval: { first: PRF_INPUT } },
            },
        },
    });

    if (!credential) {
        throw new Error("Registration cancelled.");
    }

    const credentialId = credential.rawId;
    const prf = credential.getClientExtensionResults()?.prf;

    // Best case (platform authenticators like Touch ID): PRF was evaluated right
    // here at create(), so use it directly -no second prompt needed. Note the
    // value is an ArrayBuffer; a non-empty byteLength means a real result.
    if (prf?.results?.first && prf.results.first.byteLength > 0) {
        return { credentialId, prfOutput: prf.results.first };
    }

    // The authenticator confirmed PRF support but didn't evaluate at create()
    // (some providers only evaluate on assertion). Fetch it via a follow-up
    // get(). If it explicitly reported no support, fail now.
    if (prf?.enabled === false) {
        throw prfNotSupportedError();
    }
    const prfOutput = await authenticatePasskey(credentialId);
    return { credentialId, prfOutput };
}

// Authenticates with an existing passkey and returns the PRF output, or throws.
// Throws { name: "PRFNotSupported" } when the authenticator doesn't return PRF.
// When credentialId is null, uses the discoverable (resident-key) flow so the
// browser shows a picker of all xipher passkeys on this device.
async function authenticatePasskey(credentialId) {
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const allowCredentials = credentialId
        ? [{ type: "public-key", id: credentialId }]
        : [];

    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge,
            rpId: location.hostname,
            allowCredentials,
            userVerification: "required",
            // Prefer the platform authenticator (Touch ID, Face ID, Windows Hello)
            // over roaming/extension authenticators. Advisory only - the browser
            // may still show other options, but this surfaces the system prompt first.
            hints: ["client-device"],
            extensions: {
                prf: { eval: { first: PRF_INPUT } },
            },
        },
    });

    if (!assertion) {
        throw new Error("Authentication cancelled.");
    }

    const prfOutput = assertion.getClientExtensionResults()?.prf?.results?.first;
    if (!prfOutput || prfOutput.byteLength === 0) {
        throw prfNotSupportedError();
    }

    // Update the stored credential ID in case we used the discoverable flow.
    storeCredentialId(assertion.rawId);

    return prfOutput;
}

// Converts a PRF output to an XSK_ secret key via HKDF + xipher's seed path.
async function seedKeyFromPrf(prfOutput) {
    const seed = await hkdfExpand(prfOutput);
    return await genXipherSecretKeyFromSeed(seed);
}

/* ==========================================================================
   Public entry points called from ui.js
   ========================================================================== */

// Registers a NEW passkey and installs the key derived from it. The derived key
// is never persisted: it lives only in this tab and is re-derived via the passkey
// on next visit. `name` (optional) is the user's display name: it labels the
// credential in their passkey manager and is stored as the local identity name.
// Since WebAuthn won't return it on a later login, an existing passkey used on
// another device will have no name until set again there.
async function setupPasskey(name) {
    const { credentialId, prfOutput } = await registerPasskey(name);
    storeCredentialId(credentialId);
    const xsk = await seedKeyFromPrf(prfOutput);
    await setProviderIdentity(xsk, "passkey", (name || "").trim() || null, null, false);
    return xsk;
}

// Uses an EXISTING passkey. Always runs the discoverable flow (null credential
// ID) so it finds any xipher passkey on this device regardless of localStorage
// state -robust against a cleared store, a new browser, or a stale stored ID.
// authenticatePasskey records the selected credential's ID for next time. The
// derived key is never persisted -re-derived from the passkey on every visit.
//
// The stored identity name is kept only when the SAME passkey re-authenticates.
// We snapshot the stored credential ID before authenticatePasskey overwrites it,
// then compare: if the user picked a different passkey (or none was stored), the
// old name belongs to another credential and is cleared.
async function unlockWithPasskey() {
    const previousCredentialId = getStoredCredentialId();
    const prfOutput = await authenticatePasskey(null);
    const sameCredential = credentialIdsEqual(previousCredentialId, getStoredCredentialId());
    const name = sameCredential ? (getIdentity().name || null) : null;
    const xsk = await seedKeyFromPrf(prfOutput);
    await setProviderIdentity(xsk, "passkey", name, null, false);
    return xsk;
}
