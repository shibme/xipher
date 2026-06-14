const burialCache = new Map();
const xipherSecretStoreId = "xipherSecret";
const xipherPublicKeyStoreId = "xipherPublicKey";
const xipherQuantumSafeStoreId = "xipherQuantumSafe";
// Identity metadata sidecars (non-secret: a display name, an id/email, and the
// host that issued the key). Stored in plain localStorage alongside the public
// key. Absent provider => the key is self-issued by this deployment, and the
// name is user-editable; a stored host => an external credential provider issued
// it, and the name/id are managed (read-only).
const xipherNameStoreId = "xipherName";
// The id is an identifier for the authenticating entity, typed as "user",
// "group", or "service". Stored as two fields: the entity type and the id value.
const xipherTypeStoreId = "xipherType";
const xipherIdValueStoreId = "xipherIdValue";
const xipherProviderStoreId = "xipherProvider";
const xipherSecretKindStoreId = "xipherSecretKind"; // "key" | "password"
// Per-credential timeout. The stored secret is wrapped in an envelope carrying a
// validity duration and a sliding deadline (now + duration), refreshed on every
// load. A security tool shouldn't keep a key on a machine the user has abandoned;
// active use slides the deadline forward, so it never expires while in use. The
// duration is capped at 7 days and can only be lowered (raising it requires
// setting the credential again). See buryXipherSecret / enforceCredentialTimeout.
const MAX_TIMEOUT_MS = 7 * 24 * 60 * 60 * 1000; // 7 days, the hard ceiling
// Default duration offered when setting a password/secret key directly. The user
// can change it in the prompt; lowered later in the profile, or raised (up to the
// ceiling) by setting the credential again. Change here to adjust the default.
const DEFAULT_NEW_CREDENTIAL_TIMEOUT_MS = 24 * 60 * 60 * 1000; // 1 day
// Slack on the suspicious-deadline check, to absorb clock skew / write latency so
// a legitimate now+7d deadline isn't flagged the instant it's written.
const SUSPICIOUS_MARGIN_MS = 5 * 60 * 1000; // 5 minutes
// Duration units (ms) shared by the timeout pickers. Largest first so a stored
// duration renders in the coarsest unit that divides it evenly.
const TIMEOUT_UNIT_MS = { days: 86400000, hours: 3600000, minutes: 60000 };

// splitDuration renders a duration (ms) as { value, unit } using the largest unit
// that divides it evenly, rounding to the nearest minute first so a non-aligned
// value (e.g. a provider-set odd duration) still shows cleanly. Minimum 1 minute.
function splitDuration(durationMs) {
    let minutes = Math.max(1, Math.round(durationMs / TIMEOUT_UNIT_MS.minutes));
    const ms = minutes * TIMEOUT_UNIT_MS.minutes;
    if (ms % TIMEOUT_UNIT_MS.days === 0) {
        return { value: ms / TIMEOUT_UNIT_MS.days, unit: "days" };
    }
    if (ms % TIMEOUT_UNIT_MS.hours === 0) {
        return { value: ms / TIMEOUT_UNIT_MS.hours, unit: "hours" };
    }
    return { value: minutes, unit: "minutes" };
}
const MAX_IDENTITY_FIELD_LEN = 64;
// C0 and C1 control characters, stripped from untrusted identity fields.
// Matches CONTROL_CHARS in resolve.js.
const IDENTITY_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/g;

// encryptForStorage obfuscates a string for at-rest storage using AES-GCM with
// a key derived from the data itself (SHA-256). The IV and key-hash are packed
// ahead of the ciphertext. Returns a binary string suitable for *Storage.
async function encryptForStorage(data) {
    const textEncoder = new TextEncoder();
    const dataBytes = textEncoder.encode(data);
    const hashBuffer = await crypto.subtle.digest("SHA-256", dataBytes);
    const hash = new Uint8Array(hashBuffer);
    const key = await crypto.subtle.importKey(
        "raw",
        hash,
        {
            name: "AES-GCM"
        },
        false,
        ["encrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedDataBuffer = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        dataBytes
    );
    const encryptedData = new Uint8Array(encryptedDataBuffer);
    const combinedData = new Uint8Array(iv.length + hash.length + encryptedData.length);
    combinedData.set(iv);
    combinedData.set(hash, iv.length);
    combinedData.set(encryptedData, iv.length + hash.length);
    return String.fromCharCode(...combinedData);
}

// decryptFromStorage reverses encryptForStorage. Returns the original string, or
// null if the input is missing or can't be decrypted.
async function decryptFromStorage(storedData) {
    if (!storedData) {
        return null;
    }
    try {
        const combinedData = Uint8Array.from(storedData.split("").map(char => char.charCodeAt(0)));
        const iv = combinedData.slice(0, 12);
        const hash = combinedData.slice(12, 44);
        const encryptedData = combinedData.slice(44);
        const key = await crypto.subtle.importKey(
            "raw",
            hash,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        const decryptedDataBuffer = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            key,
            encryptedData
        );
        return new TextDecoder().decode(decryptedDataBuffer);
    } catch (error) {
        return null;
    }
}

async function bury(id, data) {
    localStorage.setItem(id, await encryptForStorage(data));
    burialCache.set(id, data);
}

async function dig(id) {
    const cachedData = burialCache.get(id);
    if (cachedData) {
        return cachedData;
    }
    const originalData = await decryptFromStorage(localStorage.getItem(id));
    if (originalData === null) {
        return null;
    }
    burialCache.set(id, originalData);
    return originalData;
}

// clampDuration coerces an arbitrary timeout (ms) into [0, MAX_TIMEOUT_MS]. A
// non-finite or negative input falls back to the 7-day ceiling (the safe default
// for a credential that didn't specify one). 0 is preserved (ephemeral).
function clampDuration(durationMs) {
    if (!Number.isFinite(durationMs) || durationMs < 0) {
        return MAX_TIMEOUT_MS;
    }
    return Math.min(durationMs, MAX_TIMEOUT_MS);
}

// buryXipherSecret stores the secret key wrapped in a timeout envelope
// { key, durationMs, deadline } encrypted at rest. The deadline is now+duration.
// A 0 duration marks the credential ephemeral: the secret is held only in the
// in-memory burial cache for this tab (never written to localStorage), so it
// vanishes on reload -the same treatment as a session-only passkey key.
async function buryXipherSecret(key, durationMs) {
    const duration = clampDuration(durationMs);
    if (duration === 0) {
        // Ephemeral: keep the raw key in memory only; leave nothing on disk.
        burialCache.set(xipherSecretStoreId, key);
        localStorage.removeItem(xipherSecretStoreId);
        return;
    }
    const envelope = JSON.stringify({ key, durationMs: duration, deadline: Date.now() + duration });
    await bury(xipherSecretStoreId, envelope);
}

// digXipherSecret reads and parses the stored secret envelope. Returns
// { key, durationMs, deadline } or null when no secret is stored. For backward
// compatibility a bare XSK_ string (the pre-envelope format, or an in-memory
// ephemeral key) is wrapped as a default 7-day envelope with no deadline written
// yet -enforceCredentialTimeout reburies it to materialise the deadline.
async function digXipherSecret() {
    const raw = await dig(xipherSecretStoreId);
    if (raw === null || raw === undefined) {
        return null;
    }
    if (typeof raw === "string" && raw.startsWith("{")) {
        try {
            const env = JSON.parse(raw);
            if (env && typeof env.key === "string" && env.key) {
                return {
                    key: env.key,
                    durationMs: clampDuration(env.durationMs),
                    deadline: Number.isFinite(env.deadline) ? env.deadline : null,
                };
            }
        } catch (error) {
            // Not an envelope; fall through to the bare-key form.
        }
    }
    // Legacy bare key (or in-memory ephemeral key): default to the 7-day ceiling.
    return { key: raw, durationMs: MAX_TIMEOUT_MS, deadline: null };
}

// Quantum-safe preference for public key derivation.
function isQuantumSafe() {
    return localStorage.getItem(xipherQuantumSafeStoreId) === "true";
}

function setQuantumSafe(enabled) {
    const current = isQuantumSafe();
    if (current !== !!enabled) {
        if (enabled) {
            localStorage.setItem(xipherQuantumSafeStoreId, "true");
        } else {
            localStorage.removeItem(xipherQuantumSafeStoreId);
        }
        // Invalidate the cached public key so it gets re-derived.
        localStorage.removeItem(xipherPublicKeyStoreId);
        return true;
    }
    return false;
}

// Sets the active secret with a fresh timeout envelope. durationMs defaults to
// the 7-day ceiling; setting the credential is the only way to *raise* the
// timeout (a freshly set credential is always allowed up to the cap). A change
// resets the identity to self-issued, dropping any provider metadata.
async function setXipherSecret(xipherSecret, durationMs = MAX_TIMEOUT_MS) {
    const current = await digXipherSecret();
    if (!current || current.key !== xipherSecret) {
        await buryXipherSecret(xipherSecret, durationMs);
        localStorage.removeItem(xipherPublicKeyStoreId);
        // A manual key/password change makes this a fresh self-issued identity:
        // drop any provider metadata and let the name default again. (The
        // provider flow uses setProviderIdentity instead, which sets these.)
        localStorage.removeItem(xipherNameStoreId);
        localStorage.removeItem(xipherTypeStoreId);
        localStorage.removeItem(xipherIdValueStoreId);
        localStorage.removeItem(xipherProviderStoreId);
        localStorage.removeItem(xipherSecretKindStoreId);
    }
}

// Returns the current credential's timeout duration in ms, or null if no secret
// is stored. Used by the Profile UI to render and bound the duration control.
async function getCredentialTimeout() {
    const env = await digXipherSecret();
    return env ? env.durationMs : null;
}

// Lowers the credential timeout to durationMs and reburies with a fresh deadline.
// The duration can only be *reduced*: a request to raise it above the currently
// stored value is rejected (returns false). Raising requires setting the
// credential again (setXipherSecret). Returns true when applied.
async function setCredentialTimeout(durationMs) {
    const env = await digXipherSecret();
    if (!env) {
        return false;
    }
    const next = clampDuration(durationMs);
    if (next > env.durationMs) {
        return false;
    }
    await buryXipherSecret(env.key, next);
    return true;
}

// Installs a secret key delivered by an external credential provider, recording
// the issuing host and the managed name/id alongside it. Unlike setXipherSecret,
// this marks the identity as provider-managed (name/id read-only in the UI).
// `id` is the entity's identifier value (string) and `type` is the entity kind
// ("user" | "group" | "service"); both optional.
//
// `persist` defaults to true: the key is written to localStorage so it survives
// across sessions. When false (the passkey flow, which re-derives each time), the
// secret lives only in the in-memory burial cache for this tab -it is never
// written to localStorage, so it vanishes on reload and must be re-derived. The
// non-secret identity metadata is removed from localStorage in that case too, so
// a closed tab leaves no trace of a passkey-only identity.
async function setProviderIdentity(xipherSecret, providerHost, name, id, type, persist = true, durationMs = MAX_TIMEOUT_MS) {
    if (persist) {
        // buryXipherSecret applies the timeout envelope. A 0 duration there is
        // itself ephemeral (memory-only), so a provider key with timeout=0 lands
        // in the same session-only state as a passkey without a separate branch.
        await buryXipherSecret(xipherSecret, durationMs);
    } else {
        // Session-only (passkey): hold the secret in memory for this tab, and make
        // sure no stale copy lingers in localStorage from a previous identity.
        burialCache.set(xipherSecretStoreId, xipherSecret);
        localStorage.removeItem(xipherSecretStoreId);
    }
    localStorage.removeItem(xipherPublicKeyStoreId);
    localStorage.setItem(xipherProviderStoreId, providerHost);
    setIdentityField(xipherNameStoreId, name);
    // An id is stored whenever it has a value. The type (the entity kind the id
    // names) is optional: a recognised value is kept as the id's label, anything
    // else is dropped and the id shows under a generic "ID" label.
    const idValue = typeof id === "string" ? id : "";
    const validType = type === "user" || type === "group" || type === "service";
    if (sanitiseIdentityField(idValue)) {
        setIdentityField(xipherIdValueStoreId, idValue);
        if (validType) {
            setIdentityField(xipherTypeStoreId, type);
        } else {
            localStorage.removeItem(xipherTypeStoreId);
        }
    } else {
        localStorage.removeItem(xipherTypeStoreId);
        localStorage.removeItem(xipherIdValueStoreId);
    }
}

async function getXipherSecret() {
    const env = await digXipherSecret();
    if (env) {
        return env.key;
    }
    const xipherSecret = await genXipherSecretKey();
    await setXipherSecret(xipherSecret);
    return xipherSecret;
}

async function getPublicKey() {
    const xipherSecret = await getXipherSecret();
    let xipherPublicKey = localStorage.getItem(xipherPublicKeyStoreId);
    if (!xipherPublicKey) {
        xipherPublicKey = await genXipherPublicKey(xipherSecret, isQuantumSafe());
        localStorage.setItem(xipherPublicKeyStoreId, xipherPublicKey);
    }
    return xipherPublicKey;
}

// Returns the stored secret key without generating one, or null if the browser
// has no identity yet. Used by the provider flow to decide whether accepting a
// delivered key would overwrite (and orphan) an existing identity, and by the
// startup flow to decide whether a Setup is needed.
async function getExistingXipherSecret() {
    const env = await digXipherSecret();
    return env ? env.key : null;
}

// Reports whether this browser already has a usable secret (persisted in
// localStorage, or held in the in-memory burial cache for a session-only
// passkey identity). Unlike getXipherSecret, it never generates one -used at
// startup to decide between the normal flow and the Setup prompt.
async function hasXipherSession() {
    return !!(await getExistingXipherSecret());
}

/* ==========================================================================
   Identity metadata (name, id/email, issuing provider)
   ========================================================================== */

// The host serving this app: the default "self" provider (e.g. xipher.org, or
// whatever a self-host runs on). An identity with no stored provider is treated
// as issued by self, and its name is user-editable.
function selfHost() {
    return window.location.host;
}

// Sanitises an untrusted display field: strip control chars, trim, cap length.
// Mirrors sanitiseName in resolve.js. Returns "" for empty/invalid input.
function sanitiseIdentityField(value) {
    if (typeof value !== "string") {
        return "";
    }
    value = value.replace(IDENTITY_CONTROL_CHARS, "").trim();
    const chars = Array.from(value); // split by code point
    if (chars.length > MAX_IDENTITY_FIELD_LEN) {
        value = chars.slice(0, MAX_IDENTITY_FIELD_LEN).join("");
    }
    return value;
}

// Stores a sanitised identity field, or removes it when blank.
function setIdentityField(storeId, value) {
    const clean = sanitiseIdentityField(value);
    if (clean) {
        localStorage.setItem(storeId, clean);
    } else {
        localStorage.removeItem(storeId);
    }
}

// Returns the current identity metadata for display. `provider` is the issuing
// host (defaults to self). `managed` is true when a stored provider backs the
// key. `nameLocked` is true only when an *external* provider issued the name -
// passkey-backed identities are provider-backed but keep a user-editable name.
function getIdentity() {
    const provider = localStorage.getItem(xipherProviderStoreId) || selfHost();
    const managed = !!localStorage.getItem(xipherProviderStoreId);
    const nameLocked = managed && provider !== "passkey";
    const idValue = localStorage.getItem(xipherIdValueStoreId) || "";
    const idType = localStorage.getItem(xipherTypeStoreId) || "";
    return {
        name: localStorage.getItem(xipherNameStoreId) || "",
        // Identifier; null when no value was stored. type is "" when the provider
        // gave no recognised entity kind - the UI then falls back to "ID".
        id: idValue ? { type: idType, value: idValue } : null,
        provider,
        managed,
        nameLocked,
    };
}

// Wipes the stored secret and all identity metadata from this browser, returning
// it to a fresh state. Clears the in-memory burial cache too, so a session-only
// (non-persisted) key held in memory is dropped as well. The passkey credential-ID
// pointer is removed when available (passkey.js defines clearStoredCredentialId).
function clearStoredIdentity() {
    burialCache.clear();
    localStorage.removeItem(xipherSecretStoreId);
    localStorage.removeItem(xipherPublicKeyStoreId);
    localStorage.removeItem(xipherNameStoreId);
    localStorage.removeItem(xipherTypeStoreId);
    localStorage.removeItem(xipherIdValueStoreId);
    localStorage.removeItem(xipherProviderStoreId);
    localStorage.removeItem(xipherSecretKindStoreId);
    if (typeof clearStoredCredentialId === "function") {
        clearStoredCredentialId();
    }
}

// Per-credential timeout gate. Reads the stored secret envelope and:
//   - wipes the identity and returns "expired" when the deadline has passed;
//   - wipes it and returns "suspicious" when the deadline is implausibly far in
//     the future (> cap + margin), which means a tampered/forward-dated envelope;
//   - otherwise slides the deadline forward to now + duration (activity) and
//     returns false.
// Call this once, early on load, before reading the secret. Passkey-backed and
// ephemeral (memory-only) identities have no persisted deadline to enforce and
// are skipped. A legacy bare-key secret (deadline null) is simply materialised
// into an envelope with a fresh deadline.
async function enforceCredentialTimeout() {
    // Passkeys are session-only by design; nothing persisted to expire.
    if (getIdentity().provider === "passkey") {
        return false;
    }
    const env = await digXipherSecret();
    if (!env) {
        return false;
    }
    // Held in memory only (ephemeral): leave it alone -it dies with the tab.
    if (!localStorage.getItem(xipherSecretStoreId)) {
        return false;
    }
    const now = Date.now();
    if (env.deadline !== null) {
        if (now > env.deadline) {
            clearStoredIdentity();
            return "expired";
        }
        if (env.deadline - now > MAX_TIMEOUT_MS + SUSPICIOUS_MARGIN_MS) {
            clearStoredIdentity();
            return "suspicious";
        }
    }
    // Activity: slide the deadline forward by the stored duration.
    await buryXipherSecret(env.key, env.durationMs);
    return false;
}

// Updates the user-chosen display name. Allowed for self-issued and
// passkey-backed identities; rejected only when an external provider issued
// the name (nameLocked).
function setSelfName(name) {
    if (getIdentity().nameLocked) {
        return false;
    }
    setIdentityField(xipherNameStoreId, name);
    return true;
}

/* ==========================================================================
   Credential-provider exchange record

   A single sessionStorage record, keyed by a random `state`, binds together the
   provider URL and the ephemeral secret key generated for one exchange. The
   public half is sent to the provider; the secret half stays here to open the
   sealed key it returns. The record is strictly single-use (deleted the instant
   it is read) and additionally expires after a short TTL to bound the exposure
   of an abandoned exchange. See the design notes for the rationale.
   ========================================================================== */

const providerExchangePrefix = "xipherProviderExchange:";
// Max lifetime of a pending exchange. Kept tight (<= 1 min) because the sealed
// payload is a long-term secret key; a stale return is rejected as spoofed.
const PROVIDER_EXCHANGE_TTL_MS = 60000;

// Generates a random URL-safe state token.
function newExchangeState() {
    const bytes = crypto.getRandomValues(new Uint8Array(18));
    let binary = "";
    for (const b of bytes) {
        binary += String.fromCharCode(b);
    }
    // base64url, no padding.
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Creates a pending exchange and returns its state token. The caller sends the
// ephemeral PUBLIC key and this state to the provider; the matching secret stays
// in the record so the return blob can be opened. The record holds the ephemeral
// secret key, so it is encrypted at rest with the same scheme as the stored
// identity key (encryptForStorage) rather than kept in plaintext.
async function createProviderExchange(providerUrl, ephemeralSecretKey) {
    const state = newExchangeState();
    const record = {
        providerUrl,
        ephemeralSecretKey,
        createdAt: Date.now(),
    };
    sessionStorage.setItem(providerExchangePrefix + state, await encryptForStorage(JSON.stringify(record)));
    return state;
}

// Reads and DELETES the exchange record for a returned state in one step. Returns
// the record, or null if absent (spoofed/replayed) or expired (stale). Deleting
// before use makes the exchange single-use even against an in-tab re-trigger.
async function consumeProviderExchange(state) {
    if (!state) {
        return null;
    }
    const id = providerExchangePrefix + state;
    const stored = sessionStorage.getItem(id);
    sessionStorage.removeItem(id);
    const raw = await decryptFromStorage(stored);
    if (!raw) {
        return null;
    }
    let record;
    try {
        record = JSON.parse(raw);
    } catch (error) {
        return null;
    }
    if (!record || typeof record.createdAt !== "number" ||
        Date.now() - record.createdAt > PROVIDER_EXCHANGE_TTL_MS) {
        return null;
    }
    return record;
}
