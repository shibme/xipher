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
// The id is a labelled identifier: a name (e.g. "Email", "Employee ID") and its
// value. Stored as two fields so the provider chooses how it's labelled.
const xipherIdNameStoreId = "xipherIdName";
const xipherIdValueStoreId = "xipherIdValue";
const xipherProviderStoreId = "xipherProvider";
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

async function setXipherSecret(xipherSecret) {
    const currentXipherSecret = await dig(xipherSecretStoreId);
    if (currentXipherSecret !== xipherSecret) {
        await bury(xipherSecretStoreId, xipherSecret);
        localStorage.removeItem(xipherPublicKeyStoreId);
        // A manual key/password change makes this a fresh self-issued identity:
        // drop any provider metadata and let the name default again. (The
        // provider flow uses setProviderIdentity instead, which sets these.)
        localStorage.removeItem(xipherNameStoreId);
        localStorage.removeItem(xipherIdNameStoreId);
        localStorage.removeItem(xipherIdValueStoreId);
        localStorage.removeItem(xipherProviderStoreId);
    }
}

// Installs a secret key delivered by an external credential provider, recording
// the issuing host and the managed name/id alongside it. Unlike setXipherSecret,
// this marks the identity as provider-managed (name/id read-only in the UI).
// `id` is an optional labelled identifier { name, value }.
async function setProviderIdentity(xipherSecret, providerHost, name, id) {
    await bury(xipherSecretStoreId, xipherSecret);
    localStorage.removeItem(xipherPublicKeyStoreId);
    localStorage.setItem(xipherProviderStoreId, providerHost);
    setIdentityField(xipherNameStoreId, name);
    // An id is only meaningful when it has a value; label defaults to "ID".
    const idValue = id && typeof id.value === "string" ? id.value : "";
    const idName = id && typeof id.name === "string" && id.name.trim() ? id.name : "ID";
    if (sanitiseIdentityField(idValue)) {
        setIdentityField(xipherIdNameStoreId, idName);
        setIdentityField(xipherIdValueStoreId, idValue);
    } else {
        localStorage.removeItem(xipherIdNameStoreId);
        localStorage.removeItem(xipherIdValueStoreId);
    }
}

async function getXipherSecret() {
    let xipherSecret = await dig(xipherSecretStoreId);
    if (!xipherSecret) {
        xipherSecret = await genXipherSecretKey();
        await setXipherSecret(xipherSecret);
    }
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
// delivered key would overwrite (and orphan) an existing identity.
async function getExistingXipherSecret() {
    return await dig(xipherSecretStoreId);
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
// host (defaults to self). `managed` is true when an external provider issued
// the key, in which case the name/id are read-only.
function getIdentity() {
    const provider = localStorage.getItem(xipherProviderStoreId) || selfHost();
    const managed = !!localStorage.getItem(xipherProviderStoreId);
    const idValue = localStorage.getItem(xipherIdValueStoreId) || "";
    return {
        name: localStorage.getItem(xipherNameStoreId) || "",
        // Labelled identifier; null when none was issued.
        id: idValue ? { name: localStorage.getItem(xipherIdNameStoreId) || "ID", value: idValue } : null,
        provider,
        managed,
    };
}

// Updates the user-chosen display name. Only meaningful for self-issued
// identities; rejected when the identity is provider-managed.
function setSelfName(name) {
    if (localStorage.getItem(xipherProviderStoreId)) {
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
