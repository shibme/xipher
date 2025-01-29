const burialCache = new Map();
const xipherSecretStoreId = "xipherSecret";
const xipherPublicKeyStoreId = "xipherPublicKey";

async function bury(id, data) {
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
    localStorage.setItem(id, String.fromCharCode(...combinedData));
    burialCache.set(id, data);
}

async function dig(id) {
    const cachedData = burialCache.get(id);
    if (cachedData) {
        return cachedData;
    }
    try {
        const storedData = localStorage.getItem(id);
        if (!storedData) {
            return null;
        }
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
        const textDecoder = new TextDecoder();
        const originalData = textDecoder.decode(decryptedDataBuffer);
        burialCache.set(id, originalData);
        return originalData;
    } catch (error) {
        console.error("Xipher dig failed!");
        return null;
    }
}

async function setXipherSecret(xipherSecret) {
    const currentXipherSecret = await dig(xipherSecretStoreId);
    if (currentXipherSecret !== xipherSecret) {
        await bury(xipherSecretStoreId, xipherSecret);
        localStorage.removeItem(xipherPublicKeyStoreId);
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
        xipherPublicKey = await genXipherPublicKey(xipherSecret);
        localStorage.setItem(xipherPublicKeyStoreId, xipherPublicKey);
    }
    return xipherPublicKey;
}