const burialCache = new Map();
const xipherSecretStoreId = "xipherSecret";
const xipherPublicKeyStoreId = "xipherPublicKey";

async function loadXipherWASM() {
    if (!WebAssembly.instantiateStreaming) {
        WebAssembly.instantiateStreaming = async (resp, importObject) => {
            const source = await (await resp).arrayBuffer();
            return await WebAssembly.instantiate(source, importObject);
        };
    }
    const go = new Go();
    const result = await WebAssembly.instantiateStreaming(fetch("wasm/xipher.wasm"), go.importObject);
    go.run(result.instance);
}

async function bury(id, data) {
    const textEncoder = new TextEncoder();
    const dataBytes = textEncoder.encode(data);
    const hashBuffer = await crypto.subtle.digest("SHA-256", dataBytes);
    const hash = new Uint8Array(hashBuffer);
    const key = await crypto.subtle.importKey(
        "raw",
        hash,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedDataBuffer = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
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

async function genXipherKey() {
    const xipherKeyOutput = await window.xipherNewSecretKey();
    if (xipherKeyOutput.error) {
        throw new Error(xipherKeyOutput.error);
    } else if (!xipherKeyOutput.result) {
        throw new Error("Failed to get secret key");
    }
    return xipherKeyOutput.result;
}

async function getXipherSecret() {
    let xipherSecret = await dig(xipherSecretStoreId);
    if (!xipherSecret) {
        xipherSecret = await genXipherKey();
        await setXipherSecret(xipherSecret);
    }
    return xipherSecret;
}

async function getXipherPublicKey() {
    const xipherSecret = await getXipherSecret();
    let xipherPublicKey = localStorage.getItem(xipherPublicKeyStoreId);
    if (!xipherPublicKey) {
        const xipherPublicKeyOutput = await window.xipherGetPublicKey(xipherSecret);
        if (xipherPublicKeyOutput.error) {
            throw new Error(xipherPublicKeyOutput.error);
        } else if (!xipherPublicKeyOutput.result) {
            throw new Error("Failed to get public key");
        }
        xipherPublicKey = xipherPublicKeyOutput.result;
        localStorage.setItem(xipherPublicKeyStoreId, xipherPublicKey);
    }
    return xipherPublicKey;
}

const XipherStreamStatus = {
    PROCESSING: "PROCESSING",
    COMPLETED: "COMPLETED",
    FAILED: "FAILED",
    CANCELLED: "CANCELLED",
};

async function newEncryptingTransformer(keyOrPassword, compress) {
    const streamEncrypterOutput = await window.xipherNewEncryptingTransformer(keyOrPassword, compress);
    if (streamEncrypterOutput.error) {
        throw new Error(streamEncrypterOutput.error);
    } else if (!streamEncrypterOutput.result) {
        throw new Error("Failed to create stream encrypter");
    }
    return streamEncrypterOutput.result;
}

async function encryptThroughTransformer(encrypterId, chunkArray) {
    const writeOutput = await window.xipherEncryptThroughTransformer(encrypterId, chunkArray);
    if (writeOutput.error) {
        throw new Error(writeOutput.error);
    }
    return writeOutput.result;
}

async function closeEncryptingTransformer(encrypterId) {
    const closeOutput = await window.xipherCloseEncryptingTransformer(encrypterId);
    if (closeOutput.error) {
        throw new Error(closeOutput.error);
    }
    return closeOutput.result;
}

async function encryptFile(key, file, compress, outStream, progressCallback) {
    if (!file) {
        throw new Error("No file provided");
    }
    const encrypterId = await newEncryptingTransformer(key, compress);
    const fileStream = file.stream();
    let processedSize = 0;
    const encryptStream = new TransformStream({
        async transform(chunk, controller) {
            const chunkArray = new Uint8Array(chunk);
            const encryptedChunk = await encryptThroughTransformer(encrypterId, chunkArray);
            if (encryptedChunk && encryptedChunk.length > 0) {
                controller.enqueue(encryptedChunk);
                processedSize += chunkArray.length;
                progressCallback(processedSize, XipherStreamStatus.PROCESSING);
            }
        },
        async flush(controller) {
            const residualData = await closeEncryptingTransformer(encrypterId);
            if (residualData && residualData.length > 0) {
                controller.enqueue(residualData);
                processedSize += residualData.length;
                progressCallback(processedSize, XipherStreamStatus.PROCESSING);
            }
            controller.terminate();
        }
    });
    try {
        await fileStream.pipeThrough(encryptStream).pipeTo(outStream);
        progressCallback(processedSize, XipherStreamStatus.COMPLETED);
    } catch (error) {
        progressCallback(processedSize, XipherStreamStatus.FAILED);
    }
}

async function encryptStr(key, str) {
    const encryptOutput = await window.xipherEncryptStr(key, str);
    if (encryptOutput.error) {
        throw new Error(encryptOutput.error);
    } else if (!encryptOutput.result) {
        throw new Error("Failed to encrypt string");
    }
    return encryptOutput.result;
}

async function newDecryptingTransformer(keyOrPassword) {
    const streamDecrypterOutput = await window.xipherNewDecryptingTransformer(keyOrPassword);
    if (streamDecrypterOutput.error) {
        throw new Error(streamDecrypterOutput.error);
    } else if (!streamDecrypterOutput.result) {
        throw new Error("Failed to create stream decrypter");
    }
    return streamDecrypterOutput.result;
}

async function decryptThroughTransformer(decrypterId, chunkArray) {
    const readOutput = await window.xipherDecryptThroughTransformer(decrypterId, chunkArray);
    if (readOutput.error) {
        throw new Error(readOutput.error);
    }
    return readOutput.result;
}

async function closeDecryptingTransformer(decrypterId) {
    const closeOutput = await window.xipherCloseDecryptingTransformer(decrypterId);
    if (closeOutput.error) {
        throw new Error(closeOutput.error);
    }
    return closeOutput.result;
}

async function decryptFile(key, file, outStream, progressCallback) {
    if (!file) {
        throw new Error("No file provided");
    }
    const decrypterId = await newDecryptingTransformer(key);
    const fileStream = file.stream();
    let processedSize = 0;
    const decryptStream = new TransformStream({
        async transform(chunk, controller) {
            const chunkArray = new Uint8Array(chunk);
            const decryptedChunk = await decryptThroughTransformer(decrypterId, chunkArray);
            if (decryptedChunk && decryptedChunk.length > 0) {
                controller.enqueue(decryptedChunk);
                processedSize += chunkArray.length;
                progressCallback(processedSize, XipherStreamStatus.PROCESSING);
            }
        },
        async flush(controller) {
            const residualData = await closeDecryptingTransformer(decrypterId);
            if (residualData && residualData.length > 0) {
                controller.enqueue(residualData);
                processedSize += residualData.length;
                progressCallback(processedSize, XipherStreamStatus.PROCESSING);
            }
            controller.terminate();
        }
    });
    try {
        await fileStream.pipeThrough(decryptStream).pipeTo(outStream);
        progressCallback(processedSize, XipherStreamStatus.COMPLETED);
    } catch (error) {
        progressCallback(processedSize, XipherStreamStatus.FAILED);
    }
}

async function decryptStr(key, ct) {
    const decryptOutput = await window.xipherDecryptStr(key, ct);
    if (decryptOutput.error) {
        throw new Error(decryptOutput.error);
    } else if (!decryptOutput.result) {
        throw new Error("Failed to decrypt string");
    }
    return decryptOutput.result;
}