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

async function setXipherSecret(xipherSecret) {
    const currentXipherSecret = localStorage.getItem("xipherSecret");
    if (currentXipherSecret !== xipherSecret) {
        localStorage.setItem("xipherSecret", xipherSecret);
        localStorage.removeItem("xipherPublicKey");
    }
}

async function getXipherSecret() {
    let xipherSecret = localStorage.getItem("xipherSecret");
    if (!xipherSecret) {
        localStorage.removeItem("xipherPublicKey");
        const xipherSecretOutput = await window.xipherNewSecretKey();
        if (xipherSecretOutput.error) {
            throw new Error(xipherSecretOutput.error);
        } else if (!xipherSecretOutput.result) {
            throw new Error("Failed to get secret key");
        }
        xipherSecret = xipherSecretOutput.result;
        const currentXipherSecret = localStorage.getItem("xipherSecret");
        if (currentXipherSecret !== xipherSecret) {
            localStorage.setItem("xipherSecret", xipherSecret);
        }
    }
    return xipherSecret;
}

async function getXipherPublicKey() {
    await getXipherSecret();
    let xipherPublicKey = localStorage.getItem("xipherPublicKey");
    if (!xipherPublicKey) {
        const xipherSecret = await getXipherSecret();
        const xipherPublicKeyOutput = await window.xipherGetPublicKey(xipherSecret);
        if (xipherPublicKeyOutput.error) {
            throw new Error(xipherPublicKeyOutput.error);
        } else if (!xipherPublicKeyOutput.result) {
            throw new Error("Failed to get public key");
        }
        xipherPublicKey = xipherPublicKeyOutput.result;
        localStorage.setItem("xipherPublicKey", xipherPublicKey);
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