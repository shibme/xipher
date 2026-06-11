// The release workflow rewrites "xipher-cache" to "xipher-v<release-version>"
// (see .github/workflows/release.yaml), so this key tracks the release and
// busts the IndexedDB WASM module cache on every version. Leave as-is.
const WASM_CACHE_KEY = 'xipher-cache';
const WASM_IDB_NAME = 'xipher-wasm';

function _openWasmIDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(WASM_IDB_NAME, 1);
        req.onupgradeneeded = e => e.target.result.createObjectStore(WASM_IDB_NAME);
        req.onsuccess = e => resolve(e.target.result);
        req.onerror = e => reject(e.target.error);
    });
}

function _getFromIDB(db, key) {
    return new Promise((resolve, reject) => {
        const req = db.transaction(WASM_IDB_NAME).objectStore(WASM_IDB_NAME).get(key);
        req.onsuccess = e => resolve(e.target.result);
        req.onerror = e => reject(e.target.error);
    });
}

function _putInIDB(db, key, value) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(WASM_IDB_NAME, 'readwrite');
        tx.objectStore(WASM_IDB_NAME).put(value, key);
        tx.oncomplete = () => resolve();
        tx.onerror = e => reject(e.target.error);
    });
}

// Deletes all keys in the WASM IDB store except the current version key,
// mirroring what the service worker does for HTTP caches on activate.
function _pruneWasmIDB(db) {
    return new Promise((resolve) => {
        const tx = db.transaction(WASM_IDB_NAME, 'readwrite');
        const store = tx.objectStore(WASM_IDB_NAME);
        const req = store.getAllKeys();
        req.onsuccess = e => {
            e.target.result
                .filter(k => k !== WASM_CACHE_KEY)
                .forEach(k => store.delete(k));
        };
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve(); // non-fatal
    });
}

async function loadXipherWASM() {
    if (!WebAssembly.instantiateStreaming) {
        WebAssembly.instantiateStreaming = async (resp, importObject) => {
            const source = await (await resp).arrayBuffer();
            return await WebAssembly.instantiate(source, importObject);
        };
    }
    const go = new Go();
    try {
        const db = await _openWasmIDB();
        _pruneWasmIDB(db); // fire-and-forget cleanup of stale version entries
        const cached = await _getFromIDB(db, WASM_CACHE_KEY);
        if (cached) {
            const result = await WebAssembly.instantiate(cached, go.importObject);
            go.run(result.instance);
            return;
        }
        const wasmPath = window.XIPHER_WASM_PATH || 'wasm/xipher.wasm';
        const result = await WebAssembly.instantiateStreaming(fetch(wasmPath), go.importObject);
        go.run(result.instance);
        _putInIDB(db, WASM_CACHE_KEY, result.module).catch(() => {}); // fire-and-forget
    } catch (_) {
        // IDB unavailable (e.g. private browsing) - fall back to normal load
        const wasmPath = window.XIPHER_WASM_PATH || 'wasm/xipher.wasm';
        const result = await WebAssembly.instantiateStreaming(fetch(wasmPath), go.importObject);
        go.run(result.instance);
    }
}

async function genXipherSecretKey() {
    const xipherKeyOutput = await window.xipherNewSecretKey();
    if (xipherKeyOutput.error || !xipherKeyOutput.result) {
        throw new Error(xipherKeyOutput.error ? xipherKeyOutput.error : "Failed to get secret key");
    }
    return xipherKeyOutput.result;
}

// Derives a secret key (XSK_…) from a 64-byte seed. The seed is passed as a
// Uint8Array of exactly 64 bytes so raw entropy crosses into WASM intact.
async function genXipherSecretKeyFromSeed(seed) {
    const xipherKeyOutput = await window.xipherSecretKeyFromSeed(seed);
    if (xipherKeyOutput.error || !xipherKeyOutput.result) {
        throw new Error(xipherKeyOutput.error ? xipherKeyOutput.error : "Failed to get secret key");
    }
    return xipherKeyOutput.result;
}

async function genXipherPublicKey(xipherSecret, quantumSafe) {
    const xipherPublicKeyOutput = await window.xipherGetPublicKey(xipherSecret, !!quantumSafe);
    if (xipherPublicKeyOutput.error || !xipherPublicKeyOutput.result) {
        throw new Error(xipherPublicKeyOutput.error ? xipherPublicKeyOutput.error : "Failed to get public key");
    }
    return xipherPublicKeyOutput.result;
}

// Validates a string as a Xipher secret key (XSK_ prefix). The WASM module
// rejects malformed keys when deriving the public key, so we reuse that path.
async function isValidSecretKey(secret) {
    if (!secret || !secret.startsWith("XSK_")) {
        return false;
    }
    try {
        await genXipherPublicKey(secret, false);
        return true;
    } catch (error) {
        return false;
    }
}

const XipherStreamStatus = {
    PROCESSING: "PROCESSING",
    COMPLETED: "COMPLETED",
    FAILED: "FAILED",
    CANCELLING: "CANCELLING",
    CANCELLED: "CANCELLED",
};

async function encryptStr(key, str) {
    const encryptOutput = await window.xipherEncryptStr(key, str);
    if (encryptOutput.error) {
        throw new Error(encryptOutput.error);
    } else if (!encryptOutput.result) {
        throw new Error("Failed to encrypt string");
    }
    return encryptOutput.result;
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

class FileEncrypter {
    
    constructor(keyOrPassword, inputFile, outputStream, compress, progressCallback) {
        this.keyOrPassword = keyOrPassword;
        this.inputFile = inputFile;
        this.outputStream = outputStream;
        this.compress = compress;
        this.progressCallback = progressCallback;
        this.processedSize = 0;
        this.cancelled = false;
        this.controllerAborted = false;
        this.ended = false;
    }

    async start() {
        const self = this;
        const streamEncrypterOutput = await window.xipherNewEncryptingTransformer(self.keyOrPassword, self.compress);
        if (streamEncrypterOutput.error || !streamEncrypterOutput.result) {
            throw new Error(streamEncrypterOutput.error ? streamEncrypterOutput.error : "Failed to initialize encrypter");
        }
        const encrypterId = streamEncrypterOutput.result;
        const fileStream = self.inputFile.stream();
        const encryptStream = new TransformStream({
            async transform(chunk, controller) {
                if (self.cancelled) {
                    if (!self.controllerAborted) {
                        controller.abort();
                        self.controllerAborted = true;
                    }
                    return;
                }
                const chunkArray = new Uint8Array(chunk);
                const transformedOutput = await window.xipherEncryptThroughTransformer(encrypterId, chunkArray);
                if (transformedOutput.error) {
                    throw new Error(transformedOutput.error);
                }
                const encryptedChunk = transformedOutput.result;
                if (encryptedChunk && encryptedChunk.length > 0) {
                    controller.enqueue(encryptedChunk);
                    self.processedSize += chunkArray.length;
                    if (self.progressCallback) {
                        self.progressCallback(self.processedSize, XipherStreamStatus.PROCESSING);
                    }
                }
            },
            async flush(controller) {
                const closedOutput = await window.xipherCloseEncryptingTransformer(encrypterId);
                if (closedOutput.error) {
                    throw new Error(closedOutput.error);
                }
                const residualData = closedOutput.result;
                if (residualData && residualData.length > 0) {
                    controller.enqueue(residualData);
                    self.processedSize += residualData.length;
                    if (self.progressCallback) {
                        self.progressCallback(self.processedSize, XipherStreamStatus.PROCESSING);
                    }
                }
                controller.terminate();
            }
        });
        let finalStatus = XipherStreamStatus.COMPLETED;
        try {
            await fileStream.pipeThrough(encryptStream).pipeTo(self.outputStream);
        } catch (error) {
            finalStatus = XipherStreamStatus.FAILED;
        }
        if (self.cancelled) {
            finalStatus = XipherStreamStatus.CANCELLED;
        }
        if (self.progressCallback) {
            self.progressCallback(self.processedSize, finalStatus);
        }
        this.ended = true;
    }

    isEnded() {
        return this.ended;
    }

    async cancel() {
        if (this.progressCallback && !this.cancelled) {
            this.progressCallback(this.processedSize, XipherStreamStatus.CANCELLING);
        }
        this.cancelled = true;
    }
}

class FileDecrypter {

    constructor(keyOrPassword, inputFile, outputStream, progressCallback) {
        this.keyOrPassword = keyOrPassword;
        this.inputFile = inputFile;
        this.outputStream = outputStream;
        this.progressCallback = progressCallback;
        this.processedSize = 0;
        this.cancelled = false;
        this.controllerAborted = false;
        this.ended = false;
    }

    async start() {
        const self = this;
        const streamDecrypterOutput = await window.xipherNewDecryptingTransformer(self.keyOrPassword);
        if (streamDecrypterOutput.error || !streamDecrypterOutput.result) {
            throw new Error(streamDecrypterOutput.error ? streamDecrypterOutput.error : "Failed to initialize decrypter");
        }
        const decrypterId = streamDecrypterOutput.result;
        const fileStream = self.inputFile.stream();
        const decryptStream = new TransformStream({
            async transform(chunk, controller) {
                if (self.cancelled) {
                    if (!self.controllerAborted) {
                        controller.abort();
                        self.controllerAborted = true;
                    }
                    return;
                }
                const chunkArray = new Uint8Array(chunk);
                const transformedOutput = await window.xipherDecryptThroughTransformer(decrypterId, chunkArray);
                if (transformedOutput.error) {
                    throw new Error(transformedOutput.error);
                }
                const decryptedChunk = transformedOutput.result;
                if (decryptedChunk && decryptedChunk.length > 0) {
                    controller.enqueue(decryptedChunk);
                    self.processedSize += chunkArray.length;
                    if (self.progressCallback) {
                        self.progressCallback(self.processedSize, XipherStreamStatus.PROCESSING);
                    }
                }
            },
            async flush(controller) {
                if (self.cancelled) {
                    if (!self.controllerAborted) {
                        controller.abort();
                        self.controllerAborted = true;
                    }
                    return;
                }
                const closedOutput = await window.xipherCloseDecryptingTransformer(decrypterId);
                if (closedOutput.error) {
                    throw new Error(closedOutput.error);
                }
                const residualData = closedOutput.result;
                if (residualData && residualData.length > 0) {
                    controller.enqueue(residualData);
                    self.processedSize += residualData.length;
                    if (self.progressCallback) {
                        self.progressCallback(self.processedSize, XipherStreamStatus.PROCESSING);
                    }
                }
                controller.terminate();
            }
        });
        let finalStatus = XipherStreamStatus.COMPLETED;
        try {
            await fileStream.pipeThrough(decryptStream).pipeTo(self.outputStream);
        } catch (error) {
            finalStatus = XipherStreamStatus.FAILED;
        }
        if (self.cancelled) {
            finalStatus = XipherStreamStatus.CANCELLED;
        }
        if (self.progressCallback) {
            self.progressCallback(self.processedSize, finalStatus);
        }
        this.ended = true;
    }

    isEnded() {
        return this.ended;
    }

    async cancel() {
        if (this.progressCallback) {
            this.progressCallback(this.processedSize, XipherStreamStatus.CANCELLING);
        }
        this.cancelled = true;
    }
}