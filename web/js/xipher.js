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

async function genXipherSecretKey() {
    const xipherKeyOutput = await window.xipherNewSecretKey();
    if (xipherKeyOutput.error || !xipherKeyOutput.result) {
        throw new Error(xipherKeyOutput.error ? xipherKeyOutput.error : "Failed to get secret key");
    }
    return xipherKeyOutput.result;
}

async function genXipherPublicKey(xipherSecret) {
    const xipherPublicKeyOutput = await window.xipherGetPublicKey(xipherSecret);
    if (xipherPublicKeyOutput.error || !xipherPublicKeyOutput.result) {
        throw new Error(xipherPublicKeyOutput.error ? xipherPublicKeyOutput.error : "Failed to get public key");
    }
    return xipherPublicKeyOutput.result;
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
        self = this;
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
        if (self.progressCallback && !self.cancelled) {
            self.progressCallback(self.processedSize, XipherStreamStatus.CANCELLING);
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
        self = this;
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
        if (self.progressCallback) {
            self.progressCallback(self.processedSize, XipherStreamStatus.CANCELLING);
        }
        this.cancelled = true;
    }
}