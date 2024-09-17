const xipher = {
    async newSecretKey() {
        const response = await window.xipherNewSecretKey();
        if (response.error) {
            throw new Error(response.error);
        }
        return response.result;
    },

    async getPublicKey(xSecret) {
        const response = await window.xipherGetPublicKey(xSecret);
        if (response.error) {
            throw new Error(response.error);
        }
        return response.result;
    },

    async encryptStr(publicKey, str) {
        const response = await window.xipherEncryptStr(publicKey, str);
        if (response.error) {
            throw new Error(response.error);
        }
        return response.result;
    },

    async decryptStr(xSecret, cipherText) {
        const response = await window.xipherDecryptStr(xSecret, cipherText);
        if (response.error) {
            throw new Error(response.error);
        }
        return response.result;
    }
};

export default xipher;