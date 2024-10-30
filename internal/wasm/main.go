package main

import (
	"fmt"
	"syscall/js"
)

func unifiedReturn(fn func(args []js.Value) (result any, err error)) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		result, err := fn(args)
		if err != nil {
			return map[string]any{
				"error": err.Error(),
			}
		}
		return map[string]any{
			"result": result,
		}
	})
}

func main() {
	fmt.Println("Xipher Web Assembly!")

	// Keygen Functions
	js.Global().Set("xipherNewSecretKey", unifiedReturn(newSecretKey))
	js.Global().Set("xipherGetPublicKey", unifiedReturn(getPublicKey))

	// Encryption Functions
	js.Global().Set("xipherEncryptStr", unifiedReturn(encryptStr))
	js.Global().Set("xipherNewStreamEncrypter", unifiedReturn(newStreamEncrypter))
	js.Global().Set("xipherEncrypterWrite", unifiedReturn(writeToEncrypter))
	js.Global().Set("xipherEncrypterClose", unifiedReturn(closeEncrypter))

	// Decryption Functions
	js.Global().Set("xipherDecryptStr", unifiedReturn(decryptStr))
	js.Global().Set("xipherNewStreamDecrypter", unifiedReturn(newStreamDecrypter))
	js.Global().Set("xipherDecrypterRead", unifiedReturn(readFromDecrypter))
	js.Global().Set("xipherDecrypterClose", unifiedReturn(closeDecrypter))

	<-make(chan struct{})
}
