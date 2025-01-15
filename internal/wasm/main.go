package main

import (
	"syscall/js"
)

func exportJSFunc(name string, fn func(args []js.Value) (result any, err error)) {
	js.Global().Set(name, js.FuncOf(func(this js.Value, args []js.Value) any {
		result, err := fn(args)
		if err != nil {
			return map[string]any{
				"error": err.Error(),
			}
		}
		return map[string]any{
			"result": result,
		}
	}))
}

func main() {
	// Keygen Functions
	exportJSFunc("xipherNewSecretKey", newSecretKey)
	exportJSFunc("xipherGetPublicKey", getPublicKey)

	// Encryption Functions
	exportJSFunc("xipherEncryptStr", encryptStr)
	exportJSFunc("xipherNewEncryptingTransformer", newEncryptingTransformer)
	exportJSFunc("xipherEncryptThroughTransformer", encryptThroughTransformer)
	exportJSFunc("xipherCloseEncryptingTransformer", closeEncryptingTransformer)

	// Decryption Functions
	exportJSFunc("xipherDecryptStr", decryptStr)
	exportJSFunc("xipherNewDecryptingTransformer", newDecryptingTransformer)
	exportJSFunc("xipherDecryptThroughTransformer", decryptThroughTransformer)
	exportJSFunc("xipherCloseDecryptingTransformer", closeDecryptingTransformer)

	<-make(chan struct{})
}
