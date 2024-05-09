package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	fmt.Println("Xipher Web Assembly!")
	js.Global().Set("xipherNewSecretKey", newSecretKey())
	js.Global().Set("xipherPubKeyFromPrivKey", pubKeyFromPrivKey())
	js.Global().Set("xipherPubKeyFromPassword", pubKeyFromPassword())
	js.Global().Set("xipherEncryptStr", encryptStr())
	js.Global().Set("xipherDecryptStrWithSecretKey", decryptStrWithSecretKey())
	js.Global().Set("xipherDecryptStrWithPassword", decryptStrWithPassword())
	<-make(chan struct{})
}
