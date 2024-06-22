package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	fmt.Println("Xipher Web Assembly!")
	js.Global().Set("xipherNewSecretKey", newSecretKey())
	js.Global().Set("xipherGetPublicKey", getPublicKey())
	js.Global().Set("xipherEncryptStr", encryptStr())
	js.Global().Set("xipherDecryptStr", decryptStr())
	<-make(chan struct{})
}
