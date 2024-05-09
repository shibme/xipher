package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	fmt.Println("Xipher Web Assembly!")
	js.Global().Set("newSecretKey", newSecretKey())
	js.Global().Set("pubKeyFromPrivKey", pubKeyFromPrivKey())
	js.Global().Set("pubKeyFromPassword", pubKeyFromPassword())
	js.Global().Set("encryptStr", encryptStr())
	js.Global().Set("decryptStrWithSecretKey", decryptStrWithSecretKey())
	js.Global().Set("decryptStrWithPassword", decryptStrWithPassword())
	<-make(chan struct{})
}
