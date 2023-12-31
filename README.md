# Xipher

A curated collection of cryptographic primitives written purely in Go to encrypt and decrypt data locally with optional compression.

### Install or Update
```bash
go get -u gopkg.shib.me/xipher
```

### Usage Example
```go
package main

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/base58"
	"gopkg.shib.me/xipher"
)

func main() {
    // Creating a new private key for password
	privKey, err := xipher.NewPrivateKeyForPassword([]byte("some_password"))
	if err != nil {
		panic(err)
	}

    // Deriving  public key from private key
	pubKey, err := privKey.PublicKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("pubKey:", base58.Encode(pubKey.Bytes()))

	platinText := []byte("hello xipher!")

    // Encrypting plain text with public key
	cipherText, err := pubKey.Encrypt(platinText, true)
	if err != nil {
		panic(err)
	}
	fmt.Println("encrypted:", base58.Encode(cipherText))

    // Decrypting cipher text with private key
	plainText, err := privKey.Decrypt(cipherText)
	if err != nil {
		panic(err)
	}
	fmt.Println("decrypted:", string(plainText))
}
```
The output of the above code looks something like this:
```bash
pubKey: BeUKzwruWt2UagysUbRT3iT9epYvZLWG8XQ2GSr9fhypdPtYzPZQ7V3i8aT6qLokdjcAXo
encrypted: 5db2zz3Bbi4zhiXTqcCUqDrwfrtYAHoFS9WnDtgm6HczfFWbvSoMouKMUaHisTbnkcWbck3sCkahc4xvgNtZjFR2KWzZC56MRi2oq4NhxkjnDh8oAFPhGpKpBb17nCq7nCRxXaqeLBumhe6
decrypted: hello xipher!
```