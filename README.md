# Xipher

A curated collection of cryptographic primitives written in Go to encrypt and decrypt data with optional compression.

### Features
- Password based public key generation
- Encrypt data with public key generated from a password
- Encrypt data with password or a generated private key
- Decrypt data with password or a a given private key (works on all combinations of encryption)

### Install or Update
```bash
go get -u gopkg.shib.me/xipher
```

### Usage Example
```go
package main

import (
	"encoding/base32"
	"fmt"

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
	fmt.Println("pubKey:", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(pubKey.Bytes()))

	platinText := []byte("Hello Xipher!")

	// Encrypting plain text with public key
	cipherText, err := pubKey.Encrypt(platinText, true)
	if err != nil {
		panic(err)
	}
	fmt.Println("encrypted:", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cipherText))

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
pubKey: KGDBEL7IDUENIGSPYT5L76CBXK6FR3N7OEBMXLCBR2SUPJW5VB6SAIABRJCMFOTGIYX5GI7ZSR5M3SMTQM
encrypted: AQQCAAMKITBLUZSGF7JSH6MUPLG4TE4DKX4VNIVJFYIE63UIHNMNHSVRPOG5IGGPDG24GVNKVUEQ55SK3QV2ZAOJINLCHKN4DGYPIZNKYNFRBM3BVTCO7UTA2H27U5GFFCQXAWBUPMKRHMT4UMFAQ7TCNHWETNTDYE66XGZA
decrypted: Hello Xipher!
```