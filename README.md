# Xipher
[![Go Reference](https://pkg.go.dev/badge/dev.shib.me/xipher.svg)](https://pkg.go.dev/dev.shib.me/xipher)
[![Go Report Card](https://goreportcard.com/badge/dev.shib.me/xipher)](https://goreportcard.com/report/dev.shib.me/xipher)
[![Test Status](https://github.com/shibme/xipher/actions/workflows/test.yml/badge.svg)](https://github.com/shibme/xipher/actions/workflows/test.yml)
[![Release Status](https://github.com/shibme/xipher/actions/workflows/release.yml/badge.svg)](https://github.com/shibme/xipher/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/shibme/xipher)](https://github.com/shibme/xipher/blob/main/LICENSE)

Xipher is a curated collection of cryptographic primitives written in Go to encrypt and decrypt data with optional compression.

### Features
- Password based public key generation.
- Encrypt data with public key generated from a password.
- Encrypt data with password or a generated private key.
- Decrypt data with password or a a given private key (works on all combinations of encryption).
- Supports stream cipher along with stream compression thereby keeping a low memory footprint. Makes it handy for encrypting large files or data streams.

### Under the hood
Xipher uses the following cryptographic primitives and libraries to encrypt/decrypt and compress/decompress data:
- [Argon2id](https://en.wikipedia.org/wiki/Argon2) for password hashing.
- [Curve25519](https://en.wikipedia.org/wiki/Curve25519) for elliptic curve cryptography.
- [XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) for encryption and decryption.
- [Zlib](https://en.wikipedia.org/wiki/Zlib) for compression and decompression.

### Install or Update
```bash
go get -u dev.shib.me/xipher
```

### Usage Example
```go
package main

import (
	"encoding/base32"
	"fmt"

	"dev.shib.me/xipher"
)

func main() {
	// Creating a new private key for password
	privKey, err := xipher.NewPrivateKeyForPassword([]byte("xipher_password"))
	if err != nil {
		panic(err)
	}

	// Deriving  public key from private key
	pubKey, err := privKey.PublicKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("PublicKey:", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(pubKey.Bytes()))

	platinText := []byte("Hello World!")

	// Encrypting plain text with public key
	cipherText, err := pubKey.Encrypt(platinText, true)
	if err != nil {
		panic(err)
	}
	fmt.Println("Encrypted:", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cipherText))

	// Decrypting cipher text with private key
	plainText, err := privKey.Decrypt(cipherText)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", string(plainText))
}
```
The output of the above code looks something like this:
```sh
PublicKey: MS5JUG7ZVJLETJA7WE2XKFHRE4PP6LKYCTEF2FTNUJ5QEZJIGZPCAIABX7UMDM7DPZX6WNOXICBUBBPPKE
Encrypted: AQQCAAN75DA3HY36N7VTLV2AQNAIL32RBWA2GJY7JNFA7QNOBT4CFXFBZMKY36DGE6FBKPATB7EJTD5SCNXI6URGO4WERYXYHYTL4RCXLRMYBG4K4UDZ5HGE7APXUVZ4RNESUV3EWVDJBHUAT5F7U5BFNUMTXB72Q3AZBGZDN3KXBWLUX23Q
Decrypted: Hello World!
```

### Basic CLI
Download the latest binary from the [releases](https://github.com/shibme/xipher/releases/latest) page and add it to your path.

You can also install with brew using the following command
```sh
brew install shibme/beta/xipher
```
Alternatively try it out using docker by mounting to `/data` directory inside the container
```sh
docker run --rm -v $(pwd):/data/ -it shibme/xipher help
```