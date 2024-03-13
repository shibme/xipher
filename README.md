# Xipher
[![Go Reference](https://pkg.go.dev/badge/dev.shib.me/xipher.svg)](https://pkg.go.dev/dev.shib.me/xipher)
[![Go Report Card](https://goreportcard.com/badge/dev.shib.me/xipher)](https://goreportcard.com/report/dev.shib.me/xipher)
[![Test Status](https://github.com/shibme/xipher/actions/workflows/test.yml/badge.svg)](https://github.com/shibme/xipher/actions/workflows/test.yml)
[![Release Status](https://github.com/shibme/xipher/actions/workflows/release.yml/badge.svg)](https://github.com/shibme/xipher/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/shibme/xipher)](https://github.com/shibme/xipher/blob/main/LICENSE)

Xipher is a curated collection of cryptographic primitives put together to perform password-based asymmetric encryption. It is written in Go and can be used as a library or a CLI tool.

### What does it do?
- Encrypts data with the public key generated based on a password.
- Supports stream cipher along with stream compression, resulting in lower memory footprint.

## Demo

![Demo](https://dev.shib.me/xipher/demo/xipher_text.gif)

## CLI Installation
Download the latest binary from the [releases](https://github.com/shibme/xipher/releases/latest) page and add it to your path.

### Homebrew
Xipher can be installed with brew using the following command on macOS
```zsh
brew install shibme/tap/xipher
```

### Install Script

#### Install Latest Version
**With Shell (MacOs/Linux):**
```sh
curl -fsSL https://dev.shib.me/xipher/install.sh | sh
```
**With PowerShell (Windows):**
```powershell
irm https://dev.shib.me/xipher/install.ps1 | iex
```

#### Install Specific Version
**With Shell (MacOs/Linux):**
```sh
curl -fsSL https://dev.shib.me/xipher/install.sh | sh -s v0.9.2
```
**With PowerShell (Windows):**
```powershell
$v="0.9.2"; irm https://dev.shib.me/xipher/install.ps1 | iex
```

### Docker
You can also run Xipher without installing using Docker:
```zsh
docker run --rm -v $PWD:/data -it shibme/xipher help
```


## Using as a Go package
Install the package
```sh
go get -u dev.shib.me/xipher
```
Use it in your code
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

## Under the hood
Xipher uses the following cryptographic primitives and libraries to encrypt/decrypt and compress/decompress data:
- [Argon2id](https://en.wikipedia.org/wiki/Argon2) for password hashing.
- [Curve25519](https://en.wikipedia.org/wiki/Curve25519) for elliptic curve cryptography.
- [XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) for encryption and decryption.
- [Zlib](https://en.wikipedia.org/wiki/Zlib) for compression and decompression.

## Disclaimer
This tool/library is provided without any warranties, and there is no guarantee of its stability. Due to the experimental nature of some of its components, it is anticipated that modifications to the code, repository, and API will be made in the future. Caution is advised before incorporating this into a production application. Please [report](https://github.com/shibme/xipher/security/advisories) any identified security issues promptly. Your cooperation in notifying us of such concerns is highly appreciated.
