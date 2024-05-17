# Xipher
[![Go Reference](https://pkg.go.dev/badge/dev.shib.me/xipher.svg)](https://pkg.go.dev/dev.shib.me/xipher)
[![Go Report Card](https://goreportcard.com/badge/dev.shib.me/xipher)](https://goreportcard.com/report/dev.shib.me/xipher)
[![Test Status](https://github.com/shibme/xipher/actions/workflows/test.yml/badge.svg)](https://github.com/shibme/xipher/actions/workflows/test.yml)
[![Release Status](https://github.com/shibme/xipher/actions/workflows/release.yml/badge.svg)](https://github.com/shibme/xipher/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/shibme/xipher)](https://github.com/shibme/xipher/blob/main/LICENSE)

Xipher is a curated collection of cryptographic primitives put together to perform key/password based asymmetric encryption.

## What does it do?

- Allows sharing of data securely between two parties over an insecure channel using asymmetric encryption.
- The sender encrypts the data using a public key (received from a receiver) derived from a password and shares the encrypted data with the receiver.
- The receiver decrypts the data using the same password.

## Key Aspects
- Encrypts data with the public key generated based on a password.
- Supports stream cipher along with stream compression, resulting in lower memory footprint.
- Supports post-quantum cryptography using the Kyber algorithm.

## CLI
Download the latest binary from the [releases](https://github.com/shibme/xipher/releases/latest) page and add it to your path.

### Demo

![Demo](https://dev.shib.me/xipher/demo/xipher_text.gif)

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
curl -fsSL https://dev.shib.me/xipher/install.sh | sh -s v1.1.0
```
**With PowerShell (Windows):**
```powershell
$v="1.1.0"; irm https://dev.shib.me/xipher/install.ps1 | iex
```

### Docker
You can also run Xipher without installing using Docker:
```zsh
docker run --rm -v $PWD:/data -it shibme/xipher help
```

## Web Interface

- An interoperable web interface implemented using [web assembly](#web-assembly) is available at [https://dev.shib.me/xipher/web](https://dev.shib.me/xipher/web).
- The source code for the web implementation is available at [shibina3/xenigma](https://github.com/shibina3/xenigma).

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
	privKey, err := xipher.NewPrivateKeyForPassword([]byte("Paws0meKittyKuwan!"))
	if err != nil {
		panic(err)
	}

	// Deriving  public key from private key
	pubKey, err := privKey.PublicKey(false)
	if err != nil {
		panic(err)
	}
	publicKeyBytes, err := pubKey.Bytes()
	if err != nil {
		panic(err)
	}
	fmt.Println("PublicKey:", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publicKeyBytes))

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

## Web Assembly
To use xipher as a web assembly (wasm) module in a browser app, follow the example below.
```html
<html>
	<head>
		<meta charset="utf-8"/>
		<script src="https://dev.shib.me/xipher/wasm/wasm_exec.js"></script>
		<script>
			const go = new Go();
			WebAssembly.instantiateStreaming(fetch("https://dev.shib.me/xipher/wasm/xipher.wasm"), go.importObject).then((result) => {
				go.run(result.instance);
			});
		</script>
	</head>
<body>
	Call Xipher methods that start with xipher. For example: xipherNewSecretKey()
</body>
</html>
```

## Under the hood
Xipher uses the following algorithms and libraries to achieve its functionality:
- [Argon2id](https://en.wikipedia.org/wiki/Argon2) for password hashing.
- [Curve25519](https://en.wikipedia.org/wiki/Curve25519) for elliptic curve cryptography.
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/) using [CIRCL](https://github.com/cloudflare/circl) library for post-quantum cryptography.
- [XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) for symmetric encryption.
- [Zlib](https://en.wikipedia.org/wiki/Zlib) for compression.

## Workflow
The following sequence diagram illustrates the workflow of Xipher in encrypting data using a password based public key.
```mermaid
sequenceDiagram
participant RX as Xipher
actor Receiver
actor Sender
participant SX as Xipher
    Receiver-->>+RX: Derive public (inputs password)
    RX-->>-Receiver: Returns Public Key
    Receiver->>Sender: Shares Public Key
    Sender-->>+SX: Encrypt data with public key
    SX-->>-Sender: Returns ciphertext encrypted with Public Key
    Sender->>Receiver: Sends the encrypted ciphertext to the Receiver
    Receiver-->>+RX: Decrypt data (inputs ciphertext and password)
    RX-->>-Receiver: Returns decrypted data
```

## Disclaimer
This tool/library is provided without any warranties, and there is no guarantee of its stability. Due to the experimental nature of some of its components, it is anticipated that modifications to the code, repository, and API will be made in the future. Caution is advised before incorporating this into a production application. Please [report](https://github.com/shibme/xipher/security/advisories) any identified security issues promptly. Your cooperation in notifying us of such concerns is highly appreciated.
