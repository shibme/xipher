<div align="center">
	<img src="https://xipher.org/assets/images/logo.svg" width="128" alt="Xipher Logo">
	<h1>Xipher</h1>
	<p><strong>Key/password-based asymmetric encryption with optional post-quantum security</strong></p>
	
[![Go Reference](https://pkg.go.dev/badge/xipher.org/xipher.svg)](https://pkg.go.dev/xipher.org/xipher)
[![Go Report Card](https://goreportcard.com/badge/xipher.org/xipher)](https://goreportcard.com/report/xipher.org/xipher)
[![Test Status](https://github.com/shibme/xipher/actions/workflows/test.yaml/badge.svg)](https://github.com/shibme/xipher/actions/workflows/test.yaml)
[![Release Status](https://github.com/shibme/xipher/actions/workflows/release.yaml/badge.svg)](https://github.com/shibme/xipher/actions/workflows/release.yaml)
[![License](https://img.shields.io/github/license/shibme/xipher)](https://github.com/shibme/xipher/blob/main/LICENSE)

</div>

## Overview

Xipher is a collection of cryptographic primitives for key/password-based asymmetric encryption, with optional post-quantum security. It lets you share encrypted data between parties over insecure channels using public keys derived from passwords.

## Features

- Asymmetric encryption using key/password-derived public keys
- Stream processing with built-in compression
- Post-quantum security (optional ML-KEM / Kyber-1024 support)
- Available as CLI tool, Go library, WebAssembly module, and web interface
- Optimized for both small and large data

## Quick Start

### Installation

#### CLI Tool

**Homebrew (macOS):**
```bash
brew install --cask shibme/tap/xipher
```

**Install Script (Linux/macOS):**
```bash
# Latest version
curl -fsSL https://xipher.org/install/install.sh | sh

# Specific version
curl -fsSL https://xipher.org/install/install.sh | sh -s vX.Y.Z
```

**Install Script (Windows):**
```powershell
# PowerShell (latest version)
irm https://xipher.org/install/install.ps1 | iex

# PowerShell with specific version
$v="X.Y.Z"; irm https://xipher.org/install/install.ps1 | iex
```

**Binary Download:**
Download from [releases page](https://github.com/shibme/xipher/releases/latest)

**Docker:**
```bash
docker run --rm -v $PWD:/data -it shibme/xipher help
```

#### Go Package
```bash
go get -u xipher.org/xipher
```

### Basic Usage

#### CLI Example
![Demo](https://xipher.org/assets/previews/demo.gif)

#### Go Package Example
```go
package main

import (
	"fmt"
	"xipher.org/xipher"
)

func main() {
	// Create secret key from password
	secretKey, err := xipher.NewSecretKeyForPassword([]byte("your-secure-password"))
	if err != nil {
		panic(err)
	}

	// Derive public key (pass true for quantum-safe)
	publicKey, err := secretKey.PublicKey(false)
	if err != nil {
		panic(err)
	}

	// Encrypt data (compress = true, encode = true)
	plaintext := []byte("Hello, World!")
	ciphertext, err := publicKey.Encrypt(plaintext, true, true)
	if err != nil {
		panic(err)
	}

	// Decrypt data
	decrypted, err := secretKey.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Original: %s\n", plaintext)
	fmt.Printf("Decrypted: %s\n", decrypted)
}
```

## Usage

### Web Interface
Try it out at [xipher.org](https://xipher.org)

How it works:

1. The receiver opens the web app and generates a key pair (keys are saved in the browser).
2. The receiver shares their public key URL with the sender.
3. The sender opens this URL, encrypts their data using the receiver's encryption URL, and then sends the resulting ciphertext (or encrypted link) back to the receiver.
4. The receiver decrypts the ciphertext in the same browser where the key pair was originally generated.

```mermaid
sequenceDiagram
participant RX as Xipher<br>(Browser)
actor R as Receiver
actor S as Sender
participant SX as Xipher<br>(Browser)
    R-->>+RX: Opens app
    RX-->>RX: Generate keys
    RX-->>-R: Public key URL
    R->>+S: Share URL
    S-->>+SX: Open URL & encrypt
    SX-->>-S: Ciphertext
    S->>-R: Send ciphertext
    R-->>+RX: Decrypt
    RX-->>-R: Plaintext
```

### CLI, GitHub Action, WebAssembly & self-hosting

Full command reference, flags, and copy-paste examples for the CLI, GitHub Action, WebAssembly module, and self-hosting the web app live in the [documentation](https://xipher.org/docs/).

## Technical Details

### Algorithms

- Key derivation: [Argon2id](https://en.wikipedia.org/wiki/Argon2)
- Elliptic curve: [Curve25519](https://en.wikipedia.org/wiki/Curve25519) with ephemeral key exchange
- Post-quantum: [ML-KEM / Kyber-1024](https://pq-crystals.org/kyber/)
- Symmetric encryption: [XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
- Compression: [Zlib](https://en.wikipedia.org/wiki/Zlib)

> **Note**: v1.19+ uses Go's native ML-KEM package for post-quantum crypto ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) compliant). This breaks compatibility with previous Kyber implementations. Standard ECC encryption is unaffected.

## Documentation

- Guides & examples: [xipher.org/docs](https://xipher.org/docs/)
- Architecture & cryptography: [xipher.org/docs/#arch-overview](https://xipher.org/docs/#arch-overview)
- Go API reference: [pkg.go.dev/xipher.org/xipher](https://pkg.go.dev/xipher.org/xipher)
- Web interface: [xipher.org](https://xipher.org)

## Contributing

Contributions are welcome. Fork the repo, make your changes, and submit a pull request. For bugs or feature requests, [open an issue](https://github.com/shibme/xipher/issues).

## Security

This project is experimental - use with caution in production. If you find security issues, please [report them](https://github.com/shibme/xipher/security/advisories).

A few things to keep in mind:
- Password strength matters
- Post-quantum algorithms are still evolving
- Keep your dependencies updated

See the [architecture &amp; security analysis](https://xipher.org/docs/#arch-overview) for cryptographic details.

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

## Acknowledgments

Thanks to these projects:

- [Retriever](https://retriever.corgea.io/) - Inspiration for web-based encryption concepts
- [StreamSaver.js](https://github.com/jimmywarting/StreamSaver.js) - Browser file saving capabilities
- [age](https://github.com/FiloSottile/age) - Inspiration for Curve25519 and XChaCha20-Poly1305 usage