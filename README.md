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
- Quantum-safe security (optional hybrid X25519 + ML-KEM-1024 support)
- Available as CLI tool, Go library, WebAssembly module, and web interface
- Optimized for both small and large data

## Quick Start

### Installation

```bash
# CLI (Homebrew, macOS)
brew install --cask shibme/tap/xipher

# CLI (Linux/macOS install script)
curl -fsSL https://xipher.org/install/install.sh | sh

# Go package
go get -u xipher.org/xipher
```

See the [installation guide](https://xipher.org/docs/#cli-install) for Windows, Docker, binary downloads, and version pinning.

### Basic Usage

#### CLI Example
![Demo](https://xipher.org/assets/previews/demo.gif)

#### Go Package Example
See the [Go library guide](https://xipher.org/docs/#lib-usage) for derive-key/encrypt/decrypt and streaming examples, and the [API reference](https://pkg.go.dev/xipher.org/xipher) for the full surface.

## Usage

### Web Interface

Try it out at [xipher.org](https://xipher.org). Keys are generated and stored in your browser, and all encryption happens locally. See the [web app guide](https://xipher.org/docs/#web-overview) for the full send/receive flow.

### CLI, GitHub Action, WebAssembly & self-hosting

Full command reference, flags, and copy-paste examples for the CLI, GitHub Action, WebAssembly module, and self-hosting the web app live in the [documentation](https://xipher.org/docs/).

### Public key references (URLs & domains)

Anywhere a public key is accepted, you can instead point Xipher at an **HTTPS URL** (or bare domain) that serves the key, giving recipients a friendly, memorable reference instead of a long `XPK_…` string.

```bash
xipher encrypt text --fetch -k "alice.example.com" -t "Secret message"
```

A bare domain resolves to `/.well-known/xipher`. See [key references](https://xipher.org/docs/#keyref-overview) for resolution rules, the published key format, and hosting (including the CORS requirement for the web app).

## Technical Details

Argon2id key derivation, Curve25519 / X25519 (with an optional quantum-safe hybrid that combines X25519 and ML-KEM-1024), and XChaCha20-Poly1305. See the [cryptographic primitives](https://xipher.org/docs/#arch-primitives) for parameters, security levels, and the data format.

> **Note**: v1.19+ uses Go's native ML-KEM package for post-quantum crypto ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) compliant). This breaks compatibility with previous Kyber implementations. Standard ECC encryption is unaffected.
>
> **Note**: Quantum-safe mode now defaults to a hybrid of X25519 and ML-KEM-1024 instead of pure ML-KEM, so security holds as long as either primitive is unbroken. Ciphertexts and public keys self-describe their algorithm, so data produced with the earlier pure ML-KEM mode still decrypts.

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