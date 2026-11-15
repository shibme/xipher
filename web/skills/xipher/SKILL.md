---
name: xipher
description: Encrypt and decrypt text, files, and streams with the Xipher CLI, including password-derived public keys, published key URLs, and optional post-quantum (X25519 + ML-KEM-1024) mode. Use when a user needs to share a secret over an insecure channel without a server, or asks how to encrypt data with xipher.
license: MIT
---

# Xipher

Xipher is key/password-based asymmetric encryption. A receiver publishes a public key (`XPK_…`); a sender
encrypts to it; only the holder of the matching secret key (`XSK_…`) or password can decrypt.

Canonical documentation: **https://xipher.org/docs.md**
This skill is a summary. If it disagrees with the docs, the docs win.

## Install

```bash
curl -fsSL https://xipher.org/install/install.sh | sh       # Linux / macOS
brew install --cask shibme/tap/xipher                        # macOS
```

Check with `xipher version`. Every command supports `--help`.

## Commands

```bash
# Public key derived from a password (prompts)
xipher keygen

# Random key pair, or a quantum-safe public key
xipher keygen --auto
xipher keygen --quantum-safe

# Text
xipher encrypt text -k "XPK_..." -t "message"
xipher decrypt text -c "XCT_..."

# Files and streams
xipher encrypt file -k "XPK_..." -f report.pdf -o report.pdf.xipher
xipher decrypt file -f report.pdf.xipher
cat data.bin | xipher encrypt stream -k "XPK_..." > data.bin.xipher
cat data.bin.xipher | xipher decrypt stream > data.bin

# Published key (a domain or URL, with the conventional /.well-known/xipher path)
xipher encrypt text --fetch -k "alice.example.com" -t "message"

# Machine-readable output
xipher keygen --auto --json
```

`-k` accepts a public key, a secret key, a password, or a URL/domain. Use `XIPHER_SECRET` for
non-interactive decryption.

## Rules

1. Never print or transmit an `XSK_` value. Treat any exposed secret key as compromised.
2. Never put a secret key or password in a URL. Links carry public keys only.
3. Prefer `XIPHER_SECRET` over `-k "XSK_..."` so the key does not land in shell history.
4. Do not invent flags; read `--help`.
5. `--web-auth` needs a browser and a loopback callback — it does not work headless.

## Scope

Use Xipher for sharing secrets or files without a trusted server, for memorable password-derived key
references, and for scripted encryption in CI. It is not a password manager, a TLS replacement, or a
disk-encryption tool. It does not verify key ownership beyond TLS.

Full details: https://xipher.org/docs.md
