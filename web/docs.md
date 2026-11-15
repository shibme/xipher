<!-- Canonical: https://xipher.org/docs.md · Markdown mirror of https://xipher.org/docs/ -->

# Xipher

Xipher is a lightweight, server-free tool for key/password-based asymmetric encryption. Share sensitive data over any channel (the CLI, your browser, a Go program, or WebAssembly) without trusting a server with your secrets.

- **Quick start**: Encrypt your first secret in under a minute.
- **CLI**: Scriptable encryption for your terminal.
- **Web app**: No install. Everything runs in your browser.
- **Go library**: Embed Xipher into your own programs.

<a id="introduction"></a>

## Introduction

Xipher lets two parties exchange encrypted data over an insecure channel using asymmetric encryption. A **receiver** shares a public key (often derived from a password); a **sender** encrypts data against that public key; only the receiver, who holds the matching secret key or password, can decrypt it.

It is available in several forms that all share the same cryptography and wire format:

- **CLI**: a single binary for Linux, macOS, and Windows.
- **Web app**: runs entirely in your browser via WebAssembly. Nothing is sent to a server.
- **Go library**: `xipher.org/xipher` for embedding in your apps.
- **WebAssembly module**: call Xipher directly from JavaScript.
- **GitHub Action**: bring Xipher into your CI pipelines.

<a id="concepts"></a>

## Core concepts

Xipher uses a handful of string types, each with a recognizable prefix:

| Prefix | Type | Meaning |
| --- | --- | --- |
| `XSK_` | Secret key | Private. Decrypts data. Never share it. |
| `XPK_` | Public key | Safe to share. Senders encrypt with it. |
| `XCT_` | Ciphertext | Encrypted data, safe to send over any medium. |

There are two ways to obtain a secret key:

- **Password-based**: derived from a password using Argon2id. Convenient and portable: the same password always yields the same identity, so you can decrypt on any device.
- **Random**: generated from 64 bytes of secure randomness (`XSK_…`). Maximum entropy, but you must store it safely, since it can't be recovered if lost.

> **💡 Note:**
>
> Enable **quantum-safe** mode when deriving a public key to use ML-KEM (Kyber-1024) alongside Curve25519, protecting against future quantum attacks. It produces larger keys and ciphertext.

### Symmetric vs asymmetric

If you pass a secret key (`XSK_…`) or a password as the key, Xipher encrypts **symmetrically**: the same credential encrypts and decrypts. That is what the web app does when you encrypt something for yourself, and it is the faster mode.

If you pass a public key (`XPK_…`), encryption is **asymmetric**: the sender needs only the public key, and only the holder of the matching secret key or password can decrypt. This is the mode to use when two different parties are involved. Only a public key can be handed to a sender - never a secret key or password.

<a id="quickstart"></a>

## Quick start

### With the CLI

```bash
# Encrypt a message with a password (you'll be prompted)
xipher encrypt text -t "Hello, World!"

# Decrypt it back
xipher decrypt text -c "XCT_..."
```

### In the browser

1. Open [the web app](https://xipher.org/). A key pair is generated and stored in your browser automatically.
2. Copy your *shareable link* and send it to whoever should send you a secret.
3. They open the link, type their message, and click **Encrypt**.
4. They send the resulting ciphertext (or encrypted link) back to you.
5. You paste it into the same browser and click **Decrypt**.

<a id="cli-install"></a>

## CLI

### Installation

**Homebrew (macOS):**

```bash
brew install --cask shibme/tap/xipher
```

**Install script (Linux / macOS):**

```bash
# Latest version
curl -fsSL https://xipher.org/install/install.sh | sh

# Specific version
curl -fsSL https://xipher.org/install/install.sh | sh -s v0.0.0
```

**Install script (Windows / PowerShell):**

```powershell
# Latest version
irm https://xipher.org/install/install.ps1 | iex

# Specific version
$v="0.0.0"; irm https://xipher.org/install/install.ps1 | iex
```

**Docker:**

```bash
docker run --rm -v $PWD:/data -it shibme/xipher help
```

<a id="cli-keygen"></a>

### Generating keys

```bash
# Derive a public key from a password (you'll be prompted)
xipher keygen

# Auto-generate a random secret key and show its public key
xipher keygen --auto

# Quantum-safe public key
xipher keygen --quantum-safe

# Write the public key to a file
xipher keygen --public-key-file mykey.xpk
```

| Flag | Short | Description |
| --- | --- | --- |
| `--auto` | `-a` | Auto-generate a secret key |
| `--quantum-safe` | `-q` | Use quantum-safe cryptography |
| `--public-key-file` | `-p` | Path to write the public key file |
| `--ignore-password-policy` |  | Skip the password strength check |

<a id="cli-encrypt"></a>

### Encrypting

```bash
# Encrypt text (prompts for a key/password if -k is omitted)
xipher encrypt text -t "Hello, World!"

# Encrypt text against a public key
xipher encrypt text -k "XPK_..." -t "Secret message"

# Read the plaintext from stdin
echo "piped secret" | xipher encrypt text -t -

# Encrypt a file
xipher encrypt file -k "XPK_..." -f report.pdf -o report.pdf.xipher

# Encrypt a stream (stdin -> stdout)
cat backup.tar | xipher encrypt stream -k "XPK_..." > backup.tar.xipher
```

| Flag | Short | Description |
| --- | --- | --- |
| `--key` | `-k` | Public key, secret key, password, or a URL/domain serving a public key |
| `--text` | `-t` | Text to encrypt (`-` reads stdin) |
| `--file` | `-f` | Path to the input file |
| `--out` | `-o` | Path to the output file |
| `--fetch` |  | Treat `--key` as a URL/domain and fetch the public key without prompting |
| `--compress` |  | Compress data before encryption |
| `--xiphertext` |  | Encode output as Xipher text |
| `--overwrite` |  | Overwrite the output file if it exists (`file` only) |
| `--ignore-password-policy` |  | Skip the password strength check |

<a id="cli-decrypt"></a>

### Decrypting

You are prompted for the secret key or password unless it is set via the `XIPHER_SECRET` environment variable.

```bash
# Decrypt text
xipher decrypt text -c "XCT_..."

# Decrypt a file (the .xipher suffix is stripped for the output path)
xipher decrypt file -f report.pdf.xipher

# ...or set an explicit output path
xipher decrypt file -f report.pdf.xipher -o report.pdf

# Decrypt a stream (stdin -> stdout)
cat backup.tar.xipher | xipher decrypt stream > backup.tar
```

| Flag | Short | Description |
| --- | --- | --- |
| `--ciphertext` | `-c` | Ciphertext to decrypt (`text` only) |
| `--file` | `-f` | Path to the encrypted input file |
| `--out` | `-o` | Path to the output file (inferred only when the input ends in `.xipher`) |
| `--overwrite` |  | Overwrite the output file if it exists |

If the input file does not end in `.xipher` and you omit `--out`, there is no name to infer: pass `--out` explicitly.

<a id="cli-webauth"></a>

### Web auth

When your key lives in a browser - set up as a passkey or as the web app's stored key - you can authenticate the CLI through the browser instead of typing a password or pasting a secret key. Pass `--web-auth` (`-w`) to any `encrypt` or `decrypt` command:

```bash
# Encrypt using a key obtained from the browser
xipher encrypt text --web-auth -t "Hello, World!"

# Decrypt using a key obtained from the browser
xipher decrypt text --web-auth -c "XCT_..."

# Point at a self-hosted Xipher instance
xipher encrypt text --web-auth --xipher-url "https://your-xipher.example.com" -t "Hello"
```

1. The CLI generates a one-time ephemeral keypair and a random `state` token, then starts a temporary HTTP server on a random loopback port.
2. It opens `https://xipher.org/web-auth/` (or your custom `--xipher-url`) in the default browser, passing the ephemeral public key (`xwa`), `state`, and callback address (`cb`) as query parameters.
3. The web page lets you authenticate - either with the current browser key or via a passkey - and seals (encrypts) your Xipher secret key to the ephemeral public key.
4. The sealed key is delivered to the CLI's local callback endpoint, which verifies the `state`, decrypts the payload with the ephemeral secret, and proceeds with the command.

| Flag | Description |
| --- | --- |
| `--web-auth` / `-w` | Authenticate via browser instead of prompting for a key or password |
| `--xipher-url` | Base URL of the Xipher web app to use (default: `https://xipher.org`) |

> **⚠️ Warning:**
>
> The callback server listens only on `127.0.0.1` (loopback) and the exchange times out after 3 minutes. The `state` parameter guards against CSRF. The ephemeral keypair is discarded immediately after use; the secret key is never written to disk.

<a id="cli-env"></a>

### Environment & JSON output

For non-interactive use (CI, scripts), provide your secret key or password via the `XIPHER_SECRET` environment variable. The `stream` subcommands require it.

```bash
export XIPHER_SECRET="XSK_..."   # or a password
cat data.bin | xipher encrypt stream -k "XPK_..." > data.bin.xipher
cat data.bin.xipher | xipher decrypt stream > data.bin

# Machine-readable output (works on any command)
xipher keygen --auto --json

# Version and help
xipher version
xipher encrypt --help
```

The global `--json` / `-j` flag emits structured output (and errors) as JSON on any command. Every command also accepts `--help` / `-h`.

<a id="keyref-overview"></a>

## Key references (URLs & domains)

Anywhere a public key is accepted, you can instead point Xipher at an **HTTPS URL** that serves the key. This gives recipients a friendly, memorable reference (your domain) instead of a long `XPK_…` string. Xipher fetches the URL and uses the public key it finds.

```bash
# Full URL to a published key
xipher encrypt text -k "https://alice.example.com/.well-known/xipher" -t "Secret message"

# A bare domain or URL: pass --fetch to fetch without a prompt
xipher encrypt text --fetch -k "alice.example.com" -t "Secret message"

# Without --fetch, a domain-like value asks for confirmation before fetching,
# so an ordinary password is never sent over the network by mistake.
xipher encrypt text -k "alice.example.com" -t "Secret message"
# > 'alice.example.com' looks like a domain. Fetch the public key from it? [y/N]:
```

- A **bare domain** (e.g. `alice.example.com`) is expanded to `https://` and the [well-known path](#keyref-format) is fetched.
- A **URL with a path** (e.g. `alice.example.com/shib`) is tried verbatim first; if no key is found there, the [well-known path](#keyref-format) is probed *under* that path (`alice.example.com/shib/.well-known/xipher`). So a path can point either directly at a key file or at a prefix that hosts one.
- Only `https://` is allowed. The one exception is **loopback hosts** (`localhost`, `127.0.0.1`, `::1`), which may use plain `http://` for local development.
- In the **web app**, opening a link such as `https://xipher.org/?xk=alice.example.com` resolves the key automatically. Only public keys and URLs are accepted through a link; secret keys and passwords are never read from the URL.

> **⚠️ Warning:**
>
> A URL authenticates the *host* (via TLS), not the key's owner. Treat a key reference as a convenience, not a cryptographic identity guarantee. Anyone who controls the host (or its DNS) controls the key served there.

<a id="keyref-format"></a>

### Published key format

The URL should serve the public key in one of two forms. Xipher tries JSON first, then falls back to plain text.

**JSON** (recommended, lets you attach a display name shown to the sender):

```json
{
  "name": "Alice",
  "publicKey": "XPK_..."
}
```

**Plain text**, where the response body is exactly the `XPK_…` string:

```text
XPK_...
```

| Field | Required | Notes |
| --- | --- | --- |
| `publicKey` | Yes | Must be a valid `XPK_…` public key |
| `name` | No | Display-only; trimmed and capped at 64 characters |

Responses must be served over HTTPS, return `200 OK`, and stay under 8 KiB. The conventional location for a bare domain is the well-known path:

```text
https://your-domain/.well-known/xipher
```

<a id="keyref-hosting"></a>

### Hosting a key

Publish the JSON (or plain `XPK_…`) file at `/.well-known/xipher` on any static host such as GitHub Pages, Cloudflare Pages, S3, or your own server. To host several keys under one domain, place each at `/<name>/.well-known/xipher` and share the path (e.g. `example.com/alice`), which probes that location automatically.

> **🌐 Warning:**
>
> **For the web app, CORS is required.** When the browser-based app resolves a key from another origin, the browser only allows it to read the response if your host sends an `Access-Control-Allow-Origin` header. Without it, resolution fails with a "couldn't reach that key URL" error. Add the header to your `/.well-known/xipher` response:

```text
Access-Control-Allow-Origin: *
Content-Type: application/json
```

The CLI and Go library are not browsers and have no CORS restriction. They resolve any reachable HTTPS URL regardless of headers.

<a id="web-overview"></a>

## Web app

The web app at [xipher.org](https://xipher.org) performs all cryptography locally using WebAssembly. Your keys are stored encrypted in your browser's local storage and never transmitted anywhere.

> **🔒 Note:**
>
> It works offline and can be installed as a Progressive Web App (PWA) on desktop and mobile. Once loaded, no network connection is required to encrypt or decrypt.

<a id="web-receive"></a>

### Receiving a secret

When you open the app fresh, you are the **receiver**. The app shows a shareable link containing your public key. Anyone who opens that link can encrypt data that only you can decrypt.

1. Copy the link with the button, or share it with the button.
2. When you receive ciphertext back, paste it into the text box and press **Decrypt**.

<a id="web-send"></a>

### Sending a secret

When you open someone else's shareable link, you become the **sender**. The app loads their public key automatically and any text or file you encrypt is locked to their identity.

1. Type your message or pick a file.
2. Press **Encrypt**.
3. Copy or share the resulting ciphertext / link back to the receiver.

<a id="web-keys"></a>

### Keys & passwords

By default the web app generates a random secret key the first time you visit. To use the same identity across devices, open ⚙️ Settings in the top bar and choose one of:

- **Password**: set a password; the same password recreates the same identity anywhere.
- **Secret key**: paste an existing `XSK_…` key (e.g. generated by the CLI).
- **Random**: generate a fresh, ephemeral key for one-off use.

> **⚠️ Warning:**
>
> Changing your key or password changes your public link. Secrets encrypted to your previous identity can still be decrypted only with that previous key or password.

<a id="web-passkeys"></a>

### Passkeys

Passkeys let you derive your Xipher secret key from a **WebAuthn platform authenticator** (Touch ID, Face ID, Windows Hello, etc.) instead of a typed password. When you register a passkey, the browser uses its PRF extension to produce a deterministic 32-byte value inside the authenticator, which Xipher expands to a 64-byte seed via HKDF-SHA-256. The derived key is identical every time you authenticate with the same device, without any secret ever leaving the authenticator.

To set up a passkey, open ⚙️ Settings and choose **Passkey** as the key source. Your device's biometric or PIN mechanism creates the credential. On subsequent visits the same passkey re-derives the same key.

> **💡 Note:**
>
> **Never at rest.** The passkey-derived key is never written to local storage. It is held only in memory for the current tab and is re-derived from your passkey each time you open the app, so you re-authenticate on every visit.

> **⚠️ Warning:**
>
> Passkey support requires Chrome 108+, Safari 17+, or Firefox 119+ and a device with a platform authenticator. Browsers or devices that lack the PRF extension will show a graceful error. A passkey is tied to the origin that created it - a self-hosted deployment uses its own passkeys, separate from those at `xipher.org`.

<a id="post-quantum"></a>

### Post-quantum encryption

Next to your shareable link is a **Post-quantum encryption** toggle. When on, Xipher uses a hybrid key exchange that combines Curve25519 (X25519) with ML-KEM-1024 (FIPS 203 / Kyber) instead of X25519 alone. The hybrid stays secure as long as *either* primitive is unbroken, which guards against "harvest-now, decrypt-later" attacks - where an adversary records ciphertext today to decrypt once a quantum computer can break classical ECC.

Because your public key is always re-derived from your stored identity, you can switch it on or off at any time without changing your password or secret key; your shareable link updates instantly. The tradeoff is a larger public key and ciphertext (~1.6 KB vs ~33 bytes for the key-exchange portion). See the [architecture](#arch-primitives) section for the full cryptographic details.

<a id="web-files"></a>

### Encrypting files

Drag & drop a file onto the text box, or use **Pick a file**. Files are processed as a stream, so even large files are handled efficiently without loading them fully into memory.

- Encrypted files are saved with a `.xipher` extension.
- To decrypt, drop a `.xipher` file and press **Decrypt**.

<a id="provider-overview"></a>

## Credential providers

A **credential provider** is an external service that authenticates a user and issues them a Xipher secret key, instead of the user generating one themselves. This lets an organization provision and manage identities for its members. For example, an internal portal that hands each employee the same Xipher key on any device after they sign in.

> **🔑 Warning:**
>
> **This is a key-escrow / custodial model, an opt-in departure from Xipher's default.** A provider that issues the secret key necessarily knows it, and can therefore read everything sent to that user and impersonate them. Self-generated keys remain the default; the provider flow is only ever entered when the app is opened with an explicit `?provider=` parameter. External providers require two confirmations (trust before redirect, and again if a different key would be replaced on return); a provider on the **same origin** as the app skips the pre-redirect trust step and redirect countdown as first-party.

The flow is modeled on the OAuth 2.0 Authorization Code grant, repurposed to deliver a secret key in place of a token. The browser binds the exchange with a one-time, single-use `state` and an ephemeral keypair, so the issued key can only be opened by the exact browser session that started the request, even if the return URL leaks.

<a id="provider-flow"></a>

### The exchange

1. **Initiate.** The app is opened at `https://xipher.org/?provider=<your-provider-url>`. After the user confirms the destination, the app generates a fresh ephemeral keypair, stores its secret half locally (encrypted in `sessionStorage`, bound to a random `state`), and redirects the browser to your provider URL with three query parameters.
2. **Authenticate & seal.** Your provider authenticates the user, validates the supplied callback against its allowlist, looks up that user's Xipher secret key (with an optional display name and identifier), and *seals* it to the supplied ephemeral public key.
3. **Return.** Your provider redirects the browser back to the callback URL with the sealed key and the original `state` in the **URL fragment**.
4. **Install.** The app verifies the `state` (single-use; absent or older than 15 minutes is rejected), decrypts the sealed key with the matching ephemeral secret, warns the user if a key already exists, and on confirmation sets it as the active identity.

```text
Browser (xipher app)                         Credential provider
  |                                                   |
  |  generate ephemeral keypair + state              |
  |  redirect: ?xpk&state&xcb                         |
  |-------------------------------------------------->|
  |                                          authenticate user
  |                                          check callback allowlist
  |                                          seal secret key to public key
  |  redirect back: #xck=&state=       |
  |<--------------------------------------------------|
  |  verify state, decrypt with ephemeral secret      |
  |  prompt, then set as identity                      |
  v                                                   v
```

<a id="provider-open"></a>

### Opening the app

Send the user to the app with your provider URL in the `provider` query parameter:

```text
https://xipher.org/?provider=https%3A%2F%2Fyour-provider.example%2Fissue
```

| Parameter | Required | Description |
| --- | --- | --- |
| `provider` | Yes | Your provider URL. The scheme is optional: a bare host like `auth.example.com` is promoted to HTTPS automatically. If you do include a scheme it must be `https://` (only loopback hosts may use `http://`, for local development); any other scheme is rejected. |
| `xecc` | No | Set (e.g. `xecc=1`) to request the compact X25519 key up front instead of the hybrid one. Use this when you know your server caps request URLs below ~4 KB, to skip the hybrid attempt. Omit it to get the stronger hybrid key with automatic fallback. |

<a id="provider-request"></a>

### Request parameters

The app redirects to your provider URL, appending these query parameters (existing query parameters in your URL are preserved):

| Parameter | Description |
| --- | --- |
| `xpk` | The ephemeral `XPK_…` public key to seal the user's secret key to. Fresh per request. Usually the hybrid (post-quantum) key; the app falls back to the compact X25519 key when the hybrid one would make the URL too long for your server. |
| `state` | An opaque, URL-safe one-time token. Echo it back unchanged. |
| `xcb` | The absolute app URL to redirect back to. **Validate this against your allowlist** before honoring the request. |

```text
https://your-provider.example/issue
    ?xpk=XPK_...
    &state=Yk9f...Q
    &xcb=https%3A%2F%2Fxipher.org%2F
```

<a id="provider-seal"></a>

### Sealing the key

"Sealing" is ordinary Xipher public-key encryption: encrypt the user's credentials to the supplied `xpk`. Only the holder of the matching ephemeral secret (the browser session that initiated the request) can open the result, so a leaked callback URL is useless to anyone else. The output is a standard `XCT_…` ciphertext.

Seal a small **JSON document** so you can attach the user's display name and an identifier alongside the key:

```json
{
  "key": "XSK_...",
  "name": "Alice Example",
  "id": "alice@acme.com",
  "type": "user",
  "timeout": 604800
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `key` | Either `key` or `seed` | The user's `XSK_…` secret key |
| `seed` | Either `key` or `seed` | The 64-byte seed the secret key is deterministically derived from, as **standard base64** (see below), an alternative to sending the key directly. If both `key` and `seed` are present, `key` takes precedence. |
| `name` | No | Display name; trimmed and capped at 64 characters |
| `id` | No | The identifier value for the authenticating entity (e.g. an email or service name). Shown read-only in the user's profile, labelled by `type` (or a generic `ID` when no type is given). |
| `type` | No | The kind of entity the `id` names: `user`, `group`, or `service`. Used as the read-only label shown beside the id. Any other value (or omitting it) just falls back to an `ID` label; the id is still kept. |
| `timeout` | No | How long the issued key stays valid in the browser, in **seconds**, capped at 7 days. The window slides forward on each visit and clears the key once it lapses. `0` - the default when omitted or invalid - makes the key **ephemeral**: it's never written to storage and lives only while the tab stays open, like a passkey. Send an explicit duration to persist the key. The user can shorten this in their profile but never extend it beyond what you issued. |

Instead of `key`, you may send a `seed` and let the app derive the secret key from it. This is useful when your provider stores or generates seeds rather than full keys. The same seed always yields the same key, so it must be kept as secret as the key itself. The seed is **exactly 64 bytes of raw entropy, base64-encoded** (standard or URL-safe base64; the app rejects anything that doesn't decode to 64 bytes).

```json
{
  "seed": "3q2+7wAAAAB...<88 base64 chars total>...AAAA=",
  "name": "Alice Example"
}
```

For backward compatibility the app also accepts a bare `XSK_…` string as the sealed payload (no name, id, or type). Seal with any Xipher binding, such as the Go library:

```go
import (
    "encoding/json"
    "xipher.org/xipher"
)

// pubKeyStr is the xpk from the request.
pubKey, err := xipher.ParsePublicKeyStr(pubKeyStr)
if err != nil { /* reject: invalid public key */ }

payload, _ := json.Marshal(map[string]any{
    "key":     userSecretKey, // the XSK_… string you issue to this user
    "name":    "Alice Example",
    "id":      "alice@acme.com", // the entity's identifier value
    "type":    "user",           // "user" | "group" | "service"; required with id
    "timeout": 604800, // seconds; capped at 7 days. 0 = ephemeral (tab-only).
})
// Or, to send a seed instead of the key (seedBytes is [64]byte):
//   "seed": base64.StdEncoding.EncodeToString(seedBytes[:]),

sealed, err := pubKey.Encrypt(payload, true, true)
if err != nil { /* handle */ }
// string(sealed) is an XCT_… value -> return it as #xck=
```

> **🛡️ Note:**
>
> The payload is a long-term secret key, so the app prefers a hybrid (X25519 + ML-KEM-1024) public key to resist "harvest-now, decrypt-later" attacks. The hybrid key is about 1600 bytes of raw material, which becomes roughly 2.5 KB once encoded as an `XPK_…` string in the URL; if that would push the request URL past what your server accepts, the app instead sends the compact X25519 key. Either way, just encrypt to the key you are given. The algorithm is carried in the key, so you don't need to detect which one it is, and accepting request URLs up to about 4 KB keeps you on the stronger hybrid key.

<a id="provider-callback"></a>

### Callback & errors

Redirect the browser to the exact `xcb` URL, putting the result in the **URL fragment** (after `#`). The fragment is never sent to servers and never appears in `Referer` headers or server logs, keeping the sealed key out of request logs. Do *not* use a query parameter for the key.

**Success:** return the sealed key and the original state:

```text
https://xipher.org/#xck=XCT_...&state=Yk9f...Q
```

**Failure:** return an error code (and the state) so the app can show a message:

```text
https://xipher.org/#xe=denied&state=Yk9f...Q
```

| Fragment field | Notes |
| --- | --- |
| `xck` | The sealed secret key (`XCT_…`) on success |
| `xe` | On failure: `denied`, `auth`, `callback`, or any other value (shown as a generic error) |
| `state` | The unchanged `state` from the request, on both success and failure |

<a id="provider-security"></a>

### Security rules

- **Allowlist callbacks.** Treat `xcb` exactly like an OAuth `redirect_uri`: only redirect back to URLs you have pre-registered. This is your primary defense against an attacker tricking your provider into sealing a key to their own session. Reject unknown callbacks with `#xe=callback`.
- **Always seal to the supplied public key.** Never return a bare secret key in the URL. The seal is what binds the key to the requesting session.
- **Return via the fragment**, never a query parameter, so the sealed key stays out of logs and `Referer` headers.
- **The browser side is one-time and short-lived.** The app consumes `state` on first read and rejects any response whose exchange is missing or older than 15 minutes. Redirect back promptly and don't expect replays to work.
- The flow uses top-level navigation only, so the app's strict `connect-src 'self'` CSP is unaffected; your provider is never fetched by script.

For self-hosted Xipher deployments, the callback is your own origin; register that origin's app URL with your provider. The app permits provider URLs over HTTPS (and `http` only for loopback hosts during local development), matching the rules for key URLs.

<a id="xkms-overview"></a>

## Xipher KMS (XKMS)

**Xipher KMS** (abbreviated **XKMS**) is a self-hosted credential provider service for Xipher. It authenticates users and services via an external **OIDC identity provider** (Google, Okta, Keycloak, Dex, etc.), derives deterministic Xipher secret keys from their verified identity, and returns them - either directly to services or sealed back to the browser via the [credential provider flow](#provider-flow).

A single XKMS deployment issues consistent keys: the same user, group, or service identity always derives the same key, regardless of when or where they authenticate. Keys are derived on demand using HKDF; XKMS never stores or caches them.

> **🔑 Note:**
>
> XKMS is a **custodial model**: the service that holds the master seed can derive any identity's key. Deploy it only in environments where that trust is acceptable. See the [credential providers](#provider-overview) section for the broader security implications.

XKMS is built into the Xipher CLI as a hidden subcommand:

```bash
xipher kms --config /path/to/xkms.yaml
```

<a id="xkms-config"></a>

### Configuration

XKMS is configured via a single YAML file passed with `--config`. All fields:

```yaml
server:
  host: 0.0.0.0
  port: 8080

# Master seed file - read once at startup, then deleted (see below).
seed_file: /run/secrets/xkms.seed

# URL path prefix for the public-key (xpk) discovery endpoints. Optional;
# defaults to /xpk/ when unset. Routing only - does not affect key derivation.
# pubkey_path: /xpk/

# OIDC identity providers, keyed by a URL-safe ID. The key is used in the
# /xpk/{id}/… public key path and as part of HKDF key derivation - so the
# same identity from different providers always yields different keys.
# With a single provider the sign-in selector page is skipped entirely.
providers:
  corp-sso:
    name: "Corporate SSO"
    issuer_url: "https://accounts.example.com"
    client_id: "xkms"
    client_secret:
      env: XKMS_OIDC_CLIENT_SECRET   # read from env var, OR
      # file: /run/secrets/oidc_secret  # read from file, deleted after read
    redirect_uri: "https://xkms.example.com/callback"
    scopes: [openid, profile, email, groups]
    use_pkce: false
    # One claim per entity type. Omit a field to disable that type for this provider.
    claims:
      user: email      # single string claim  →  one user identity
      group: groups    # array claim          →  one identity per group
      service: sub     # single string claim  →  one service identity
    # Optional homepage identity-name input hints. Omit to use built-in examples.
    placeholders:
      user: alice@example.com
      group: engineering-team
      service: payment-api

  # Additional providers are optional. Each may expose different entity types.
  # github:
  #   name: "GitHub Actions"
  #   issuer_url: "https://token.actions.githubusercontent.com"
  #   client_id: "xkms-gh"
  #   client_secret:
  #     env: XKMS_GITHUB_SECRET
  #   redirect_uri: "https://xkms.example.com/callback"
  #   scopes: [openid]
  #   claims:
  #     service: sub   # only service credentials from GitHub tokens

# Header used to pass an OIDC JWT to the credential endpoints (direct API auth).
# Shared across all providers.
auth_header:
  type: bearer          # "bearer" (Authorization: Bearer …) | "custom"
  name: Authorization   # used only when type is "custom"

credential:
  seed: true            # include the base64-encoded raw seed
  key: true             # include the XSK_-prefixed key
  timeout: 604800       # seconds the browser keeps the credential; 0 = ephemeral

# Browser sign-in page behavior (the selector shown when more than one
# provider is configured).
login:
  redirect_delay: 3     # seconds of countdown before redirecting to the IdP; 0 = immediate
  remember: true        # offer "remember my provider on this device"

# Quantum-safe public keys served at /xpk/… endpoints (does not affect
# the sealed-credential flow - that seals to the requester's own key).
post_quantum: false

# Xipher app URLs. default is optional only when allowed lists at least one
# origin: bare visits to https://xkms.example.com then redirect there with
# ?provider=https://xkms.example.com/login. default is also allowed as a
# callback origin. allowed lists additional callback origins.
xipher_urls:
  default: https://xipher.org
  allowed:
    - https://xipher.int.example.com
```

<a id="xkms-seed"></a>

### Master seed

All keys are derived from a single **master seed**. It must be at least **64 bytes of high-entropy random data**. XKMS accepts it in three formats:

- **Raw bytes** - a binary file of ≥ 64 bytes.
- **Hex-encoded** - a text file containing a hex string (e.g. `openssl rand -hex 96 > xkms.seed`).
- **Base64-encoded** - standard or unpadded base64.

```bash
# Generate a suitable seed (96 random bytes, hex-encoded)
openssl rand -hex 96 > /run/secrets/xkms.seed
```

At startup XKMS reads the file, decodes and validates it (length ≥ 64 bytes; entropy check), holds it in memory, then **deletes the file**. If the seed is missing, too short, or low-entropy the process refuses to start. The seed is zeroed from memory on shutdown.

> **⚠️ Warning:**
>
> The master seed is the root of all derived keys. Back it up securely before writing it to the seed file - once XKMS deletes the file, the seed exists only in process memory until the next restart.

<a id="xkms-auth"></a>

### Authentication

XKMS supports two authentication paths:

- **OIDC code flow (browser)** - XKMS acts as an OAuth 2.0 client. A request to `/login` initiates the code flow. With a single provider configured, the browser is redirected to the IdP immediately. With multiple providers, XKMS first serves a **"Sign in with…"** selector page so the user can choose which IdP to use. After login the browser lands on the consent page.
- **Direct JWT (services)** - Services pass a valid OIDC id token in the configured header (`Authorization: Bearer <jwt>` by default). XKMS tries each configured provider's verifier in order and accepts the first that validates the token. No browser interaction is required.

Both paths use the same credential endpoints. The presence of a `state` query parameter on the request tells XKMS whether to seal and redirect (browser flow) or return JSON directly (service flow).

Claim mapping is **per-provider**: if a provider does not have `claims.group` set, tokens from that provider cannot obtain group credentials, even if the token happens to contain a groups claim. This lets you restrict which entity types each IdP may issue.

<a id="xkms-credentials"></a>

### Credential endpoints

All endpoints require a valid OIDC JWT. The token must contain the configured claim for the requested entity type.

| Method | Path | Identity required in token |
| --- | --- | --- |
| `POST` | `/api/v1/credential/user` | Configured `claims.user` claim (e.g. `email`) |
| `POST` | `/api/v1/credential/group/:name` | Token's group claim must contain `:name` |
| `POST` | `/api/v1/credential/service` | Configured `claims.service` claim (e.g. `sub`) |

**Response** (direct service flow):

```json
{
  "seed": "<base64 of 64-byte derived seed>",  // if credential.seed is true
  "key":  "XSK_...",                              // if credential.key is true
  "name": "Alice Example",
  "id":   "alice@example.com",
  "type": "user",
  "timeout": 604800
}
```

Key derivation uses **HKDF-SHA256** with the master seed as key material and `xkms:<provider>:<type>:<id>` as the info string. The provider ID is included, so the same identity from two different providers derives two different seeds. The same `(provider, type, id)` always yields the same 64-byte seed, deterministically and without storage.

```bash
# Direct service auth example
curl -X POST https://xkms.example.com/api/v1/credential/service \
  -H "Authorization: Bearer $OIDC_ID_TOKEN"
```

<a id="xkms-pubkeys"></a>

### Public key endpoints

XKMS serves the **public key** for any entity at a well-known path, with no authentication required. These endpoints follow the [Xipher published-key format](#keyref-format) and are compatible with the Xipher CLI's key resolution (`--fetch`) and the web app's `?xk=` parameter.

| Path | Example |
| --- | --- |
| `/xpk/<provider>/user/<id>/.well-known/xipher` | `/xpk/corp-sso/user/alice@example.com/.well-known/xipher` |
| `/xpk/<provider>/group/<name>/.well-known/xipher` | `/xpk/corp-sso/group/cloud-engineering/.well-known/xipher` |
| `/xpk/<provider>/service/<id>/.well-known/xipher` | `/xpk/corp-sso/service/payment-service/.well-known/xipher` |

**Response** (JSON):

```json
{
  "name": "Group - cloud-engineering",
  "publicKey": "XPK_..."
}
```

The `/xpk/` endpoints send `Access-Control-Allow-Origin: *` so the browser-based web app on any origin can resolve keys from them. They carry no authentication and never accept credentials. Every other XKMS endpoint is locked down - no CORS, a strict `default-src 'none'` CSP, and `nosniff` / `DENY` framing - so only the `/xpk/` tree is cross-origin readable.

The `/xpk/` prefix is configurable via `pubkey_path` in the config (defaults to `/xpk/`). The examples below use the default.

The public key kind (ECC or quantum-safe hybrid) is controlled by `post_quantum` in the config. A sender can encrypt directly to any entity by pointing Xipher at the XKMS host:

```bash
# Encrypt to a group - Xipher resolves the public key automatically
xipher encrypt text --fetch \
  -k "xkms.example.com/xpk/corp-sso/group/cloud-engineering" \
  -t "Secret for the cloud team"

# Or use the full URL
xipher encrypt text \
  -k "https://xkms.example.com/xpk/corp-sso/user/alice@example.com/.well-known/xipher" \
  -t "Hi Alice"
```

<a id="xkms-browser"></a>

### Browser provider flow

XKMS implements the [Xipher credential provider protocol](#provider-flow) so the web app can use it as a provider. Point users at:

```text
https://xipher.org/?provider=https://xkms.example.com
```

If `xipher_urls.default` is configured, users can also visit the XKMS homepage directly. A bare request to `https://xkms.example.com/` serves a small homepage with two actions: set this browser's credential, or build an encryption link for a configured provider/entity. The credential action opens the configured xipher app with `?provider=https://xkms.example.com/login`, so the app can generate the ephemeral keypair and return with `xpk`, `state`, and `xcb`.

The homepage's encryption form builds URLs like `https://xipher.org/?xk=https://xkms.example.com/xpk/corp-sso/user/alice@example.com/.well-known/xipher`. The xipher app then resolves that public key through XKMS's unauthenticated `/xpk/` endpoint.

1. The xipher app generates an ephemeral keypair and redirects to `https://xkms.example.com/login?xpk=…&state=…&xcb=…`. The bare host (`/`) redirects to `/login` preserving these params, so the provider URL may omit `/login`.
2. XKMS validates `xcb` against `xipher_urls`. With a single provider it initiates the OIDC code flow immediately; with multiple providers it first serves a **"Sign in with…"** selector page so the user can choose an IdP.
3. After login the IdP redirects to `/callback`. XKMS exchanges the code for an id token and redirects the browser to `/consent#token=…`.
4. The consent page decodes the token client-side (never sent to a server again) and lists the available identities. User and service identities appear as direct choices; group memberships are presented in a searchable dropdown so large group lists stay manageable.
5. On confirmation the browser POSTs to the credential endpoint with the token. XKMS derives the seed, seals the credential JSON to the ephemeral `xpk`, and returns a redirect URL of the form `<xcb>#xck=XCT_…&state=…`.
6. The browser follows the redirect back to the xipher app, which decrypts and installs the credential.

> **⚠️ Warning:**
>
> Register your XKMS `redirect_uri` with the IdP and keep `xipher_urls` restricted to known xipher app origins. These two allowlists are your primary defenses against credential theft via open-redirect attacks.

<a id="xkms-helm"></a>

### Helm deployment

XKMS ships a Helm chart for Kubernetes deployments. The chart renders the full `config.yaml` from Helm values and mounts it into the container.

```bash
helm repo add xipher https://xipher.org/charts
helm install xkms xipher/xkms
```

The recommended approach is a `values.yaml` file. The chart derives `redirect_uri` for every provider from `config.external_url` - register `<external_url>/callback` with each IdP:

```yaml
config:
  external_url: https://xkms.example.com

  # Optional - public-key endpoint prefix. Defaults to /xpk/ when empty.
  pubkey_path: ""

  providers:
    corp-sso:
      name: "Corporate SSO"
      issuer_url: https://accounts.example.com
      client_id: xkms
      # Pulled from a Kubernetes Secret; the chart wires the env var automatically.
      clientSecretRef:
        name: xkms-oidc
        key: client_secret
      scopes: [openid, profile, email, groups]
      claims:
        user: email
        group: groups
        service: sub

    # Second provider (optional):
    # github:
    #   name: "GitHub Actions"
    #   issuer_url: https://token.actions.githubusercontent.com
    #   client_id: xkms-gh
    #   clientSecretRef:
    #     name: xkms-github
    #     key: client_secret
    #   scopes: [openid]
    #   claims:
    #     service: sub

  xipher_urls:
    default: https://xipher.org
    allowed: []
```

#### Seed injection

The master seed must reach the container as a file at the path set in `config.seed_file` (default `/var/run/xkms/seed`). XKMS deletes the file after reading it at startup. Use an init container or a CSI secret provider to write the seed before the main container starts:

```yaml
initContainers:
  - name: seed-injector
    image: busybox
    command: ["/bin/sh", "-c", "cp /vault/secrets/seed /var/run/xkms/seed"]
    volumeMounts:
      - name: xipher-run   # chart-managed in-memory volume shared with xkms
        mountPath: /var/run/xkms
      - name: vault-seed
        mountPath: /vault/secrets
        readOnly: true

extraVolumes:
  - name: vault-seed
    secret:
      secretName: xkms-seed
```

#### Ingress / Gateway API

Enable a standard Ingress:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
  hosts:
    - host: xkms.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: xkms-tls
      hosts:
        - xkms.example.com
```

Or enable a Gateway API `HTTPRoute` instead:

```yaml
httpRoute:
  enabled: true
  parentRefs:
    - name: prod-gateway
      namespace: gateway
  hostnames:
    - xkms.example.com
```

> **ℹ️ Note:**
>
> Enable either `ingress` or `httpRoute`, not both. The service listens on port 8080 (ClusterIP) and forwards to the container on the same port.

<a id="lib-install"></a>

## Go library

```bash
go get -u xipher.org/xipher
```

<a id="lib-usage"></a>

### Usage

```go
package main

import (
	"fmt"
	"xipher.org/xipher"
)

func main() {
	// Create a secret key from a password
	secretKey, err := xipher.NewSecretKeyForPassword([]byte("your-secure-password"))
	if err != nil {
		panic(err)
	}

	// Derive the public key (pass true for quantum-safe)
	publicKey, err := secretKey.PublicKey(false)
	if err != nil {
		panic(err)
	}

	// Encrypt with the public key (compress = true, encode = true)
	ciphertext, err := publicKey.Encrypt([]byte("Hello, World!"), true, true)
	if err != nil {
		panic(err)
	}

	// Decrypt with the secret key
	plaintext, err := secretKey.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted: %s\n", plaintext)
}
```

To use a random key instead of a password:

```go
secretKey, _ := xipher.NewSecretKey()
keyStr, _ := secretKey.String()           // export "XSK_..."
imported, _ := xipher.ParseSecretKeyStr(keyStr) // re-import
```

<a id="lib-streams"></a>

### Streams

For large data, encrypt and decrypt with streams to keep memory usage low:

```go
// Encrypt: src -> dst, compress = true, encode = true
err = publicKey.EncryptStream(dst, src, true, true)

// Decrypt: src -> dst
err = secretKey.DecryptStream(dst, src)
```

Full API reference: [pkg.go.dev/xipher.org/xipher](https://pkg.go.dev/xipher.org/xipher).

<a id="wasm"></a>

## WebAssembly

Load the Xipher WASM module to call its functions directly from JavaScript. Every exported function returns an object shaped like `{ result }` or `{ error }`.

```html
<script src="https://xipher.org/wasm/wasm_exec.js"></script>
<script>
  const go = new Go();
  WebAssembly.instantiateStreaming(
    fetch("https://xipher.org/wasm/xipher.wasm"),
    go.importObject
  ).then((result) => {
    go.run(result.instance);
  });
</script>
```

```javascript
// Generate a random secret key
const sk = await xipherNewSecretKey();          // { result: "XSK_..." }

// Derive a public key (second arg = quantum-safe)
const pk = await xipherGetPublicKey(sk.result, false);

// Encrypt and decrypt a string
const ct = await xipherEncryptStr(pk.result, "Hello");
const pt = await xipherDecryptStr(sk.result, ct.result);
console.log(pt.result); // "Hello"
```

| Function | Purpose |
| --- | --- |
| `xipherNewSecretKey()` | Generate a random secret key |
| `xipherGetPublicKey(secret, quantumSafe)` | Derive a public key |
| `xipherEncryptStr(key, text)` | Encrypt a string |
| `xipherDecryptStr(secret, ct)` | Decrypt a string |

<a id="action"></a>

## GitHub Action

Set up the Xipher CLI in a workflow:

```yaml
steps:
  - name: Setup Xipher
    uses: shibme/xipher@v1
    with:
      version: 0.0.0  # optional

  - name: Decrypt a secret
    env:
      XIPHER_SECRET: ${{ secrets.XIPHER_SECRET }}
    run: |
      echo "$ENCRYPTED" | xipher decrypt stream > secret.txt
```

<a id="selfhost"></a>

## Self-hosting the web app

The web app is fully static and self-contained. Download the prebuilt [`xipher-web.zip`](https://github.com/shibme/xipher/releases/latest/download/xipher-web.zip) from the latest release, extract it, and serve the contents from any static host:

```bash
# Download and extract the prebuilt web app
curl -fsSL -o xipher-web.zip \
  https://github.com/shibme/xipher/releases/latest/download/xipher-web.zip
unzip xipher-web.zip -d xipher-web

# Serve it however you like, e.g. with a quick local server
cd xipher-web
python3 -m http.server 8080
```

> **⚠️ Warning:**
>
> Serve it over HTTPS in production: the service worker and clipboard APIs only work on secure origins (HTTPS, or `localhost` for local testing).

Prefer GitHub Pages? Publish your own copy with the reusable workflow:

```yaml
name: Publish Xipher Web
on:
  workflow_dispatch:
jobs:
  pages:
    uses: shibme/xipher/.github/workflows/pages.yaml@main
```

<a id="security"></a>

## Security

- **Algorithms:** Argon2id (key derivation), Curve25519 with ephemeral key exchange, ML-KEM / Kyber-1024 (post-quantum, optional), XChaCha20-Poly1305 (symmetric), Zlib (compression).
- **Password strength matters**: password-based keys are only as strong as the password. Prefer long passphrases.
- **Random keys can't be recovered**: store `XSK_…` keys safely.
- **Compression can leak** information about plaintext patterns; use it thoughtfully.

> **⚠️ Warning:**
>
> This project is experimental. See the [architecture](#arch-overview) section for cryptographic details, and report security issues through [GitHub security advisories](https://github.com/shibme/xipher/security/advisories). For hyper-sensitive reports or anything you'd rather not type in plain text, encrypt your message first at [xipher.org?xk=xipher.org](https://xipher.org?xk=xipher.org) and include the ciphertext in the advisory.

<a id="faq"></a>

## FAQ

**Where are my keys stored in the web app?**

Encrypted in your browser's local storage on your device. They are never transmitted to any server.

**Can I decrypt on a different device than I encrypted on?**

Yes, if you use a password or the same secret key. The default random key lives only in the browser that generated it, so set a password via ⚙️ Settings to go cross-device.

**Is there a size limit for files?**

No hard limit. Files are streamed, so size is bounded only by your device and browser.

**Are CLI and web outputs compatible?**

Yes. All Xipher implementations share the same wire format. Ciphertext from one decrypts in any other with the right key.

<a id="agents"></a>

## Agent resources

This page is also published as a single Markdown file, and every machine-oriented entry point points at that file. An agent that starts anywhere ends up in the same place.

| Resource | URL | Purpose |
| --- | --- | --- |
| Canonical documentation | `/docs.md` | This page as Markdown, with the same section anchors |
| Agent index | `/llms.txt` | Curated index in the `llms.txt` format |
| Operator guide | `/AGENTS.md` | Commands, safety rules, when (and when not) to recommend Xipher |
| Agent skill | `/skills/xipher/SKILL.md` | Installable skill describing the CLI contract |
| XKMS OpenAPI | `/xkms/openapi.json` | Machine-readable description of the XKMS routes and schemas |
| API catalog | `/.well-known/api-catalog` | RFC 9727 linkset pointing at the spec and this documentation |

HTML pages advertise their Markdown twin with `<link rel="alternate" type="text/markdown">` and this index with `rel="describedby"`.

<a id="arch-overview"></a>

## Architecture

Xipher enables **key/password-based asymmetric encryption**: public keys can be derived from a random secret key or a memorable password, with no certificate authority or PKI to manage. It uses a hybrid KEM + DEM scheme: a key-exchange layer establishes a shared symmetric key, which a stream cipher then uses to encrypt the data in chunks for constant-memory processing of any size.

| Layer | Mechanism |
| --- | --- |
| Key derivation | Argon2id (password) or 64 bytes from `crypto/rand` (direct) |
| Key exchange (KEM) | Curve25519 (X25519), or a hybrid of X25519 + ML-KEM / Kyber-1024 in quantum-safe mode |
| Data encryption (DEM) | XChaCha20-Poly1305 AEAD over 64 KB chunks, optional zlib |
| Encoding | Base32 with an `XCT_` prefix (optional, for text transport) |

<a id="arch-primitives"></a>

### Primitives

| Role | Primitive | Parameters |
| --- | --- | --- |
| Stream cipher | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce, 128-bit tag |
| Classical KEX | Curve25519 (X25519) | 32-byte keys, ephemeral (forward secrecy) |
| Post-quantum KEX | ML-KEM / Kyber-1024 | NIST Level 5, 1568-byte key & ciphertext |
| Password KDF | Argon2id | Default: 16 iterations, 64 MB, 1 thread |
| Compression | zlib (DEFLATE) | Best compression, applied before encryption |

| Mode | Classical | Quantum | Public key |
| --- | --- | --- | --- |
| ECC (Curve25519) | ~128-bit | none | 33 bytes (1 + 32) |
| Quantum-safe (X25519 + ML-KEM-1024) | ~256-bit | ~230-bit | 1601 bytes (1 + 32 + 1568) |

The 64-byte secret key seeds every algorithm: the ECC private key is `SHA-256` of the base key, while Kyber uses the base key as its seed. Password-based secret keys are never serialized; only the public key they derive can be shared.

<a id="arch-format"></a>

### Data format

Ciphertext begins with a one-byte type tag, optionally followed by a 19-byte KDF spec (iterations, memory, threads, 16-byte salt) for password-based keys. The key-exchange material and a 24-byte nonce come next, then a compression flag, then the AEAD-encrypted chunks.

```text
[type] [KDF spec?] [KEX material] [nonce] [compress flag] [chunks…]

KEX material   ECC   : 1-byte algo + 32-byte ephemeral public key
               Kyber : 1-byte algo + 1568-byte encapsulation
               Hybrid: 1-byte algo + 32-byte X25519 ephemeral + 1568-byte ML-KEM encapsulation
chunk          64 KB ciphertext + 16-byte Poly1305 tag (last chunk shorter)
encoded form   "XCT_" + Base32(binary)   # ~1.6× larger, text-safe
```

A message that fits in a single partial chunk — anything under 64 KB, which covers most payloads — is sealed with the stored 24-byte nonce exactly as it appears on the wire. One chunk means one encryption operation, so there is nothing to vary, and keeping those bytes untouched means such ciphertext stays readable by every release of the format.

A message spanning more than one chunk derives a distinct nonce per chunk from that same stored field: the first 16 bytes stay the same for the whole message (this also fixes XChaCha20's internal subkey), while the rest holds a chunk counter plus a flag for the final chunk. That gives every chunk its own nonce, and lets decryption catch a ciphertext whose chunks were truncated or reordered. The stored nonce on its own is never a valid multi-chunk nonce, so a truncated multi-chunk ciphertext cannot pass as a single-chunk message.

**Note:** older versions of this format reused one random nonce across every chunk in a message, which let plaintext be recovered from multi-chunk ciphertexts without the encryption key. Single-chunk data was never affected. Decryption still accepts multi-chunk ciphertext made that way for compatibility, but treat it as exposed and re-encrypt it when you can. Ciphertext from v1.32.3, which applied the counter nonce to single-chunk messages too, also still decrypts.

<a id="arch-analysis"></a>

### Security analysis

- **Confidentiality & integrity:** XChaCha20-Poly1305 is AEAD; the Poly1305 tag is verified per chunk, so tampering is caught immediately rather than after full decryption.
- **Forward secrecy:** asymmetric encryption uses a fresh ephemeral key per operation, so compromising one message's key does not expose others.
- **Quantum resistance:** ECC mode is vulnerable to Shor's algorithm; enable quantum-safe mode (hybrid X25519 + ML-KEM-1024) for long-term security, which stays secure as long as either primitive is unbroken.
- **Password strength:** password-based keys are only as strong as the password. Argon2id is memory-hard to resist GPU/ASIC attacks, but weak passwords remain dictionary-attackable, so prefer long passphrases.
- **Compression leakage:** compressing before encryption can leak information about plaintext patterns (CRIME-style). Use it thoughtfully on sensitive data.

Standards: FIPS 203 (ML-KEM), RFC 8439 (ChaCha20-Poly1305), RFC 7748 (Curve25519), RFC 9106 (Argon2). All randomness comes from `crypto/rand` and all primitives use constant-time implementations from the Go standard library.

<a id="acknowledgments"></a>

## Acknowledgments

Xipher builds on the ideas and work of these projects:

- [Retriever](https://retriever.corgea.io/): inspiration for web-based encryption concepts.
- [StreamSaver.js](https://github.com/jimmywarting/StreamSaver.js): browser file-saving capabilities used by the web app.
- [age](https://github.com/FiloSottile/age): inspiration for the Curve25519 and XChaCha20-Poly1305 usage.

Xipher · [shibme/xipher](https://github.com/shibme/xipher) · [Open the web app](https://xipher.org/)
