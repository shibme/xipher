# Xipher Cryptographic Architecture White Paper

## Abstract

Xipher is a cryptographic system that provides password-based and key-based asymmetric encryption with post-quantum cryptography support. It combines multiple cryptographic primitives into a cohesive architecture that enables secure data sharing over insecure channels. The system features a multi-layer stream cipher based on XChaCha20-Poly1305, supports both classical (ECC) and post-quantum (Kyber1024) key exchange mechanisms, and implements Argon2 for password-based key derivation.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Stream Cipher Implementation (XCP)](#4-stream-cipher-implementation-xcp)
5. [Key Derivation](#5-key-derivation)
6. [Asymmetric Encryption](#6-asymmetric-encryption)
7. [Data Format and Bit Arrangement](#7-data-format-and-bit-arrangement)
8. [Encryption Flow](#8-encryption-flow)
9. [Decryption Flow](#9-decryption-flow)
10. [Security Analysis](#10-security-analysis)
11. [Performance Considerations](#11-performance-considerations)
12. [References](#12-references)

---

## 1. Introduction

### 1.1 Motivation

Modern cryptographic systems often require users to choose between:
- Simple password-based symmetric encryption (convenient but limited to single-party use)
- Complex public-key infrastructure (powerful but challenging to manage)

Xipher bridges this gap by enabling **password-based asymmetric encryption**, where:
- Public keys can be derived from memorable passwords
- No certificate authorities or PKI infrastructure required
- Post-quantum cryptography is available as an option
- Stream processing enables encryption of arbitrarily large data

### 1.2 Design Goals

1. **Simplicity**: Users can encrypt data using just a password-derived public key
2. **Security**: Multi-layer defense using established cryptographic primitives
3. **Future-proof**: Post-quantum cryptography support via Kyber1024
4. **Efficiency**: Stream-based processing for memory-efficient large file handling
5. **Flexibility**: Support for both password-based and random key-based operations

---

## 2. System Architecture

### 2.1 Layered Architecture

Xipher implements a four-layer cryptographic architecture:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Application Layer                                  │
│ - Base32 encoding (optional)                                │
│ - XCT_ prefix for ciphertext identification                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Key Exchange Layer                                 │
│ - ECC (Curve25519) for classical security                   │
│ - Kyber1024 (ML-KEM) for post-quantum security              │
│ - Establishes shared symmetric key                          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Symmetric Encryption Layer (XCP)                   │
│ - XChaCha20-Poly1305 AEAD cipher                            │
│ - 64KB block streaming                                      │
│ - Optional zlib compression                                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Key Derivation Layer                               │
│ - Argon2id for password-based keys                          │
│ - Cryptographically secure random for direct keys           │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Component Hierarchy

```
xipher (top-level API)
├── SecretKey (64 bytes)
│   ├── Direct key (random)
│   └── Password-based (via Argon2)
│
├── PublicKey
│   ├── ECC (Curve25519) - 32 bytes
│   └── Kyber1024 - 1568 bytes
│
└── Ciphertext Format
    ├── Header (algorithm, compression, KDF params)
    ├── Key encapsulation (ephemeral key/ciphertext)
    └── Encrypted data (chunked AEAD stream)

Internal Crypto Modules:
├── asx (Asymmetric eXchange)
│   ├── ecc (Elliptic Curve Cryptography)
│   └── kyb (Kyber post-quantum)
│
└── xcp (XChaCha20-Poly1305)
    └── Stream cipher with chunking
```

---

## 3. Cryptographic Primitives

### 3.1 Primitive Selection

| Component | Primitive | Parameters | Rationale |
|-----------|-----------|------------|-----------|
| **Stream Cipher** | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce | Authenticated encryption, large nonce space, proven security |
| **Classical KEX** | Curve25519 (X25519) | 256-bit keys | Fast, constant-time, widely deployed |
| **Post-Quantum KEX** | Kyber1024 (ML-KEM) | NIST Level 5 | NIST-standardized, quantum-resistant |
| **KDF** | Argon2id | Configurable (default: 16 iter, 64MB, 1 thread) | Memory-hard, GPU-resistant, recommended by OWASP |
| **Hashing** | SHA-256 | 256-bit output | Key derivation for ECC from base key |
| **Compression** | zlib | Best compression | Optional size reduction |
| **Encoding** | Base32 | No padding | Human-readable, URL-safe |

### 3.2 Security Levels

| Variant | Classical Security | Quantum Security | Public Key Size | Ciphertext Overhead |
|---------|-------------------|------------------|----------------|---------------------|
| **ECC Mode** | ~128 bits | ~0 bits | 32 bytes | ~32 bytes |
| **Kyber1024 Mode** | ~256 bits | ~230 bits | 1568 bytes | ~1568 bytes |

---

## 4. Stream Cipher Implementation (XCP)

### 4.1 XChaCha20-Poly1305 Overview

XCP (XChaCha20-Poly1305) is the core symmetric encryption layer. It provides:

- **Confidentiality**: XChaCha20 stream cipher
- **Authenticity**: Poly1305 MAC
- **AEAD**: Authenticated Encryption with Associated Data

**Parameters:**
- **Key size**: 32 bytes (256 bits)
- **Nonce size**: 24 bytes (192 bits) - XChaCha20 extended nonce
- **Tag size**: 16 bytes (128 bits) - Poly1305 MAC
- **Block size**: 64 KB plaintext → 64 KB + 16 bytes ciphertext

### 4.2 Streaming Architecture

To enable encryption of arbitrarily large files, XCP implements a **chunked streaming** model:

```
Plaintext Stream → [Compression?] → Chunking → AEAD Encryption → Ciphertext Stream
```

#### 4.2.1 Chunk-Based Processing

**Plaintext Block Size**: 64 KB (65,536 bytes)

```go
const ptBlockSize = 64 * 1024  // 65536 bytes
```

**Ciphertext Block Size**: 64 KB + 16 bytes (Poly1305 tag)

```go
const ctBlockSize = ptBlockSize + chacha20poly1305.Overhead  // 65552 bytes
```

Each plaintext block is independently encrypted with the AEAD cipher, producing:
- 64 KB of encrypted data
- 16-byte authentication tag

**Critical Security Property**: While blocks are processed independently, they **all use the same nonce**. This is safe because:
1. XChaCha20-Poly1305 is designed for single-use nonces per key
2. Each encryption session generates a fresh random nonce
3. The nonce is never reused with the same key
4. The 192-bit nonce space makes collisions computationally infeasible

### 4.3 Bit-Level Data Layout

#### 4.3.1 Ciphertext Structure (Symmetric Mode)

```
┌──────────────────────────────────────────────────────────────────┐
│ Byte Range       │ Field                 │ Size                  │
├──────────────────────────────────────────────────────────────────┤
│ 0-0              │ Cipher Type           │ 1 byte                │
│                  │   0x00: ctKeySymmetric                        │
│                  │   0x02: ctPwdSymmetric                        │
├──────────────────────────────────────────────────────────────────┤
│ 1-19 (optional)  │ KDF Spec              │ 19 bytes              │
│                  │   [0]: iterations                             │
│                  │   [1]: memory (MB)                            │
│                  │   [2]: threads                                │
│                  │   [3-18]: salt (16 bytes)                     │
├──────────────────────────────────────────────────────────────────┤
│ N+0 to N+23      │ Nonce                 │ 24 bytes              │
├──────────────────────────────────────────────────────────────────┤
│ N+24             │ Compression Flag      │ 1 byte                │
│                  │   0x00: No compression                        │
│                  │   0x01: zlib compression                      │
├──────────────────────────────────────────────────────────────────┤
│ N+25 onwards     │ Encrypted Blocks      │ Variable              │
│                  │   [Block 0: 64KB + 16B tag]                   │
│                  │   [Block 1: 64KB + 16B tag]                   │
│                  │   ...                                         │
│                  │   [Block N: M bytes + 16B tag]                │
└──────────────────────────────────────────────────────────────────┘

Where N = 1 (key-based) or 20 (password-based)
```

#### 4.3.2 Nonce Generation

```go
nonce := make([]byte, nonceLength)  // nonceLength = 24
rand.Read(nonce)
```

The 24-byte (192-bit) nonce is generated using `crypto/rand`, providing:
- Uniform random distribution
- Cryptographically secure randomness
- Collision probability: ~2^-192 (negligible)

**Nonce Layout** (bit-level):
```
Bits 0-191: Random bytes from crypto/rand
```

The nonce is written once at the beginning of the ciphertext and **reused for all blocks in the stream**. This is cryptographically safe because:
1. Each encryption operation uses a unique random nonce
2. The key is either freshly derived (password-based) or ephemeral (asymmetric)
3. XChaCha20 is designed to tolerate nonce reuse within a single message

### 4.4 Encryption Process (Bit-by-Bit)

For each 64 KB plaintext block:

1. **Input**: 
   - `plaintext[0:65536]` - 524,288 bits
   - `nonce[0:24]` - 192 bits
   - `key[0:32]` - 256 bits

2. **XChaCha20-Poly1305 AEAD Encryption**:
   ```
   ciphertext = AEAD.Seal(nil, nonce, plaintext_block, nil)
   ```
   
   This produces:
   - `encrypted_data[0:65536]` - 524,288 bits (same size as plaintext)
   - `poly1305_tag[0:16]` - 128 bits

3. **Output**:
   - Total: 65,552 bytes (524,416 bits)
   - Layout: `[encrypted_data][poly1305_tag]`

### 4.5 Compression Integration

When compression is enabled:

```
┌────────────┐     ┌──────────┐     ┌──────────┐     ┌────────────┐
│  Plaintext │ --> │   zlib   │ --> │ Chunking │ --> │ XChaCha20  │
│   Stream   │     │ Compress │     │ (64KB)   │     │  -Poly1305 │
└────────────┘     └──────────┘     └──────────┘     └────────────┘
```

**Compression Parameters**:
- Algorithm: zlib (DEFLATE)
- Level: Best compression (`zlib.BestCompression = 9`)
- Applied **before** encryption

**Security Note**: Compression before encryption can leak information about plaintext patterns. Use with caution on sensitive data.

### 4.6 Writer Implementation

The `Writer` structure manages streaming encryption:

```go
type Writer struct {
    aead    cipher.AEAD          // XChaCha20-Poly1305 cipher
    dst     io.Writer            // Output destination
    buf     bytes.Buffer         // Accumulation buffer
    nonce   []byte               // 24-byte nonce (reused per session)
    zWriter *zlib.Writer         // Optional compressor
}
```

**Write Algorithm**:

```
function Write(plaintext_chunk):
    if compression_enabled:
        zWriter.Write(plaintext_chunk) → buf
    else:
        buf.Write(plaintext_chunk)
    
    while buf.Len() >= 64KB:
        block = buf.Next(64KB)
        ciphertext = AEAD.Seal(nil, nonce, block, nil)
        dst.Write(ciphertext)
    
    return len(plaintext_chunk)
```

**Close Algorithm**:

```
function Close():
    if compression_enabled:
        zWriter.Close()  // Flush compression buffer
    
    // Encrypt remaining data (< 64KB)
    if buf.Len() > 0:
        block = buf.Bytes()
        ciphertext = AEAD.Seal(nil, nonce, block, nil)
        dst.Write(ciphertext)
```

### 4.7 Reader Implementation

The `Reader` structure manages streaming decryption:

```go
type Reader struct {
    aead  cipher.AEAD     // XChaCha20-Poly1305 cipher
    src   io.Reader       // Input source
    buf   bytes.Buffer    // Decrypted data buffer
    nonce []byte          // 24-byte nonce
}
```

**Read Algorithm**:

```
function Read(output_buffer):
    if buf.Len() > len(output_buffer):
        return buf.Read(output_buffer)
    
    // Read next ciphertext block (64KB + 16 bytes)
    ct_block = ReadFull(src, 65552)
    
    // Decrypt and verify
    plaintext = AEAD.Open(nil, nonce, ct_block, nil)
    
    buf.Write(plaintext)
    return buf.Read(output_buffer)
```

---

## 5. Key Derivation

### 5.1 Secret Key Structure

**Direct Keys** (Random):
```
┌──────────────────────────────────────────────────────────────┐
│ Component             │ Size        │ Source                 │
├──────────────────────────────────────────────────────────────┤
│ Version               │ 1 byte      │ Always 0x00            │
│ Key Type              │ 1 byte      │ 0x00 (direct)          │
│ Key Material          │ 64 bytes    │ crypto/rand            │
└──────────────────────────────────────────────────────────────┘
Total: 66 bytes
String format: XSK_[base32-encoded 66 bytes]
```

**Password-Based Keys**:
```
┌──────────────────────────────────────────────────────────────┐
│ Component             │ Size        │ Source                 │
├──────────────────────────────────────────────────────────────┤
│ Version               │ 1 byte      │ Always 0x00            │
│ Key Type              │ 1 byte      │ 0x01 (password)        │
│ Password              │ Variable    │ User input             │
│ KDF Spec              │ 19 bytes    │ Generated              │
│ Derived Key           │ 64 bytes    │ Argon2(password, spec) │
└──────────────────────────────────────────────────────────────┘

Note: Password-based keys cannot be serialized (security measure)
```

### 5.2 Argon2id Key Derivation

**Algorithm**: Argon2id (hybrid of Argon2i and Argon2d)

**KDF Specification Structure** (19 bytes):

```
┌──────────────────────────────────────────────────────────────┐
│ Byte  │ Field         │ Default  │ Range     │ Description   │
├──────────────────────────────────────────────────────────────┤
│ 0     │ Iterations    │ 16       │ 1-255     │ Time cost     │
│ 1     │ Memory (MB)   │ 64       │ 1-255     │ Memory cost   │
│ 2     │ Threads       │ 1        │ 1-255     │ Parallelism   │
│ 3-18  │ Salt          │ Random   │ 16 bytes  │ Unique salt   │
└──────────────────────────────────────────────────────────────┘
```

**Key Derivation Process**:

```go
salt := crypto_rand(16)  // 128-bit random salt

key := Argon2id(
    password,           // Variable-length password
    salt,              // 16-byte random salt
    iterations,        // Default: 16
    memory * 1024,     // Default: 64 MB
    threads,           // Default: 1
    64                 // Output length: 64 bytes
)
```

**Argon2id Internal Structure**:

1. **Memory blocks**: (memory_MB × 1024) KB
2. **Passes**: iterations
3. **Lanes**: threads
4. **Output**: 512 bits (64 bytes)

**Security Parameters**:

| Configuration | Iterations | Memory | Threads | Time (approx) | Security Level |
|---------------|-----------|--------|---------|---------------|----------------|
| **Default**   | 16        | 64 MB  | 1       | ~100-200 ms   | High |
| **High Security** | 32    | 128 MB | 4       | ~500-1000 ms  | Very High |
| **Low Resource** | 8      | 32 MB  | 1       | ~50 ms        | Medium |

### 5.3 Key Derivation for Cryptographic Algorithms

From the 64-byte base key, algorithm-specific keys are derived:

#### 5.3.1 ECC Key Derivation

```
ecc_private_key = SHA256(base_key[0:64])  // 32 bytes
```

The 32-byte ECC private key is used with Curve25519:

```
ecc_public_key = X25519(ecc_private_key, Base_Point)
```

#### 5.3.2 Kyber Key Derivation

```
kyber_seed = base_key[0:64]  // 64 bytes used directly

kyber_private_key = ML-KEM-1024.KeyGen(kyber_seed)
kyber_public_key = kyber_private_key.PublicKey()
```

#### 5.3.3 Symmetric Cipher Key Derivation

For symmetric encryption with a 64-byte secret key:

```
if len(key) == 64:
    symmetric_key = SHA256(key)  // 32 bytes for XChaCha20-Poly1305
else if len(key) == 32:
    symmetric_key = key  // Use directly
```

This allows both 64-byte (base) and 32-byte (derived/ephemeral) keys to work with the XCP cipher.

---

## 6. Asymmetric Encryption

### 6.1 Hybrid Encryption Model

Xipher uses **hybrid encryption** (KEM+DEM):

1. **KEM** (Key Encapsulation Mechanism): ECC or Kyber
   - Establishes a shared 32-byte symmetric key
   - Public key encrypts key material
   - Private key decrypts key material

2. **DEM** (Data Encapsulation Mechanism): XChaCha20-Poly1305
   - Encrypts actual data with shared key
   - Provides AEAD properties

### 6.2 ECC Mode (Curve25519)

**Asymmetric Ciphertext Structure**:

```
┌──────────────────────────────────────────────────────────────┐
│ Byte Range    │ Field                     │ Size             │
├──────────────────────────────────────────────────────────────┤
│ 0             │ Cipher Type               │ 1 byte           │
│               │   0x00: ctKeyAsymmetric                      │
│               │   0x01: ctPwdAsymmetric                      │
├──────────────────────────────────────────────────────────────┤
│ 1-19 (opt)    │ KDF Spec                  │ 19 bytes         │
│               │   (only for password-based)                  │
├──────────────────────────────────────────────────────────────┤
│ N             │ Algorithm Type            │ 1 byte           │
│               │   0x00: algoECC                              │
├──────────────────────────────────────────────────────────────┤
│ N+1 to N+32   │ Ephemeral Public Key      │ 32 bytes         │
├──────────────────────────────────────────────────────────────┤
│ N+33 to N+56  │ Nonce                     │ 24 bytes         │
├──────────────────────────────────────────────────────────────┤
│ N+57          │ Compression Flag          │ 1 byte           │
├──────────────────────────────────────────────────────────────┤
│ N+58 onwards  │ Encrypted Blocks          │ Variable         │
└──────────────────────────────────────────────────────────────┘

Where N = 1 (key-based) or 20 (password-based)
```

**Encryption Process**:

```
1. Generate ephemeral key pair:
   eph_private = crypto_rand(32)
   eph_public = X25519(eph_private, Base_Point)

2. Compute shared secret:
   shared_secret = X25519(eph_private, recipient_public_key)

3. Write ephemeral public key to ciphertext:
   output.Write(eph_public)  // 32 bytes

4. Encrypt data with XCP using shared_secret:
   xcp_cipher = XCP.New(shared_secret)
   xcp_cipher.EncryptStream(output, plaintext)
```

**Decryption Process**:

```
1. Read ephemeral public key:
   eph_public = input.Read(32)

2. Compute shared secret:
   shared_secret = X25519(recipient_private_key, eph_public)

3. Decrypt data with XCP:
   xcp_cipher = XCP.New(shared_secret)
   plaintext = xcp_cipher.DecryptStream(input)
```

**Security Properties**:
- **Forward Secrecy**: Each encryption uses a fresh ephemeral key
- **Computational Security**: Based on ECDLP hardness (~2^128 operations)
- **Quantum Vulnerability**: Shor's algorithm can break ECDLP

### 6.3 Post-Quantum Mode (Kyber1024)

**Asymmetric Ciphertext Structure**:

```
┌──────────────────────────────────────────────────────────────┐
│ Byte Range    │ Field                     │ Size             │
├──────────────────────────────────────────────────────────────┤
│ 0             │ Cipher Type               │ 1 byte           │
├──────────────────────────────────────────────────────────────┤
│ 1-19 (opt)    │ KDF Spec                  │ 19 bytes         │
├──────────────────────────────────────────────────────────────┤
│ N             │ Algorithm Type            │ 1 byte           │
│               │   0x01: algoKyber                            │
├──────────────────────────────────────────────────────────────┤
│ N+1 to N+1568 │ Kyber Ciphertext          │ 1568 bytes       │
├──────────────────────────────────────────────────────────────┤
│ N+1569 to...  │ Nonce                     │ 24 bytes         │
├──────────────────────────────────────────────────────────────┤
│ N+1593        │ Compression Flag          │ 1 byte           │
├──────────────────────────────────────────────────────────────┤
│ N+1594 onwards│ Encrypted Blocks          │ Variable         │
└──────────────────────────────────────────────────────────────┘
```

**Kyber1024 Parameters**:
- **Security Level**: NIST Level 5 (~256-bit classical, ~230-bit quantum)
- **Public Key**: 1568 bytes
- **Private Key**: 3168 bytes (internally managed)
- **Ciphertext**: 1568 bytes
- **Shared Secret**: 32 bytes

**Encryption Process**:

```
1. Kyber encapsulation:
   (shared_secret, kyber_ciphertext) = Kyber1024.Encapsulate(recipient_public_key)
   
   // shared_secret: 32 bytes
   // kyber_ciphertext: 1568 bytes

2. Write Kyber ciphertext:
   output.Write(kyber_ciphertext)  // 1568 bytes

3. Encrypt data with XCP:
   xcp_cipher = XCP.New(shared_secret)
   xcp_cipher.EncryptStream(output, plaintext)
```

**Decryption Process**:

```
1. Read Kyber ciphertext:
   kyber_ciphertext = input.Read(1568)

2. Kyber decapsulation:
   shared_secret = Kyber1024.Decapsulate(private_key, kyber_ciphertext)
   // shared_secret: 32 bytes

3. Decrypt data with XCP:
   xcp_cipher = XCP.New(shared_secret)
   plaintext = xcp_cipher.DecryptStream(input)
```

**Security Properties**:
- **Quantum Resistance**: Based on Module-LWE problem (hard for quantum computers)
- **Classical Security**: ~256-bit security level
- **Quantum Security**: ~230-bit security level
- **Standardization**: NIST FIPS 203 (ML-KEM)

### 6.4 Algorithm Selection

```
┌─────────────────────────────────────────────────────────────┐
│                    Algorithm Selection                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  secretKey.PublicKey(pq = false)  →  ECC Public Key         │
│                                       - 32 bytes            │
│                                       - Curve25519          │
│                                       - Fast                │
│                                       - Quantum vulnerable  │
│                                                             │
│  secretKey.PublicKey(pq = true)   →  Kyber Public Key       │
│                                       - 1568 bytes          │
│                                       - ML-KEM-1024         │
│                                       - Quantum-resistant   │
│                                       - NIST standardized   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Data Format and Bit Arrangement

### 7.1 Complete Ciphertext Format

#### 7.1.1 Symmetric Encryption (Password-Based)

**Total Structure**:

```
┌─────────────────────────────────────────────────────────────────────┐
│ Prefix (optional): "XCT_" (4 bytes, if encoded)                     │
├─────────────────────────────────────────────────────────────────────┤
│ [If encoded: Base32 encoding begins]                                │
├─────────────────────────────────────────────────────────────────────┤
│ Byte 0: Cipher Type = 0x03 (ctPwdSymmetric)                         │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 1-19: KDF Specification                                       │
│   Byte 1: iterations (default: 16)                                  │
│   Byte 2: memory_MB (default: 64)                                   │
│   Byte 3: threads (default: 1)                                      │
│   Bytes 4-19: salt (16 bytes random)                                │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 20-43: Nonce (24 bytes random)                                │
├─────────────────────────────────────────────────────────────────────┤
│ Byte 44: Compression flag (0x00 or 0x01)                            │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 45 onwards: Encrypted blocks                                  │
│   [Block 0]: 65,552 bytes (64KB + 16-byte tag)                      │
│   [Block 1]: 65,552 bytes                                           │
│   ...                                                               │
│   [Block N]: variable (≤ 65,552 bytes)                              │
└─────────────────────────────────────────────────────────────────────┘
```

**Bit-Level Layout of Header** (first 45 bytes = 360 bits):

```
Bits 0-7:        Cipher Type (0x03)
Bits 8-15:       KDF iterations
Bits 16-23:      KDF memory
Bits 24-31:      KDF threads
Bits 32-159:     KDF salt (128 bits)
Bits 160-351:    Nonce (192 bits)
Bits 352-359:    Compression flag (8 bits)
```

#### 7.1.2 Asymmetric Encryption (ECC, Password-Based)

```
┌─────────────────────────────────────────────────────────────────────┐
│ Prefix (optional): "XCT_" (4 bytes, if encoded)                     │
├─────────────────────────────────────────────────────────────────────┤
│ Byte 0: Cipher Type = 0x01 (ctPwdAsymmetric)                        │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 1-19: KDF Specification (19 bytes)                            │
├─────────────────────────────────────────────────────────────────────┤
│ Byte 20: Algorithm Type = 0x00 (algoECC)                            │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 21-52: Ephemeral Public Key (32 bytes)                        │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 53-76: Nonce (24 bytes)                                       │
├─────────────────────────────────────────────────────────────────────┤
│ Byte 77: Compression flag                                           │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 78 onwards: Encrypted blocks                                  │
└─────────────────────────────────────────────────────────────────────┘
```

#### 7.1.3 Asymmetric Encryption (Kyber, Password-Based)

```
┌─────────────────────────────────────────────────────────────────────┐
│ Prefix (optional): "XCT_" (4 bytes, if encoded)                     │
├─────────────────────────────────────────────────────────────────────┤
│ Byte 0: Cipher Type = 0x01 (ctPwdAsymmetric)                        │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 1-19: KDF Specification (19 bytes)                            │
├─────────────────────────────────────────────────────────────────────┤
│ Byte 20: Algorithm Type = 0x01 (algoKyber)                          │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 21-1588: Kyber Ciphertext (1568 bytes)                        │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 1589-1612: Nonce (24 bytes)                                   │
├─────────────────────────────────────────────────────────────────────┤
│ Byte 1613: Compression flag                                         │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 1614 onwards: Encrypted blocks                                │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 Encrypted Block Format

Each encrypted block (except possibly the last):

```
┌─────────────────────────────────────────────────────────────────────┐
│ Bytes 0-65535: XChaCha20 encrypted data (64 KB)                     │
├─────────────────────────────────────────────────────────────────────┤
│ Bytes 65536-65551: Poly1305 MAC tag (16 bytes)                      │
└─────────────────────────────────────────────────────────────────────┘

Total: 65,552 bytes (524,416 bits)
```

**Bit-Level Structure**:

```
Bits 0-524287:      Encrypted plaintext (524,288 bits = 64 KB)
Bits 524288-524415: Authentication tag (128 bits)
```

**Tag Generation**:

The Poly1305 tag is computed over:
1. Associated data (if any) - in this implementation: none
2. Ciphertext
3. Lengths of AD and ciphertext

```
tag = Poly1305(key=derived_from_chacha20, message=ciphertext)
```

### 7.3 Base32 Encoding

When `encode = true`, the binary ciphertext is Base32-encoded:

**Encoding Properties**:
- Alphabet: A-Z, 2-7 (32 characters)
- Padding: None (no '=' padding)
- Expansion: 8/5 ratio (1.6× size increase)
- Case: Uppercase only

**Example Encoding**:

```
Binary:  [0x01, 0x02, 0x03, 0x04, 0x05]
Base32:  "AEBAGBA"
Final:   "XCT_AEBAGBA"
```

**Size Calculation**:

```
base32_size = ceil(binary_size * 8 / 5)
final_size = 4 (prefix) + base32_size
```

---

## 8. Encryption Flow

### 8.1 Complete Encryption Flow (Password-Based Asymmetric, ECC)

```
┌─────────────────────────────────────────────────────────────────────┐
│ Step 1: Key Derivation                                              │
├─────────────────────────────────────────────────────────────────────┤
│ Input: password = "my-secret-password"                              │
│                                                                     │
│ 1.1: Generate KDF spec                                              │
│      salt = crypto_rand(16)                                         │
│      spec = {iterations: 16, memory: 64, threads: 1, salt: salt}    │
│                                                                     │
│ 1.2: Derive secret key                                              │
│      secret_key = Argon2id(password, salt, 16, 64MB, 1, 64)         │
│      // secret_key: 64 bytes                                        │
│                                                                     │
│ 1.3: Derive ECC private key                                         │
│      ecc_private = SHA256(secret_key)                               │
│      // ecc_private: 32 bytes                                       │
│                                                                     │
│ 1.4: Generate ECC public key                                        │
│      ecc_public = X25519(ecc_private, Base_Point)                   │
│      // ecc_public: 32 bytes                                        │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 2: Ephemeral Key Exchange                                      │
├─────────────────────────────────────────────────────────────────────┤
│ 2.1: Generate ephemeral key pair                                    │
│      eph_private = crypto_rand(32)                                  │
│      eph_public = X25519(eph_private, Base_Point)                   │
│                                                                     │
│ 2.2: Compute shared secret                                          │
│      shared_secret = X25519(eph_private, ecc_public)                │
│      // shared_secret: 32 bytes                                     │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 3: Write Header                                                │
├─────────────────────────────────────────────────────────────────────┤
│ if encode:                                                          │
│     output.Write("XCT_")                                            │
│     output = base32_encoder(output)                                 │
│                                                                     │
│ output.Write(0x01)              // ctPwdAsymmetric                  │
│ output.Write(spec.bytes())      // 19 bytes KDF spec                │
│ output.Write(0x00)              // algoECC                          │
│ output.Write(eph_public)        // 32 bytes                         │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 4: Symmetric Encryption Setup                                  │
├─────────────────────────────────────────────────────────────────────┤
│ 4.1: Generate nonce                                                 │
│      nonce = crypto_rand(24)                                        │
│      output.Write(nonce)                                            │
│                                                                     │
│ 4.2: Write compression flag                                         │
│      if compress:                                                   │
│          output.Write(0x01)                                         │
│      else:                                                          │
│          output.Write(0x00)                                         │
│                                                                     │
│ 4.3: Initialize XChaCha20-Poly1305                                  │
│      aead = XChaCha20Poly1305.New(shared_secret)                    │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 5: Data Encryption Loop                                        │
├─────────────────────────────────────────────────────────────────────┤
│ buffer = []                                                         │
│                                                                     │
│ for each chunk in plaintext_stream:                                 │
│     if compress:                                                    │
│         buffer += zlib.compress(chunk)                              │
│     else:                                                           │
│         buffer += chunk                                             │
│                                                                     │
│     while len(buffer) >= 64KB:                                      │
│         block = buffer[0:64KB]                                      │
│         buffer = buffer[64KB:]                                      │
│                                                                     │
│         ciphertext = aead.Seal(nil, nonce, block, nil)              │
│         output.Write(ciphertext)  // 65,552 bytes                   │
│                                                                     │
│ // Final block (< 64KB)                                             │
│ if len(buffer) > 0:                                                 │
│     ciphertext = aead.Seal(nil, nonce, buffer, nil)                 │
│     output.Write(ciphertext)                                        │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 6: Finalization                                                │
├─────────────────────────────────────────────────────────────────────┤
│ if encode:                                                          │
│     close base32_encoder  // Flush encoding                         │
│                                                                     │
│ return ciphertext                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Memory Efficiency

The streaming architecture ensures:

**Memory Usage**:
- Maximum buffer: ~64 KB (one plaintext block)
- Compression buffer: Variable (typically << input size)
- Total: O(1) constant memory, independent of input size

**Benefits**:
- Can encrypt multi-GB files with < 1 MB RAM
- Suitable for embedded systems and resource-constrained environments
- Real-time streaming from network/disk sources

---

## 9. Decryption Flow

### 9.1 Complete Decryption Flow (Password-Based Asymmetric, ECC)

```
┌─────────────────────────────────────────────────────────────────────┐
│ Step 1: Format Detection                                            │
├─────────────────────────────────────────────────────────────────────┤
│ 1.1: Peek first 4 bytes                                             │
│      prefix = peek(input, 4)                                        │
│                                                                     │
│ 1.2: Check encoding                                                 │
│      if prefix == "XCT_":                                           │
│          discard(input, 4)                                          │
│          input = base32_decoder(input)                              │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 2: Parse Header                                                │
├─────────────────────────────────────────────────────────────────────┤
│ 2.1: Read cipher type                                               │
│      ct_type = input.Read(1)                                        │
│      // ct_type = 0x01 (ctPwdAsymmetric)                            │
│                                                                     │
│ 2.2: Read KDF spec (password-based keys only)                       │
│      spec_bytes = input.Read(19)                                    │
│      spec = parseKdfSpec(spec_bytes)                                │
│                                                                     │
│ 2.3: Derive secret key from password                                │
│      secret_key = Argon2id(password, spec.salt, spec.iterations,    │
│                            spec.memory, spec.threads, 64)           │
│                                                                     │
│ 2.4: Read algorithm type                                            │
│      algo = input.Read(1)                                           │
│      // algo = 0x00 (algoECC)                                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 3: Key Exchange Decapsulation                                  │
├─────────────────────────────────────────────────────────────────────┤
│ 3.1: Derive ECC private key                                         │
│      ecc_private = SHA256(secret_key)                               │
│                                                                     │
│ 3.2: Read ephemeral public key                                      │
│      eph_public = input.Read(32)                                    │
│                                                                     │
│ 3.3: Compute shared secret                                          │
│      shared_secret = X25519(ecc_private, eph_public)                │
│      // shared_secret: 32 bytes                                     │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 4: Symmetric Decryption Setup                                  │
├─────────────────────────────────────────────────────────────────────┤
│ 4.1: Read nonce                                                     │
│      nonce = input.Read(24)                                         │
│                                                                     │
│ 4.2: Read compression flag                                          │
│      compress_flag = input.Read(1)                                  │
│                                                                     │
│ 4.3: Initialize XChaCha20-Poly1305                                  │
│      aead = XChaCha20Poly1305.New(shared_secret)                    │
│                                                                     │
│ 4.4: Setup decompression (if needed)                                │
│      if compress_flag == 0x01:                                      │
│          decompressor = zlib.NewReader()                            │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 5: Data Decryption Loop                                        │
├─────────────────────────────────────────────────────────────────────┤
│ plaintext_buffer = []                                               │
│                                                                     │
│ loop:                                                               │
│     // Read ciphertext block (up to 65,552 bytes)                   │
│     ct_block = input.Read(65552)                                    │
│                                                                     │
│     if len(ct_block) == 0:                                          │
│         break  // End of stream                                     │
│                                                                     │
│     // Decrypt and verify                                           │
│     pt_block = aead.Open(nil, nonce, ct_block, nil)                 │
│     if error:                                                       │
│         return "decryption failed: authentication error"            │
│                                                                     │
│     plaintext_buffer += pt_block                                    │
│                                                                     │
│     // Output when buffer is sufficient                             │
│     if len(plaintext_buffer) >= requested_size:                     │
│         if compress_flag == 0x01:                                   │
│             output += decompressor.Read(plaintext_buffer)           │
│         else:                                                       │
│             output += plaintext_buffer                              │
│         plaintext_buffer = []                                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Step 6: Finalization                                                │
├─────────────────────────────────────────────────────────────────────┤
│ // Flush remaining data                                             │
│ if len(plaintext_buffer) > 0:                                       │
│     if compress_flag == 0x01:                                       │
│         output += decompressor.Flush()                              │
│     else:                                                           │
│         output += plaintext_buffer                                  │
│                                                                     │
│ return plaintext                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

### 9.2 Authentication and Integrity

**Critical Security Property**: The Poly1305 tag verification happens **per-block**:

```
For each encrypted block:
    (ciphertext, tag) = read_block(input)
    
    plaintext = XChaCha20.Decrypt(ciphertext)
    computed_tag = Poly1305(key, ciphertext)
    
    if computed_tag != tag:
        ABORT: "Authentication failed - data may be corrupted or tampered"
    
    return plaintext
```

**Guarantees**:
1. **Integrity**: Any modification to ciphertext is detected
2. **Authenticity**: Ciphertext can only be produced by someone with the key
3. **Fail-fast**: Tampering is detected immediately, not after full decryption

---

## 10. Security Analysis

### 10.1 Threat Model

**Attacker Capabilities**:
- Full access to ciphertext
- Knowledge of cryptographic algorithms
- Ability to modify ciphertext
- Ability to attempt password guessing
- (Future) Access to quantum computers

**Security Goals**:
1. **Confidentiality**: Plaintext cannot be recovered without key/password
2. **Integrity**: Modifications to ciphertext are detected

### 10.2 Security Properties

#### 10.2.1 Symmetric Layer (XChaCha20-Poly1305)

**Strengths**:
- **IND-CCA2 Security**: Indistinguishable under adaptive chosen-ciphertext attack
- **Authentication**: Poly1305 provides strong message authentication
- **Nonce Reuse Resistance**: 192-bit nonce makes collisions negligible
- **Proven Security**: Widely analyzed, no known practical attacks

**Potential Weaknesses**:
- **Nonce Reuse**: If same (key, nonce) pair is used twice, security breaks
  - **Mitigation**: Random nonce generation per encryption
- **Implementation Attacks**: Timing/side-channel attacks possible
  - **Mitigation**: Uses constant-time implementations from crypto/golang

**Attack Resistance**:
- **Brute Force**: 2^256 key space (infeasible)
- **Quantum**: Grover's algorithm → 2^128 effective security (still secure)

#### 10.2.2 ECC Layer (Curve25519)

**Strengths**:
- **Ephemeral Keys**: Forward secrecy by default
- **Constant-Time**: Implementation resistant to timing attacks
- **DLP Hardness**: Based on discrete logarithm problem

**Potential Weaknesses**:
- **Quantum Vulnerability**: Shor's algorithm can solve DLP in polynomial time
  - **Mitigation**: Use Kyber mode for quantum resistance
- **Small Subgroup Attacks**: 
  - **Mitigation**: X25519 implementation has built-in protections

**Attack Resistance**:
- **Classical Brute Force**: ~2^128 operations (infeasible)
- **Quantum**: Polynomial time with large quantum computer (vulnerable)

#### 10.2.3 Post-Quantum Layer (Kyber1024)

**Strengths**:
- **Quantum Resistance**: Based on Module-LWE (hard for quantum computers)
- **NIST Standardized**: Rigorous analysis and peer review
- **High Security Level**: NIST Level 5 (highest)

**Potential Weaknesses**:
- **Newer Algorithm**: Less battle-tested than ECC
- **Implementation Attacks**: Side-channel vulnerabilities possible
  - **Mitigation**: Uses standard library with constant-time operations

**Attack Resistance**:
- **Classical**: ~2^256 security (infeasible)
- **Quantum**: ~2^230 security (infeasible for foreseeable future)

#### 10.2.4 Password-Based KDF (Argon2id)

**Strengths**:
- **Memory-Hard**: Resistant to GPU/ASIC attacks
- **Side-Channel Resistance**: Argon2id variant provides defense
- **Configurable**: Can increase security by adjusting parameters

**Potential Weaknesses**:
- **Weak Passwords**: Low-entropy passwords are vulnerable to dictionary attacks
  - **Mitigation**: User education, entropy requirements
- **Parameter Tuning**: Too-low parameters reduce security
  - **Mitigation**: Sensible defaults (16 iterations, 64 MB)

**Attack Resistance**:

| Password Entropy | Attack Cost (default params) |
|------------------|------------------------------|
| 40 bits (weak)   | ~2^40 × 100ms = feasible     |
| 60 bits (medium) | ~2^60 × 100ms = difficult    |
| 80 bits (strong) | ~2^80 × 100ms = infeasible   |

### 10.3 Security Audit

**Strengths**:
1. Uses well-established primitives (XChaCha20, Curve25519, Kyber1024, Argon2)
2. AEAD provides both encryption and authentication
3. Forward secrecy through ephemeral keys
4. Post-quantum option available
5. Constant-time implementations used throughout
6. No custom cryptography

**Potential Concerns**:
1. Nonce reuse within a session (all blocks use same nonce)
   - **Assessment**: Safe for XChaCha20-Poly1305 within single message
2. No explicit key rotation mechanism
   - **Assessment**: Ephemeral keys provide fresh keys per encryption
3. Compression before encryption (CRIME-style attacks)
   - **Assessment**: User-controlled, documented risk
4. Password-based keys exportable via public key
   - **Assessment**: Intentional design for sharing

### 10.4 Compliance and Standards

**Standards Compliance**:
- FIPS 203 (ML-KEM / Kyber)
- RFC 8439 (ChaCha20-Poly1305)
- RFC 7748 (Curve25519)
- RFC 9106 (Argon2)

**Industry Best Practices**:
- Uses crypto/rand for all random number generation
- No ECB mode or other weak block cipher modes
- AEAD over encrypt-then-MAC
- Memory-hard KDF for password derivation

---

## 11. Performance Considerations

### 11.1 Computational Complexity

| Operation | Algorithm | Complexity | Typical Time |
|-----------|-----------|------------|--------------|
| **Key Derivation** | Argon2id | O(memory × iterations) | 100-200 ms |
| **Public Key Gen (ECC)** | X25519 | O(1) | < 1 ms |
| **Public Key Gen (Kyber)** | ML-KEM-1024 | O(n²) | ~1 ms |
| **Encryption (per 64KB)** | XChaCha20-Poly1305 | O(n) | ~1 ms |
| **Key Exchange (ECC)** | X25519 | O(1) | < 1 ms |
| **Key Exchange (Kyber)** | ML-KEM-1024 | O(n²) | ~1-2 ms |

### 11.2 Space Complexity

| Component | Size (bytes) | Notes |
|-----------|--------------|-------|
| **Secret Key** | 64 | Base key material |
| **Public Key (ECC)** | 32 | Curve25519 point |
| **Public Key (Kyber)** | 1568 | ML-KEM-1024 |
| **Nonce** | 24 | Per encryption session |
| **Block Overhead** | 16 | Poly1305 tag per 64KB |
| **Ephemeral Key (ECC)** | 32 | Per encryption |
| **Encapsulation (Kyber)** | 1568 | Per encryption |

**Ciphertext Expansion**:

| Mode | Overhead | Percentage |
|------|----------|------------|
| **Symmetric (no encoding)** | 45 bytes + 0.024% | Minimal |
| **ECC (no encoding)** | 77 bytes + 0.024% | Minimal |
| **Kyber (no encoding)** | 1622 bytes + 0.024% | ~1.6 KB |
| **With Base32 encoding** | × 1.6 + 4 bytes | 60% increase |

### 11.3 Throughput Benchmarks

**Estimated Throughput** (on modern CPU):

| Operation | Throughput |
|-----------|------------|
| XChaCha20-Poly1305 | 1-3 GB/s |
| Argon2id (default) | ~10 MB/s |
| X25519 | ~50,000 ops/s |
| Kyber1024 Encap | ~20,000 ops/s |
| Kyber1024 Decap | ~25,000 ops/s |

**Bottleneck Analysis**:
- Large files: Symmetric encryption (disk I/O bound)
- Small files: Key derivation (for password-based)
- Compression: zlib performance (if enabled)

### 11.4 Memory Usage

**Stack Memory**:
- Encryption: ~64 KB (buffer) + ~4 KB (overhead)
- Decryption: ~64 KB (buffer) + ~4 KB (overhead)
- Key derivation: Argon2 memory parameter (default: 64 MB)

**Heap Memory**:
- Minimal: All buffers are fixed-size
- Streaming ensures O(1) memory complexity

---

## Glossary

- **AEAD**: Authenticated Encryption with Associated Data
- **DEM**: Data Encapsulation Mechanism
- **ECDLP**: Elliptic Curve Discrete Logarithm Problem
- **IND-CCA2**: Indistinguishability under Adaptive Chosen-Ciphertext Attack
- **KDF**: Key Derivation Function
- **KEM**: Key Encapsulation Mechanism
- **MAC**: Message Authentication Code
- **ML-KEM**: Module-Lattice-based Key Encapsulation Mechanism
- **ML-LWE**: Module Learning With Errors
- **NIST**: National Institute of Standards and Technology
- **PQ**: Post-Quantum (cryptography)
- **XChaCha20**: eXtended-nonce ChaCha20 cipher

---

## License

This document is part of the Xipher project and is provided for informational purposes. The cryptographic implementations described herein are open source.

---
