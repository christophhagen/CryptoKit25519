# CryptoKit25519
A Swift module for Curve25519 functions and AES-GCM encryption compatible with Apple's CryptoKit.

## Purpose

This module provides signatures and key agreement based on Curve25519 in Swift. This library is meant to be compatible and syntactically similar to Apple's [`CryptoKit`](https://developer.apple.com/documentation/cryptokit) framework, which is only available for their recent operating systems. This library provides similar capabilities as [`CryptoKit.Curve25519`](https://developer.apple.com/documentation/cryptokit/curve25519), and has a very similar structure.

## Installation

When using the Swift Package Manager, specify in `Package.swift`:

````swift
.package(url: "https://github.com/christophhagen/CryptoKit25519", from: "0.6.0")
````

Then, in your source files, simply:

````swift
import CryptoKit25519
````

## Usage

This library is built to be *very* similar to Apple's [`CryptoKit`](https://developer.apple.com/documentation/cryptokit) framework, so much of the documentation there also applies to this framework. Notable differences are:
- Operations are NOT constant-time. 
- Sensitive keys are NOT immediately zeroized after use.

Currently supported operations:
- Signatures with Curve25519 (No support for P521, P384, or P256)
- Key Agreement with Curve25519 (No support for P521, P384, or P256)
- Encryption with AES-GCM (No support for ChaChaPoly)

If you need additional operations, have a look at [OpenCrypto](https://github.com/vapor/open-crypto).

### Randomness

`CryptoKit25519` requires a source of cryptographically secure random numbers to generate keys. On supported platforms (iOS 2.0+, macOS 10.7+, tvOS 9.0+, watchOS 2.0+, macCatalyst 13.0+) [SecCopyRandomBytes](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes) is used as the default. On other platforms, this source MUST be provided before any of the following operations are performed:
- `Curve25519.Signing.PrivateKey()`
- `Curve25519.KeyAgreement.PrivateKey()`
- `SymmetricKey(size:)`
- `AES.GCM.Nonce()`
- `AES.GCM.seal(_:key:nonce:authenticating)`

You can provide random numbers by setting `Randomness.source`:
````swift
Randomness.source = { count in
    return ... // Return `count` random bytes, or nil, if no randomness is available.
}
````

### Signing

Signing is part of public-key cryptography. Private keys can create signatures of data, while the corresponding public keys can verify the signatures.

#### Private Keys

When creating a signature, a private key is needed:

````swift
let privateKey = Curve25519.Signing.PrivateKey()
````

When the key is already available:

````swift
let privateKey = try Ed25519.PrivateKey(rawRepresentation: data)
````

Private keys can be converted to data:

````swift
let data = privateKey.rawRepresentation
````

#### Public Keys

Public keys are used to verify signatures. 
Public keys can be created from a private key:

````swift
let publicKey = privateKey.publicKey
````

Or, when the public key is available as data:

````swift
let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: data)
````

Public keys can be converted to data:

````swift
let data = publicKey.rawRepresentation
````

#### Signing

To create a signature with a private key:

````swift
let signature = privateKey.signature(for: data)
````

#### Verifying Signatures

To verify a signature with a public key:

````swift
let result: Bool = publicKey.isValidSignature(signature, for: data)
````

### Key Agreement

Users can exchange public keys in order to establish a shared secret.

#### Private & Public keys

The creation of private keys is analogous to the signature case above.

````swift
let privateKey = Curve25519.KeyAgreement.PrivateKey()
````

#### Calculating shared secrets

Shared secrets can be calculated by both parties, using their private key together with the received public key.

````swift
let secret = try privateKey.sharedSecretFromKeyAgreement(with: otherPublicKey)

// Access the raw data
let data: Data = secret.rawData
````

#### Deriving key material

Shared secrets should not be used directly. Instead, feed them into a *Key Derivation Function* (KDF), to increase the strength of the keys.

````swift
let salt = "My application".data(using: .utf8)!
let sharedInfo = ...

let key = try secret.hkdfDerivedSymmetricKey(
            using: .sha256, 
            salt: salt, 
            sharedInfo: Data, 
            outputByteCount: 32)
            
// Access the raw data
let data: Data = key.rawData
````

## Encryption

`CryptoKit25519` supports `AES` in `GCM`(Galois Counter Mode).

### Encrypting data

````swift
let sealedBox = try AES.GCM.seal(message, using: key)
````

It's also possible to provide a custom nonce, and additional data to be authenticated.

````swift
let sealedBox = try AES.GCM.seal(message, using: key, nonce: AES.GCM.Nonce(), authenticating: authenticatedData)
````

### Decrypting data

````swift
let plaintext = try AES.GCM.open(sealedBox, using: key)
````

## Attribution

This framework uses the Swift Wrapper [CEd25519](https://github.com/christophhagen/CEd25519), as well as the [CryptoSwift library](https://github.com/krzyzanowskim/CryptoSwift) for the HKDF and Encryption.

The implementation of the signature generation was partly inspired by [Ed25519 for Swift 3.x](https://github.com/vzsg/ed25519).
