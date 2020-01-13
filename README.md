# CryptoKit25519
A Swift module for Curve25519 functions compatible with Apple's CryptoKit.

## Purpose

This module provides signatures and key agreement based on Curve25519 in Swift. This library is meant to be compatible and syntactically similar to Apple's [`CryptoKit`](https://developer.apple.com/documentation/cryptokit) framework, which is only available for their recent operating systems. This library provides similar capabilities as [`CryptoKit.Curve25519`](https://developer.apple.com/documentation/cryptokit/curve25519), and has a very similar structure.

## Installation

When using the Swift Package Manager, specify in `Package.swift`:

````swift
.package(url: "https://github.com/christophhagen/CryptoKit25519", from: "1.0.0")
````

Then, in your source files, simply:

````swift
import CryptoKit25519
````

## Usage

The library is split into two main parts, `Signing` and `KeyAgreement`.

### Signing

Signing is part of public-key cryptography. Private keys can create signatures of data, while the corresponding public keys can verify the signatures.

#### Private Keys

When creating a signature, a private key is needed:

````swift
let privateKey = Curve25519.PrivateKey()
````

In order to use `PrivateKey()`, a source of randomness must be set:

````swift
Ed25519.randomnessSource = { count in
    return ... // Return `count` random bytes, or nil, if no randomness is available.
}
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

````swift
let publicKey = privateKey.publicKey
````

Or, when the public key is available as data:

````swift
let publicKey = try Ed25519.PublicKey(rawRepresentation: data)
````

Public keys can also be created from a private key:

````swift
let publicKey = privateKey.publicKey
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

## Attribution

This framework uses the Swift Wrapper [CEd25519](https://github.com/christophhagen/CEd25519), as well as the [CryptoSwift library](https://github.com/krzyzanowskim/CryptoSwift) for the HKDF and Encryption.

The implementation of the signature generation was partly inspired by [Ed25519 for Swift 3.x](https://github.com/vzsg/ed25519).
