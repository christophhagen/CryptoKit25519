# Ed25519
A Swift module for EdDSA over Curve25519

## Purpose

This module provides signature creation and verification based on Ed25519 in Swift. This library is meant to be compatible and syntactically similar to Apple's [`CryptoKit`](https://developer.apple.com/documentation/cryptokit) framework, which is only available for their recent operating systems. This library provides similar capabilities as `CryptoKit.Curve25519.Signing`, and has a very similar structure.

## Installation

When using the Swift Package Manager, specify in `Package.swift`:

````swift
.package(url: "https://github.com/christophhagen/Ed25519", from: "0.2.0")
````

Then, in your source files, simply:

````swift
import Ed25519
````

## Usage

### Private keys

When creating a signature, a private key is needed:

````swift
let privateKey = Ed25519.PrivateKey()
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

### Public keys

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

### Signing

To create a signature with a private key:

````swift
let signature = privateKey.signature(for: data)
````

### Verifying signatures

To verify a signature with a public key:

````swift
let result: Bool = publicKey.isValidSignature(signature, for: data)
````

## Attribution

This framework uses the Swift Wrapper [CEd25519](https://github.com/christophhagen/CEd25519). The implementation was inspired by [Ed25519 for Swift 3.x](https://github.com/vzsg/ed25519).
