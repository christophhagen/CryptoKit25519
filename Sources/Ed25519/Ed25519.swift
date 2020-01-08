//
//  Ed25519.swift
//  
//
//  Created by Christoph on 06.01.20.
//

import Foundation
import CEd25519

/// A mechanism used to create or verify a cryptographic signature using Ed25519.
public enum Ed25519 {
    
    /**
    The external source of randomness.
     
     Must be set before any calls to `PrivateKey()`.
     - Parameter count: The number of bytes to generate
     - Returns: The random bytes, or nil, if no random data is available.
     */
    public static var randomnessSource: ((_ count: Int) -> Data?)?
    
    public enum Ed25519Error: Error {
        
        /// The key material has invalid length
        case invalidKeyLength
        
        /// The source for randomness was not set (`Ed25519.randomnessSource`)
        case noRandomnessSource
        
        /// The randomness source was not able to provide randomness
        case noRandomnessAvailable
    }
    
    /// A Curve25519 private key used to create cryptographic signatures.
    public struct PrivateKey {
        
        /// The number of bytes in a Curve25519 private key
        public static let keyLength = 32
        
        /// The key (32 bytes)
        private let bytes: [UInt8]
        
        /**
         Creates a random Curve25519 private key for signing.
         - Throws: `Ed25519Error.noRandomnessSource`, `Ed25519Error.noRandomnessAvailable`
         */
        public init() throws {
            guard let randomBytes = Ed25519.randomnessSource else {
                throw Ed25519Error.noRandomnessSource
            }
            guard let data = randomBytes(PrivateKey.keyLength),
                data.count == PrivateKey.keyLength else {
                    throw Ed25519Error.noRandomnessAvailable
            }
             self.init(bytes: [UInt8](data))
        }
        
        /**
         Creates a Curve25519 private key for signing from a data representation.
         - Parameter rawRepresentation: A raw representation of the key as data.
         - Throws: `Ed25519Error.invalidKeyLength`, if the key length is not `PrivateKey.keyLength`.
         - Note: If the key has invalid bytes, the key will be automatically corrected. When this happens, then `privateKey.rawRepresentation` will differ from the original input.
         */
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == PrivateKey.keyLength else {
                throw Ed25519Error.invalidKeyLength
            }
            self.init(bytes: [UInt8](rawRepresentation))
        }
        
        init(bytes: [UInt8]) {
            var raw = bytes
            raw.withUnsafeMutableBufferPointer { priv in
                ed25519_make_private_key(priv.baseAddress)
            }
            self.bytes = raw
        }
        
        /// The corresponding public key.
        public var publicKey: PublicKey {
            // Length is valid, so no error can be thrown.
            return PublicKey(bytes: publicKeyBytes)
        }
        
        /// The raw bytes of the corresponding public key
        private var publicKeyBytes: [UInt8] {
            var pubBuffer = [UInt8](repeating: 0, count: PublicKey.keyLength)
            
            bytes.withUnsafeBufferPointer { priv in
                pubBuffer.withUnsafeMutableBufferPointer { pub in
                    ed25519_create_public_key(pub.baseAddress, priv.baseAddress)
                }
            }
            return pubBuffer
        }
        
        /**
         Generates an EdDSA signature over Curve25519.
         - Parameter data: The data to sign.
         - Returns: The signature for the data.
         */
        public func signature(for data: Data) -> Data {
            var signature = [UInt8](repeating: 0, count: 64)
            let publicKey = publicKeyBytes
            
            signature.withUnsafeMutableBufferPointer { signature in
                publicKey.withUnsafeBufferPointer { pub in
                    data.withUnsafeBytes { msg in
                        bytes.withUnsafeBufferPointer { priv in
                            ed25519_sign(signature.baseAddress,
                                         msg.bindMemory(to: UInt8.self).baseAddress,
                                         data.count,
                                         pub.baseAddress,
                                         priv.baseAddress)
                        }
                    }
                }
            }
            
            return Data(signature)
        }
        
        /// The raw bytes of the key.
        public var rawRepresentation: Data {
            return Data(bytes)
        }
    }
    
    /// A Curve25519 public key used to verify cryptographic signatures.
    public struct PublicKey {
        
        /// The number of bytes in a Curve25519 public key
        public static let keyLength = 32
        
        /// The length of a signature (in bytes)
        public static let signatureLength = 64
        
        /// The key (32 bytes)
        let bytes: [UInt8]
        
        /**
         Creates a Curve25519 public key from a data representation.
         - Parameter rawRepresentation: A representation of the key as data from which to create the key.
         - Throws: `Ed25519Error.invalidKeyLength`, if the key length is not `PublicKey.keyLength`.
          */
         public init(rawRepresentation: Data) throws {
             guard rawRepresentation.count == PublicKey.keyLength else {
                 throw Ed25519Error.invalidKeyLength
             }
             self.bytes = [UInt8](rawRepresentation)
        }
        
        fileprivate init(bytes: [UInt8]) {
            self.bytes = bytes
        }
        
        /// The raw bytes of the key.
        public var rawRepresentation: Data {
            return Data(bytes)
        }
        
        /**
         Verifies an EdDSA signature over Curve25519.
         - Parameter signature: The signature to check against the given data.
         - Parameter data: The data covered by the signature.
         - Returns: A Boolean value that’s true when the signature is valid for the given data.
         */
        public func isValidSignature(_ signature: Data, for data: Data) -> Bool {
            guard signature.count == PublicKey.signatureLength else {
                return false
            }

            return signature.withUnsafeBytes { signature in
                data.withUnsafeBytes { msg in
                    bytes.withUnsafeBufferPointer { pub in
                        ed25519_verify(signature.bindMemory(to: UInt8.self).baseAddress,
                                       msg.bindMemory(to: UInt8.self).baseAddress,
                                       data.count,
                                       pub.baseAddress) == 1
                    }
                }
            }
        }
    }
}
