//
//  File.swift
//  
//
//  Created by Christoph on 08.01.20.
//

import Foundation
import CEd25519
import CCurve25519

public extension Curve25519.KeyAgreement {
    
    /// A Curve25519 private key used to create cryptographic signatures.
    struct PrivateKey {
        
        /// The key bytes
        private let bytes: [UInt8]
        
        /**
         Creates a random Curve25519 private key for key agreement.
         - Throws: `Curve25519Error.noRandomnessSource`, `Curve25519Error.noRandomnessAvailable`
         */
        public init() throws {
            self.bytes = try Curve25519.newKeyBytes()
        }
        
        /**
         Creates a Curve25519 private key for key agreement from a collection of bytes.
         - Parameter rawRepresentation: A raw representation of the key as data.
         - Throws: `Curve25519Error.invalidKeyLength`, if the key length is not `Curve25519.keyLength`.
         */
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == Curve25519.keyLength else {
                throw Curve25519.Curve25519Error.invalidKeyLength
            }
            self.bytes = [UInt8](rawRepresentation)
        }
        
        /// The corresponding public key.
        public var publicKey: Curve25519.KeyAgreement.PublicKey {
            // Length is valid, so no error can be thrown.
            return PublicKey(bytes: publicKeyBytes)
        }
        
        /// The raw bytes of the corresponding public key
        private var publicKeyBytes: [UInt8] {
            var pubBuffer = [UInt8](repeating: 0, count: Curve25519.keyLength)
            
            bytes.withUnsafeBufferPointer { priv in
                pubBuffer.withUnsafeMutableBufferPointer { pub in
                    ed25519_create_public_key(pub.baseAddress, priv.baseAddress)
                }
            }
            return pubBuffer
        }
        
        /// The raw bytes of the key.
        public var rawRepresentation: Data {
            return Data(bytes)
        }
        
        /**
         Computes a shared secret with the provided public key from another party.
         - Parameter publicKeyShare: The public key from another party to be combined with the private key from this user to create the shared secret.
         - Returns: The computed shared secret.
         - Throws: `Curve25519Error.keyAgreementFailed`
         */
        func sharedSecretFromKeyAgreement(with publicKeyShare: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret {
            
            var sharedKey = [UInt8](repeating: 0, count: Curve25519.keyLength)
            let result: Int32 = sharedKey.withUnsafeMutableBytes { s in
                bytes.withUnsafeBytes { d in
                    publicKey.bytes.withUnsafeBytes { k in
                        curve25519_donna(
                            s.bindMemory(to: UInt8.self).baseAddress,
                            d.bindMemory(to: UInt8.self).baseAddress,
                            k.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
            }
            guard result == 0 else {
                throw Curve25519.Curve25519Error.keyAgreementFailed
            }
            return SharedSecret(bytes: sharedKey)
        }
        
    }
}
