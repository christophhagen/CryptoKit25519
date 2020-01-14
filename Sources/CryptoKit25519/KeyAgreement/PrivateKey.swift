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
        
        private static let basepoint = [9] + Data(repeating: 0, count: 31)
        
        /// The key bytes
        private let bytes: [UInt8]
        
        /**
         Creates a random Curve25519 private key for key agreement.
         - Throws: `CryptoKitError.noRandomnessSource`, `CryptoKitError.noRandomnessAvailable`
         */
        public init() throws {
            self.bytes = try Curve25519.newKeyBytes()
        }
        
        /**
         Creates a Curve25519 private key for key agreement from a collection of bytes.
         - Parameter rawRepresentation: A raw representation of the key as data.
         - Throws: `CryptoKitError.invalidKeyLength`, if the key length is not `Curve25519.keyLength`.
         */
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == Curve25519.keyLength else {
                throw CryptoKitError.invalidKeyLength
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
            
            let _: Int32 = pubBuffer.withUnsafeMutableBytes { keyPtr in
                bytes.withUnsafeBytes { privPtr in
                    Curve25519.KeyAgreement.PrivateKey.basepoint.withUnsafeBytes {
                        curve25519_donna(
                            keyPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            privPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
                    }
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
         - Throws: `CryptoKitError.keyAgreementFailed`
         */
        public func sharedSecretFromKeyAgreement(with publicKeyShare: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret {
            
            var sharedKey = [UInt8](repeating: 0, count: Curve25519.keyLength)
            let result: Int32 = sharedKey.withUnsafeMutableBytes { key in
                bytes.withUnsafeBytes { priv in
                    publicKeyShare.bytes.withUnsafeBytes { pub in
                        curve25519_donna(
                            key.bindMemory(to: UInt8.self).baseAddress,
                            priv.bindMemory(to: UInt8.self).baseAddress,
                            pub.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
            }
            guard result == 0 else {
                throw CryptoKitError.keyAgreementFailed
            }
            return SharedSecret(bytes: sharedKey)
        }
        
    }
}

extension Curve25519.KeyAgreement.PrivateKey: Hashable {
    
}
