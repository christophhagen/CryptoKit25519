//
//  PrivateKey.swift
//  CCurve25519
//
//  Created by Christoph on 09.01.20.
//

import Foundation
import CEd25519

public extension Curve25519.Signing {
    
    /// A Curve25519 private key used to create cryptographic signatures.
    struct PrivateKey {
        
        /// The key (32 bytes)
        private let bytes: [UInt8]
        
        /**
         Creates a random Curve25519 private key for signing.
         - Throws: `CryptoKitError.noRandomnessSource`, `CryptoKitError.noRandomnessAvailable`
         */
        public init() throws {
            self.bytes = try Curve25519.newNormalizedKey()
        }
        
        /**
         Creates a Curve25519 private key for signing from a data representation.
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
        public var publicKey: Curve25519.Signing.PublicKey {
            // Length is valid, so no error can be thrown.
            return PublicKey(bytes: publicKeyBytes)
        }
        
        /// The raw bytes of the corresponding public key.
        private var publicKeyBytes: [UInt8] {
            var pubBuffer = [UInt8](repeating: 0, count: Curve25519.keyLength)
            
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
    
}

extension Curve25519.Signing.PrivateKey: Hashable {
    
}
