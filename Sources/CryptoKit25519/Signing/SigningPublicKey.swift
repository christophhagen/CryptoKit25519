//
//  SigningPublicKey.swift
//  CCurve25519
//
//  Created by Christoph on 09.01.20.
//

import Foundation
import CEd25519

public extension Curve25519.Signing {
    
    /// A Curve25519 public key used to verify cryptographic signatures.
    struct PublicKey {
        
        /// The length of a signature (in bytes)
        public static let signatureLength = 64
        
        /// The key (32 bytes)
        let bytes: [UInt8]
        
        /**
         Creates a Curve25519 public key from a data representation.
         - Parameter rawRepresentation: A representation of the key as data from which to create the key.
         - Throws: `Curve25519Error.invalidKeyLength`, if the key length is not `Curve25519.keyLength`.
          */
         public init(rawRepresentation: Data) throws {
             guard rawRepresentation.count == Curve25519.keyLength else {
                throw Curve25519.Curve25519Error.invalidKeyLength
             }
             self.bytes = [UInt8](rawRepresentation)
        }
        
        init(bytes: [UInt8]) {
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
                        ed25519_verify(
                            signature.bindMemory(to: UInt8.self).baseAddress,
                            msg.bindMemory(to: UInt8.self).baseAddress,
                            data.count,
                            pub.baseAddress) == 1
                    }
                }
            }
        }
    }
}
