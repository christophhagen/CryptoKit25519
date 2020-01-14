//
//  File.swift
//  
//
//  Created by Christoph on 08.01.20.
//

import Foundation

public extension Curve25519.KeyAgreement {
    
    /// A Curve25519 public key used to verify cryptographic signatures.
    struct PublicKey {
        
        /// The length of a signature (in bytes)
        public static let signatureLength = 64
        
        /// The key (32 bytes)
        let bytes: [UInt8]
        
        /**
         Creates a Curve25519 public key from a data representation.
         - Parameter rawRepresentation: A representation of the key as data from which to create the key.
         - Throws: `CryptoKitError.invalidKeyLength`, if the key length is not `Curve25519.keyLength`.
         */
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == Curve25519.keyLength else {
                throw CryptoKitError.invalidKeyLength
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
        
        
    }
}

extension Curve25519.KeyAgreement.PublicKey: Hashable {
    
}
