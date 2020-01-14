//
//  Nonce.swift
//  CCurve25519
//
//  Created by Christoph on 13.01.20.
//

import Foundation

public extension AES.GCM {
    
    /// A value used once during a cryptographic operation, and then discarded.
    struct Nonce {
        
        /// The length of a AES GCM length in bytes.
        public static let length = 12
        
        /// The raw bytes of the nonce
        var bytes: [UInt8]
        
        /**
         Creates a new random nonce.
         
         - Throws: `CryptoKitError.noRandomnessSource`, `CryptoKitError.noRandomnessAvailable`
         */
        public init() throws {
            self.bytes = try Randomness.randomBytes(count: Nonce.length).bytes
        }
        
        /**
         Creates a nonce from the given data.
         
         Unless your use case calls for a nonce with a specific value, use the init() method to instead create a random nonce.
         - Parameter data: A data representation of the nonce.
         - Throws: `CryptoKitError.incorrectParameterSize`
         */
        public init(data: Data) throws {
            guard data.count == Nonce.length else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.bytes = data.bytes
        }
        
        init(bytes: [UInt8]) {
            self.bytes = bytes
        }
        
        /// The raw data of the nonce
        public var rawRepresentation: Data {
            return bytes.data
        }
    }
    
}

extension AES.GCM.Nonce: Hashable {
    
}
