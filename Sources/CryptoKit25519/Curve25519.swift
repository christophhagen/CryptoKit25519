//
//  Curve25519.swift
//  
//
//  Created by Christoph on 08.01.20.
//

import Foundation

public enum Curve25519 {
    
    /// The number of bytes in a Curve25519 private or public key
    public static let keyLength = 32
    
    /// Possible errors for Curve25519 functions
    public enum Curve25519Error: Error {
        
        /// The key material has invalid length
        case invalidKeyLength
        
        /// The source for randomness was not set (`Curve25519.randomnessSource`)
        case noRandomnessSource
        
        /// The randomness source was not able to provide randomness
        case noRandomnessAvailable
        
        /// The key agreement could not be completed.
        case keyAgreementFailed
        
        /// The derivation of a symmetric key could not be completed.
        case keyDerivationFailed
    }
    
    /**
     Create new random bytes for a private key.
     - Throws: `Curve25519Error.noRandomnessSource`, `Curve25519Error.noRandomnessAvailable`
     - Returns: 32 new random bytes.
     */
    static func newKeyBytes() throws -> [UInt8] {
        guard let randomBytes = Curve25519.randomnessSource else {
            throw Curve25519.Curve25519Error.noRandomnessSource
        }
        guard let data = randomBytes(Curve25519.keyLength),
            data.count == Curve25519.keyLength else {
                throw Curve25519.Curve25519Error.noRandomnessAvailable
        }
        return [UInt8](data)
    }
    
    /**
    The external source of randomness.
     
     Must be set before any calls to `PrivateKey()`.
     - Parameter count: The number of bytes to generate
     - Returns: The random bytes, or nil, if no random data is available.
     */
    public static var randomnessSource: ((_ count: Int) -> Data?)?
    
}
