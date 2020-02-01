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
    
    /**
     Create new random bytes for a private key.
     - Throws: `CryptoKitError.noRandomnessSource`, `CryptoKitError.noRandomnessAvailable`
     - Returns: 32 new random bytes.
     */
    static func newNormalizedKey() throws -> [UInt8] {
        var data = try Randomness.randomBytes(count: keyLength).bytes
        
        data[0] &= 0xf8
        data[31] &= 0x3f
        data[31] |= 0x40
        
        return data
    }
}
