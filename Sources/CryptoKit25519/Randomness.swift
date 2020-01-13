//
//  Randomness.swift
//  CCurve25519
//
//  Created by Christoph on 13.01.20.
//

import Foundation

public enum Randomness {
    
    /**
    The external source of randomness.
     
     Must be set before any calls to `PrivateKey()`.
     - Parameter count: The number of bytes to generate
     - Returns: The random bytes, or nil, if no random data is available.
     */
    public static var source: ((_ count: Int) -> Data?)?
    
    /**
     Create new random bytes.
     - Throws: `CryptoKitError.noRandomnessSource`, `CryptoKitError.noRandomnessAvailable`
     - Returns: The new random bytes.
     */
    static func randomBytes(count: Int) throws -> Data {
        guard let randomBytes = Randomness.source else {
            throw CryptoKitError.noRandomnessSource
        }
        guard let data = randomBytes(count), data.count == count else {
            throw CryptoKitError.noRandomnessAvailable
        }
        return data
    }
}
