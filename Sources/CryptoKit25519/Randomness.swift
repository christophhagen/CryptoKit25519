//
//  Randomness.swift
//  CCurve25519
//
//  Created by Christoph on 13.01.20.
//
#if os(Linux)
import SwiftGlibc
#else
import Darwin
#endif

public enum Randomness {
    
    /**
    The external source of randomness.
     
     - Note: This source must only be set if `SecRandomCopyBytes` is unavailable.
     It is available on the following platforms:
     iOS 2.0+, macOS 10.7+, tvOS 9.0+, watchOS 2.0+, Mac Catalyst 13.0+
     
     Provide a custom randomness source to suit your needs.
     
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
        // Use custom randomness source
        guard let randomBytes = Randomness.source else {
            #if os(Linux)
                return randomLinux(count)
            #else
            if #available(iOS 2.0, OSX 10.7, tvOS 9.0, watchOS 2.0, macCatalyst 13.0, *) {
                return try secRandomBytes(count: count)
            } else {
                throw CryptoKitError.noRandomnessSource
            }
            #endif
        }
        
        guard let data = randomBytes(count), data.count == count else {
            throw CryptoKitError.noRandomnessAvailable
        }
        return data
    }
    
    @available(iOS 2.0, OSX 10.7, tvOS 9.0, watchOS 2.0, macCatalyst 13.0, *)
    private static func secRandomBytes(count: Int) throws -> Data {
        var keyData = Data(count: count)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return keyData
        } else {
            throw CryptoKitError.noRandomnessAvailable
        }
    }
    
    #if os(Linux)
    private static func randomLinux(_ count: Int) -> Data {
        Data((0..<count).map({ _ in UInt8.random(in: 0...UInt8.max) }))
    }
    #endif
}
