//
//  Randomness.swift
//  CCurve25519
//
//  Created by Christoph on 13.01.20.
//
#if os(Linux)
import SwiftGlibc
#else
import Foundation
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
    public static var source: ((_ count: Int) -> [UInt8]?)?
    
    /**
     Create new random bytes.
     - Throws: `CryptoKitError.noRandomnessSource`, `CryptoKitError.noRandomnessAvailable`
     - Returns: The new random bytes.
     */
    static func randomBytes(count: Int) throws -> [UInt8] {
        // Use custom randomness source
        guard let randomBytes = Randomness.source else {
            return try randomWithoutSource(count: count)
        }
        
        guard let data = randomBytes(count), data.count == count else {
            throw CryptoKitError.noRandomnessAvailable
        }
        return data
    }
    
    private static func randomWithoutSource(count: Int) throws -> [UInt8] {
        #if os(Linux)
        return randomLinux(count)
        #else
        guard #available(iOS 2.0, OSX 10.7, tvOS 9.0, watchOS 2.0, macCatalyst 13.0, *) else {
            throw CryptoKitError.noRandomnessSource
        }
        return try secRandomBytes(count: count)
        #endif
    }
    
    @available(iOS 2.0, OSX 10.7, tvOS 9.0, watchOS 2.0, macCatalyst 13.0, *)
    private static func secRandomBytes(count: Int) throws -> [UInt8] {
        var keyData = [UInt8](repeating: 0, count: count)
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
    private static func randomLinux(_ count: Int) -> [UInt8] {
        (0..<count).map({ _ in UInt8.random(in: 0...UInt8.max) })
    }
    #endif
}
