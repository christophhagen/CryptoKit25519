//
//  SymmetricKey.swift
//  CCurve25519
//
//  Created by Christoph on 08.01.20.
//

import Foundation

/** A symmetric cryptographic key.
 
 You typically derive a symmetric key from an instance of a shared secret (`SharedSecret`) that you obtain through key agreement. You use a symmetric key to compute a message authentication code like `HMAC`, or to open and close a sealed box (`ChaChaPoly.SealedBox` or `AES.GCM.SealedBox`) using a cipher like `ChaChaPoly` or `AES`.
 */
public struct SymmetricKey {
    
    let bytes: [UInt8]
    
    // MARK: Creating a Key
    
    /**
     Creates a key from the given data.
     
     - Parameter data: The contiguous bytes from which to create the key.
     */
    public init(data: Data) {
        self.bytes = data.bytes
    }
    
    /**
     Generates a new random key of the given size.
     
     - Parameter size: The size of the key to generate. You can use one of the standard sizes, like `bits256`, or you can create a key of custom length by initializing a `SymmetricKeySize` instance with a non-standard value.
     - Throws: `CryptoKitError.noRandomnessSource`, `CryptoKitError.noRandomnessAvailable`
     */
    public init(size: SymmetricKeySize) throws {
        self.bytes = try Randomness.randomBytes(count: size.bitCount / 8).bytes
    }
    
    init(bytes: [UInt8]) {
        self.bytes = bytes
    }
    
    // MARK: Getting the Key Length
    
    /// The number of bits in the key.
    public var bitCount: Int {
        return bytes.count * 8
    }
    
    /// The raw bytes of the key
    public var rawBytes: Data {
        return Data(bytes)
    }
    
    
    /**
     
     The sizes that a symmetric cryptographic key can take.
 
     When creating a new SymmetricKey instance with a call to its `init(size:)` initializer, you typically use one of the standard key sizes, like `bits128`, `bits192`, or `bits256`. When you need a key with a non-standard length, use the`init(bitCount:)` initializer to create a `SymmetricKeySize` instance with a custom bit count.
     */
    public struct SymmetricKeySize {
        
        // MARK: Using Standard Key Lengths
        
        /// A size of 128 bits.
        public static var bits128: SymmetricKeySize {
            .init(bitCount: 128)
        }
        
        /// A size of 192 bits.
        static var bits192: SymmetricKeySize {
            .init(bitCount: 192)
        }
        
        /// A size of 256 bits.
        static var bits256: SymmetricKeySize {
            .init(bitCount: 256)
        }
        
        /// The number of bits in the key.
        public let bitCount: Int
        
        /**
         Creates a new key size of the given length.
         */
        public init(bitCount: Int) {
            self.bitCount = bitCount
        }
    }
}

extension SymmetricKey: Equatable { }
