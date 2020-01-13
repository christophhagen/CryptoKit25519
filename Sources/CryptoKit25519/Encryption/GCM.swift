//
//  GCM.swift
//  CCurve25519
//
//  Created by Christoph on 13.01.20.
//

import Foundation
import CryptoSwift

public extension AES {
    
    /// The Advanced Encryption Standard (AES) Galois Counter Mode (GCM) cipher suite.
    enum GCM {
        
        /// The length of an authentication tag in bytes
        public static let tagLength = 16
        
        /**
         Secures the given plaintext message with encryption and an authentication tag that covers both the encrypted data and additional data.
         
         - Parameter message: The plaintext data to seal.
         - Parameter key: A cryptographic key used to seal the message.
         - Parameter nonce: A nonce used during the sealing process.
         - Parameter authenticatedData: Additional data to be authenticated.
         */
        public static func seal(_ message: Data, using key: SymmetricKey, nonce: Nonce? = nil, authenticating authenticatedData: Data? = nil) throws -> SealedBox {
            let iv = try nonce ?? Nonce()
            let gcm = CryptoSwift.GCM.init(
                iv: iv.bytes,
                additionalAuthenticatedData: authenticatedData?.bytes,
                tagLength: GCM.tagLength,
                mode: .detached)
            
            let ciphertext: [UInt8]
            do {
                let cryptor = try CryptoSwift.AES(key: key.bytes, blockMode: gcm, padding: .pkcs7)
                ciphertext = try cryptor.encrypt(message.bytes)
            } catch {
                throw CryptoKitError.encryptionFailed
            }
            
            let tag = gcm.authenticationTag!.data
            return try SealedBox(nonce: iv, ciphertext: ciphertext.data, tag: tag)
        }
        
        /**
         Decrypts the message and verifies the authenticity of both the encrypted message and additional data.
         
         - Parameter sealedBox: The sealed box to open.
         - Parameter key: The cryptographic key that was used to seal the message.
         - Parameter authenticatedData: Additional data that was authenticated.
         - Returns: The original plaintext message that was sealed in the box.
         */
        public static func open(_ sealedBox: SealedBox, using key: SymmetricKey, authenticating authenticatedData: Data? = nil) throws -> Data {
            
            let gcm = CryptoSwift.GCM(
                iv: sealedBox.nonce.bytes,
                authenticationTag: sealedBox.tag.bytes,
                additionalAuthenticatedData: authenticatedData?.bytes)
            let plaintext: [UInt8]
            do {
                let cryptor = try CryptoSwift.AES(key: key.bytes, blockMode: gcm, padding: .pkcs7)
                plaintext = try cryptor.decrypt(sealedBox.ciphertext.bytes)
            } catch {
                throw CryptoKitError.decryptionFailed
            }
            return Data(plaintext)
        }
    }
}

extension Data {
    
    var bytes: [UInt8] {
        .init(self)
    }
}

extension Array where Array.Element == UInt8 {
    
    var data: Data {
        return .init(self)
    }
}
