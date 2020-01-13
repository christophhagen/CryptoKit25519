//
//  SealedBox.swift
//  CCurve25519
//
//  Created by Christoph on 13.01.20.
//

import Foundation

public extension AES.GCM {
    
    /**
     A secure container for your data that you access using a cipher.
     
     You use a sealed box as a container for data that you want to transmit securely. You seal data into a box with one of the cipher algorithms, like `seal(_:using:nonce:)`.

     The box holds an encrypted version of the original data, an authentication tag, and the nonce during encryption. The encryption makes the data unintelligible to anyone without the key, while the authentication tag makes it possible for the intended receiver to be sure the data remains intact.

     The receiver uses another instance of the same cipher to open the box, like the `open(_:using:)` method.
     */
    struct SealedBox {
        
        /// The encrypted data.
        public let ciphertext: Data
        
        /// An authentication tag.
        public let tag: Data
        
        /// The nonce used to encrypt the data.
        public let nonce: Nonce
        
        public var combined: Data {
            return nonce.rawRepresentation + ciphertext + tag
        }
        
        public init(nonce: Nonce, ciphertext: Data, tag: Data) throws {
            guard tag.count == AES.GCM.tagLength else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.nonce = nonce
            self.ciphertext = ciphertext
            self.tag = tag
        }
        
        public init(combined: Data) throws {
            guard combined.count > Nonce.length + AES.GCM.tagLength else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.nonce = try Nonce(data: combined[0..<Nonce.length])
            let tagStart = combined.count - AES.GCM.tagLength
            self.ciphertext = combined[Nonce.length..<tagStart]
            self.tag = combined[tagStart...]
        }
    }
}
