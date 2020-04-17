//
//  PrivateKey.swift
//  CCurve25519
//
//  Created by Christoph on 09.01.20.
//

import Foundation
import CEd25519

public extension Curve25519.Signing {
    
    /// A Curve25519 private key used to create cryptographic signatures.
    struct PrivateKey {
        
        private let bytes: [UInt8]
        
        /// The key (32 bytes)
        private let privateKeyBytes: [UInt8]
        
        /// The public key bytes
        private let publicKeyBytes: [UInt8]
        
        /**
         Creates a random Curve25519 private key for signing.
         - Throws: `CryptoKitError.noRandomnessSource`, `CryptoKitError.noRandomnessAvailable`
         */
        public init() throws {
            let seed = try Curve25519.newKey()
            self.init(bytes: seed)
        }
        
        /**
         Creates a Curve25519 private key for signing from a data representation.
         - Parameter rawRepresentation: A raw representation of the key as data.
         - Throws: `CryptoKitError.invalidKeyLength`, if the key length is not `Curve25519.keyLength`.
         */
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == Curve25519.keyLength else {
                throw CryptoKitError.invalidKeyLength
            }
            self.init(bytes: Array(rawRepresentation))
        }
        
        public init(bytes: [UInt8]) {
            let (priv, pub) = bytes.withUnsafeBytes { srcRawBufferPointer -> (Data, Data) in
                var priv = Data()
                var pub = Data()
                let privPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Curve25519.keyLength)
                let pubPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Curve25519.keyLength)
                defer {
                    privPointer.deallocate()
                    pubPointer.deallocate()
                }
                
                let srcBufferPointer = srcRawBufferPointer.bindMemory(to: UInt8.self)
                
                guard let srcPointer = srcBufferPointer.baseAddress else {
                  fatalError("Failed to get base address of source bytes")
                }
                ed25519_create_keypair(pubPointer, privPointer, srcPointer)
                priv.append(privPointer, count: Curve25519.keyLength)
                pub.append(pubPointer, count: Curve25519.keyLength)
                return (priv, pub)
            }
//            var pub = [UInt8](repeating: 0, count: 32)
//            var priv = [UInt8](repeating: 0, count: 32)
//            pub.withUnsafeMutableBufferPointer { pP in
//                priv.withUnsafeMutableBufferPointer { sP in
//                    bytes.withUnsafeBytes { s in
//                        ed25519_create_keypair(
//                            pP.baseAddress,
//                            sP.baseAddress,
//                            s.bindMemory(to: UInt8.self).baseAddress)
//                    }
//                }
//            }
//
            self.bytes = bytes
            self.privateKeyBytes = [UInt8](priv)
            self.publicKeyBytes = [UInt8](pub)
        }
        
        /// The corresponding public key.
        public var publicKey: Curve25519.Signing.PublicKey {
            // Length is valid, so no error can be thrown.
            return PublicKey(bytes: publicKeyBytes)
        }
        
        /**
         Generates an EdDSA signature over Curve25519.
         - Parameter data: The data to sign.
         - Returns: The signature for the data.
         */
        public func signature(for data: Data) -> Data {
            var signature = [UInt8](repeating: 0, count: 64)
            
            privateKeyBytes.withUnsafeBufferPointer { priv in
                signature.withUnsafeMutableBufferPointer { signature in
                    publicKeyBytes.withUnsafeBufferPointer { pub in
                        data.withUnsafeBytes { msg in
                            ed25519_sign(signature.baseAddress,
                                         msg.bindMemory(to: UInt8.self).baseAddress,
                                         data.count,
                                         pub.baseAddress,
                                         priv.baseAddress)
                        }
                    }
                }
            }
            
            return Data(signature)
        }
        
        /// The raw bytes of the key.
        public var rawRepresentation: Data {
            return Data(bytes)
        }
    }
    
}

extension Curve25519.Signing.PrivateKey: Hashable {
    
}
