//
//  SymmetricKey.swift
//  CCurve25519
//
//  Created by Christoph on 08.01.20.
//

import Foundation

public struct SymmetricKey {
    
    let bytes: [UInt8]
    
    init(bytes: [UInt8]) {
        self.bytes = bytes
    }
    
    /// The raw bytes of the key
    public var rawBytes: Data {
        return Data(bytes)
    }
    
    /// The number of bits in the key.
    var bitCount: Int {
        return bytes.count * 8
    }
}

extension SymmetricKey: Equatable { }
