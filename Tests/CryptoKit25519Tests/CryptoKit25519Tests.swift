import XCTest
@testable import CryptoKit25519
import CryptoKit
import CEd25519

@available(iOS 13.0, OSX 10.15, tvOS 13.0, watchOS 6.0, macCatalyst 13.0, *)
final class CryptoKit25519Tests: XCTestCase {

    static var allTests = [
        ("testKeyAgreementPublicKey", testKeyAgreementPublicKey),
        ("testSigningPublicKey", testSigningPublicKey),
        ("testVerifySignature", testVerifySignature),
        ("testSignatureCompatibility", testSignatureCompatibility),
        ("testKeyAgreement", testKeyAgreement)
    ]
    
    func testKeyAgreementPublicKey() throws {
        // Noise protocol test vector
        let sk1 = Data(base64Encoded: "S51mhgw53jFJK9s7CQUnv2bvHqdfEFu2+HMo37uf4zc=")!
        let pk1 = Data(base64Encoded: "Ht4jMICpMF9liuztB+8EztNwtfG7oJmzq8Oex7T1qD8=")!
        // Check CryptoKit
        let key1 = try CryptoKit.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk1)
        XCTAssertEqual(key1.publicKey.rawRepresentation, pk1)
        // Check CryptoKit25519
        let key2 = try CryptoKit25519.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk1)
        XCTAssertEqual(key2.publicKey.rawRepresentation, pk1)
        
        // Curve25519 test vector
        let sk2 = Data(base64Encoded: "yAZDncnSxHb/7Y8lgMCIjVirQGv3rjaYh5AhuWu0v1k=")!
        let pk2 = Data(base64Encoded: "G7dZZvLpOjaR3/+UK7KkZqHAi414yj9Nbfi4v6Lk7ig=")!
        
        // Check CryptoKit
        let key3 = try CryptoKit.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk2)
        XCTAssertEqual(key3.publicKey.rawRepresentation, pk2)
        
        // Check CryptoKit25519
        let key4 = try CryptoKit25519.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk2)
        XCTAssertEqual(key4.publicKey.rawRepresentation, pk2)
    }
    
    func testSigningPublicKey() throws {
        // Test a few iterations
        //for _ in 0..<10 {
        let sk = Data(base64Encoded: "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")!
        let pk = Data(base64Encoded: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")!
        
        // Generate private key through CryptoKit
        let key1 = try CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: sk)
        XCTAssertEqual(key1.publicKey.rawRepresentation, pk)
        
        // Compare with CryptoKit25519
        let key2 = try CryptoKit25519.Curve25519.Signing.PrivateKey(rawRepresentation: sk)
        XCTAssertEqual(key2.publicKey.rawRepresentation, pk)
    }
    
    func testVerifySignature() throws {
        let sk = try CryptoKit25519.Curve25519.Signing.PrivateKey()
        let signature = sk.signature(for: Data())
        let pk = sk.publicKey
        XCTAssertTrue(pk.isValidSignature(signature, for: Data()))
    }
    
    func testSignatureCompatibility() throws {
        let sk = Data(base64Encoded: "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")!
        
        let key1 = try CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: sk)
        let key2 = try CryptoKit25519.Curve25519.Signing.PrivateKey(rawRepresentation: sk)
        
        let signature1 = try key1.signature(for: Data())
        XCTAssertTrue(key1.publicKey.isValidSignature(signature1, for: Data()))
        XCTAssertTrue(key2.publicKey.isValidSignature(signature1, for: Data()))
        
        let signature2 = key2.signature(for: Data())
        XCTAssertTrue(key1.publicKey.isValidSignature(signature2, for: Data()))
        XCTAssertTrue(key2.publicKey.isValidSignature(signature2, for: Data()))
    }
    
    func testKeyAgreement() throws {
        let salt = "Salt".data(using: .utf8)!
        let sharedInfo = "Info".data(using: .utf8)!
        let keyA = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let keyB = try CryptoKit25519.Curve25519.KeyAgreement.PrivateKey()
        
        // Calculate key with CryptoKit
        let pubB = try CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyB.publicKey.rawRepresentation)
        let s1 = try keyA.sharedSecretFromKeyAgreement(with: pubB)
        let k1 = s1.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: sharedInfo, outputByteCount: 32)
        
        let pubA = try CryptoKit25519.Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyA.publicKey.rawRepresentation)
        let s2 = try keyB.sharedSecretFromKeyAgreement(with: pubA)
        let k2 = try s2.hkdfDerivedSymmetricKey(
            using: .sha256, salt: salt, sharedInfo: sharedInfo, outputByteCount: 32)
        
        XCTAssertEqual(k1.rawBytes, k2.rawBytes)
    }
    
    func testEncrypt() throws {
        let message = "Hi there".data(using: .utf8)!
        
        let key1 = CryptoKit.SymmetricKey(size: .bits256)
        let key2 = CryptoKit25519.SymmetricKey(data: key1.rawBytes)
        
        let nonce1 = CryptoKit.AES.GCM.Nonce()
        let nonce2 = try CryptoKit25519.AES.GCM.Nonce(data: nonce1.rawRepresentation)
        
        // Encrypt the data
        let encrypted1 = try CryptoKit.AES.GCM.seal(message, using: key1, nonce: nonce1)
        let encrypted2 = try CryptoKit25519.AES.GCM.seal(message, using: key2, nonce: nonce2)
        XCTAssertEqual(encrypted1.ciphertext, encrypted2.ciphertext)
        XCTAssertEqual(encrypted1.nonce.rawRepresentation, nonce1.rawRepresentation)
        XCTAssertEqual(encrypted1.tag, encrypted2.tag)
        XCTAssertEqual(encrypted1.combined!, encrypted2.combined)
        
        // Decrypt the data
        let box1 = try CryptoKit.AES.GCM.SealedBox(combined: encrypted2.combined)
        let box2 = try CryptoKit25519.AES.GCM.SealedBox(combined: encrypted1.combined!)
        
        let decrypted1 = try CryptoKit.AES.GCM.open(box1, using: key1)
        let decrypted2 = try CryptoKit25519.AES.GCM.open(box2, using: key2)
        
        XCTAssertEqual(decrypted1, message)
        XCTAssertEqual(decrypted2, message)
    }
}

@available(iOS 13.0, OSX 10.15, tvOS 13.0, watchOS 6.0, macCatalyst 13.0, *)
extension CryptoKit.SymmetricKey {
    
    var rawBytes: Data {
        withUnsafeBytes { Data(Array($0)) }
    }
}

@available(iOS 13.0, OSX 10.15, tvOS 13.0, watchOS 6.0, macCatalyst 13.0, *)
extension CryptoKit.AES.GCM.Nonce {
    
    var rawRepresentation: Data {
        self.withUnsafeBytes { Data(Array($0)) }
    }
}

extension Data {
    
    public func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    // Convert 0 ... 9, a ... f, A ...F to their decimal value,
    // return nil for all other input characters
    private func decodeNibble(_ u: UInt16) -> UInt8? {
        switch(u) {
        case 0x30 ... 0x39:
            return UInt8(u - 0x30)
        case 0x41 ... 0x46:
            return UInt8(u - 0x41 + 10)
        case 0x61 ... 0x66:
            return UInt8(u - 0x61 + 10)
        default:
            return nil
        }
    }
    
    public init?(hexEncoded string: String) {
        var str = string
        if str.count%2 != 0 {
            // insert 0 to get even number of chars
            str.insert("0", at: str.startIndex)
        }
        
        let utf16 = str.utf16
        self.init(capacity: utf16.count/2)
        
        var i = utf16.startIndex
        while i != str.utf16.endIndex {
            guard let hi = decodeNibble(utf16[i]),
                let lo = decodeNibble(utf16[utf16.index(i, offsetBy: 1, limitedBy: utf16.endIndex)!]) else {
                    return nil
            }
            var value = hi << 4 + lo
            self.append(&value, count: 1)
            i = utf16.index(i, offsetBy: 2, limitedBy: utf16.endIndex)!
        }
    }
}

