import XCTest
@testable import Ed25519

final class Ed25519Tests: XCTestCase {

    func testSignature() throws {
        let seed = try Seed()
        let pair = KeyPair(seed: seed)

        let a = [UInt8]("SomeString".data(using: .utf8)!)

        let signature = pair.sign(a)

        let result = try pair.publicKey.verify(signature: signature, message: a)
        XCTAssertTrue(result)
    }

    static var allTests = [
        ("testSignature", testSignature),
    ]
}
