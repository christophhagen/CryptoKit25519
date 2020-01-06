import XCTest

import Ed25519Tests

var tests = [XCTestCaseEntry]()
tests += Ed25519Tests.allTests()
XCTMain(tests)
