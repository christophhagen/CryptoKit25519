// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoKit25519",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "CryptoKit25519",
            targets: ["CryptoKit25519"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/christophhagen/CEd25519", from: "0.0.6"),
        .package(url: "https://github.com/christophhagen/CCurve25519", from: "1.0.1"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift", .upToNextMajor(from: "1.0.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "CryptoKit25519",
            dependencies: ["CEd25519", "CCurve25519", "CryptoSwift"]),
        .testTarget(
            name: "CryptoKit25519Tests",
            dependencies: ["CryptoKit25519"]),
    ]
)
