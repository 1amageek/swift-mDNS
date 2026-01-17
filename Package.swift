// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "swift-mDNS",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(
            name: "mDNS",
            targets: ["mDNS"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.8.0"),
        .package(url: "https://github.com/1amageek/swift-nio-udp.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "mDNS",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
            ],
            path: "Sources/mDNS",
            exclude: ["CONTEXT.md"]
        ),
        .testTarget(
            name: "mDNSTests",
            dependencies: ["mDNS"],
            path: "Tests/mDNSTests"
        ),
    ]
)
