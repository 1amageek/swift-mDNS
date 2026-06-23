// swift-tools-version: 6.2

import PackageDescription

// Embedded toggle: `mDNSCore` dual-builds (host + Embedded). The Embedded build
// is `P2P_CORE_EMBEDDED=1 swiftly run +6.3.1 swift build --target mDNSCore`.
// `Lifetimes` is enabled in both modes because the P2P-core `Bytes`/`ByteReader`
// Span-returning members require `@_lifetime`.
let embeddedEnabled = Context.environment["P2P_CORE_EMBEDDED"] == "1"

let coreSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

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
        .library(
            name: "mDNSCore",
            targets: ["mDNSCore"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.8.0"),
        // embedded-branch only; restore URL before release.
        // Local path so the whole embedded composition (swift-libp2p pulls quic +
        // SWIM + mDNS + nio-udp together) resolves nio-udp against ONE working tree.
        // A URL pin here collides with swift-libp2p's local-path nio-udp and trips
        // SwiftPM's "Conflicting identity for swift-nio-udp" diagnostic (escalating
        // to an error in future SwiftPM). Original: .package(url: "https://github.com/1amageek/swift-nio-udp.git", from: "1.1.2")
        .package(path: "../swift-nio-udp"),
    ],
    targets: [
        // Embedded-clean DNS/mDNS wire codec (no Foundation, no NIO, no `any`).
        //
        // The codec is `[UInt8]`-native and self-contained (its `WriteBuffer` owns
        // `ContiguousArray<UInt8>`). DNS name decompression requires random access
        // (compression pointers jump backward), so the decode workhorse reads via
        // `UnsafeRawBufferPointer` rather than a forward `ByteReader` cursor; both
        // are Embedded-clean. The target therefore needs no `swift-p2p-core`
        // dependency, which also keeps the adapter's macOS 15 deployment floor
        // (the macOS-26 `Span` platform requirement of P2PCoreBytes is avoided).
        .target(
            name: "mDNSCore",
            path: "Sources/mDNSCore",
            swiftSettings: coreSettings
        ),
        // Foundation/NIO adapter: advertiser/browser/transport + Data/ByteBuffer bridges.
        .target(
            name: "mDNS",
            dependencies: [
                "mDNSCore",
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
