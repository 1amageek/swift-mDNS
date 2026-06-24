// swift-tools-version: 6.2

import PackageDescription

// Embedded toggle: `DNSWire` dual-builds (host + Embedded). The Embedded build
// is `P2P_CORE_EMBEDDED=1 swiftly run +6.3.1 swift build --target DNSWire`.
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
        // Embedded-first baseline (docs/design/api/embedded-first-api.md §2.2):
        // the `MDNS` facade surfaces `P2PCore.IPAddress`, whose package floors at
        // macOS 26. The Tier-3 `DNSWire` codec has no p2p-core dependency and so
        // is not itself bound to this floor, but the package's single platform set
        // adopts the shared baseline.
        .macOS(.v26),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        // Tier-1 facade. `import MDNS` re-exports only the facade types
        // (`MDNSBrowser` / `MDNSResponder` / `MDNSService` / `MDNSError`).
        .library(
            name: "MDNS",
            targets: ["MDNS"]
        ),
        // Tier-3 DNS/mDNS wire codec (separate import; NOT pulled in by `import MDNS`).
        .library(
            name: "DNSWire",
            targets: ["DNSWire"]
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
        // Provides the facade currency type `IPAddress` (Foundation-free, Embedded-clean).
        .package(path: "../swift-p2p-core"),
    ],
    targets: [
        // Tier-3: Embedded-clean DNS/mDNS wire codec (no Foundation, no NIO, no `any`).
        //
        // The codec is `[UInt8]`-native and self-contained (its `WriteBuffer` owns
        // `ContiguousArray<UInt8>`). DNS name decompression requires random access
        // (compression pointers jump backward), so the decode workhorse reads via
        // random-access indexing into `[UInt8]` rather than a forward cursor; this
        // is Embedded-clean. The target needs no `swift-p2p-core` dependency, which
        // keeps it free of the macOS-26 `Span` platform requirement of P2PCoreBytes
        // so `swift build --target DNSWire` compiles under Embedded at a lower floor.
        .target(
            name: "DNSWire",
            path: "Sources/DNSWire",
            swiftSettings: coreSettings
        ),
        // Tier-1 facade: host-only NIO adapter. Browser / responder / transport over
        // `[UInt8]` / `MDNSService` / `IPAddress`. Does I/O via NIO internally; the
        // public surface carries no `Data` / `ByteBuffer` / NIO types.
        .target(
            name: "MDNS",
            dependencies: [
                "DNSWire",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
                .product(name: "P2PCoreTransport", package: "swift-p2p-core"),
            ],
            path: "Sources/MDNS",
            exclude: ["CONTEXT.md"]
        ),
        // Host test target: covers both the Tier-3 codec (`DNSWire`) and the
        // Tier-1 facade (`MDNS`).
        .testTarget(
            name: "mDNSTests",
            dependencies: ["MDNS", "DNSWire"],
            path: "Tests/mDNSTests"
        ),
    ]
)
