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

// The Tier-1 `MDNS` facade's dependencies. `DNSWire` (the codec), `P2PCoreTransport`
// (`IPAddress` / `SocketEndpoint`), and `P2PCoreCrypto` (the `AsyncTimer` time+sleep
// seam) are present in BOTH builds — all three dual-build under `P2P_CORE_EMBEDDED`.
// The host-only deps (swift-log for logging, swift-nio-udp for the NIO multicast
// transport) are dropped under Embedded, where the source gates the matching imports
// behind `#if !hasFeature(Embedded)` and uses the Embedded placeholder transport +
// the no-op logger shim instead.
// The package's external dependencies. `swift-p2p-core` (the `IPAddress` /
// `SocketEndpoint` currency + the `AsyncTimer` seam) is needed in BOTH builds. The
// host-only packages (swift-log, swift-nio-udp) are dropped under Embedded, where
// the facade uses the no-op logger shim and the POSIX placeholder transport — this
// keeps the Embedded module graph minimal and avoids an "unused dependency" warning.
let packageDependencies: [Package.Dependency] = {
    var d: [Package.Dependency] = [
        // Provides the facade currency type `IPAddress` (Foundation-free, Embedded-clean).
        .package(url: "https://github.com/1amageek/swift-p2p-core.git", from: "0.1.0"),
    ]
    if embeddedEnabled {
        // The Embedded mDNS transport drives the Embedded-clean POSIX multicast
        // datagram transport (raw sockets, no Foundation/NIO/any). Pulled in ONLY
        // under Embedded: the host path uses NIO. P2PTransportPOSIX activates its
        // own Embedded build under `P2P_CORE_EMBEDDED=1`, so the whole Embedded
        // module graph stays Embedded-consistent (no non-Embedded import).
        d += [
            .package(url: "https://github.com/1amageek/swift-p2p-transport.git", from: "0.1.0"),
        ]
    } else {
        d += [
            .package(url: "https://github.com/apple/swift-log.git", from: "1.8.0"),
            .package(url: "https://github.com/1amageek/swift-nio-udp.git", from: "1.1.2"),
        ]
    }
    return d
}()

let mdnsFacadeDependencies: [Target.Dependency] = {
    var d: [Target.Dependency] = [
        "DNSWire",
        .product(name: "P2PCoreTransport", package: "swift-p2p-core"),
        .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
    ]
    if embeddedEnabled {
        // Embedded multicast I/O via the raw-POSIX multicast datagram transport.
        d += [
            .product(name: "P2PTransportPOSIX", package: "swift-p2p-transport"),
        ]
    } else {
        d += [
            .product(name: "Logging", package: "swift-log"),
            .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
        ]
    }
    return d
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
    dependencies: packageDependencies,
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
        // Tier-1 facade: dual-build (host + Embedded). Browser / responder /
        // transport over `[UInt8]` / `MDNSService` / `IPAddress`. The public
        // surface carries no `Data` / `ByteBuffer` / NIO / Foundation types.
        //
        // Host: I/O via NIO (`NIODNSTransport`), logging via swift-log, lock via
        // `Synchronization.Mutex`, timers via `ContinuousClock`. Embedded: those
        // host-only deps are dropped (the source gates them behind
        // `#if !hasFeature(Embedded)`); the transport becomes the no-multicast
        // `EmbeddedMDNSTransport` placeholder, the lock an `Atomic` spinlock, and
        // timers the `clock_gettime`-backed `MDNSEmbeddedTimer`. The Embedded build
        // is `P2P_CORE_EMBEDDED=1 swiftly run +6.3.1 swift build --target MDNS -c release`.
        .target(
            name: "MDNS",
            dependencies: mdnsFacadeDependencies,
            path: "Sources/MDNS",
            exclude: ["CONTEXT.md"],
            swiftSettings: coreSettings
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
