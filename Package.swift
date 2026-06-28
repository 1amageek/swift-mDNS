// swift-tools-version: 6.2

import PackageDescription

// Embedded toggle: `DNSWire` dual-builds (host + Embedded). The Embedded build
// is `P2P_CORE_EMBEDDED=1 swiftly run +6.3.1 swift build --target DNSWire`.
// `Lifetimes` is enabled in both modes because the P2P-core `Bytes`/`ByteReader`
// Span-returning members require `@_lifetime`.
let embeddedEnabled = Context.environment["P2P_CORE_EMBEDDED"] == "1"

let hostIOPlatforms: [Platform] = [
    .macOS, .iOS, .tvOS, .watchOS, .visionOS, .linux,
]

let coreSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

// The package's external dependencies. `swift-p2p-core` is needed in every build
// for `IPAddress`, `SocketEndpoint`, and the timer seam. Host packages are present
// only when the manifest is not building Embedded; their target products are still
// platform-gated so a WASI target does not compile `swift-log` or `swift-nio-udp`.
// The Embedded graph adds `swift-p2p-transport` for raw POSIX multicast I/O.
let packageDependencies: [Package.Dependency] = {
    var d: [Package.Dependency] = [
        // Provides the facade currency type `IPAddress` (Foundation-free, Embedded-clean).
        .package(url: "https://github.com/1amageek/swift-p2p-core.git", from: "0.2.1"),
    ]
    if embeddedEnabled {
        // The Embedded mDNS transport drives the Embedded-clean POSIX multicast
        // datagram transport (raw sockets, no Foundation/NIO/any). Pulled in only
        // under Embedded: the host path uses NIO. P2PTransportPOSIX activates its
        // own Embedded build under `P2P_CORE_EMBEDDED=1`, so the whole Embedded
        // module graph stays Embedded-consistent (no non-Embedded import).
        d += [
            .package(url: "https://github.com/1amageek/swift-p2p-transport.git", from: "0.2.1"),
        ]
    } else {
        d += [
            .package(url: "https://github.com/apple/swift-log.git", from: "1.8.0"),
            .package(url: "https://github.com/1amageek/swift-nio-udp.git", from: "1.1.4"),
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
        // Host I/O products are excluded for WASI. The package dependencies may
        // still resolve, but these products are not compiled into the MDNS target.
        d += [
            .product(
                name: "NIOUDPTransport",
                package: "swift-nio-udp",
                condition: .when(platforms: hostIOPlatforms)
            ),
            .product(
                name: "Logging",
                package: "swift-log",
                condition: .when(platforms: hostIOPlatforms)
            ),
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
        // Tier-1 facade: host / Embedded / WASI build. Browser / responder /
        // transport over `[UInt8]` / `MDNSService` / `IPAddress`. The public
        // surface carries no `Data` / `ByteBuffer` / NIO / Foundation types.
        //
        // Host: I/O via NIO (`NIODNSTransport`), logging via swift-log, lock via
        // `Synchronization.Mutex`, timers via `ContinuousClock`. Embedded:
        // raw-POSIX multicast I/O (`EmbeddedMDNSTransport`), no logging, and the
        // `clock_gettime`-backed timer. WASI: no host I/O products are compiled;
        // `UnavailableMDNSTransport` makes multicast unavailability explicit.
        // The Embedded build is
        // `P2P_CORE_EMBEDDED=1 swiftly run +6.3.1 swift build --target MDNS -c release`.
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
