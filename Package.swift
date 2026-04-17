// swift-tools-version: 6.2

import PackageDescription
import Foundation

private let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
private let localSwiftNIOUDPPackage = packageDirectory
    .appendingPathComponent("../swift-nio-udp")
    .standardizedFileURL

private func packageDependency(
    localPath: URL,
    remoteURL: String,
    from version: Version
) -> Package.Dependency {
    let manifestPath = localPath.appendingPathComponent("Package.swift").path
    if FileManager.default.fileExists(atPath: manifestPath) {
        return .package(path: localPath.path)
    }
    return .package(url: remoteURL, from: version)
}

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
        packageDependency(
            localPath: localSwiftNIOUDPPackage,
            remoteURL: "https://github.com/1amageek/swift-nio-udp.git",
            from: "1.1.0"
        ),
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
