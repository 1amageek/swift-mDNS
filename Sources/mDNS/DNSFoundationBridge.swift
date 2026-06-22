// DNSFoundationBridge.swift
//
// Foundation/NIO compatibility layer for the Embedded-clean `mDNSCore` codec.
//
// `mDNSCore` operates on `[UInt8]` (Foundation-free, NIO-free). This adapter
// re-exposes the historical `Data` / `ByteBuffer` API surface so existing
// callers (and the test suite) keep compiling unchanged:
//
//   - `Data`-accepting `decode(from:)` overloads
//   - `Data`-typed `DNSRecordData.nsec` / `.unknown` convenience factories
//   - `Data` views over `IPv4Address` / `IPv6Address`
//   - `WriteBuffer` -> `Data` / `ByteBuffer` finalizers
//   - `DNSMessage` zero-copy `ByteBuffer` encode/decode (NIO transport path)
//
// All bridges are copy-only and contain no protocol logic; the codec lives in
// `mDNSCore`.

import Foundation
import NIOCore
import mDNSCore

// MARK: - DNSMessage: Data / ByteBuffer bridges

extension DNSMessage {
    /// Decodes a message from Foundation `Data`.
    @inlinable
    public static func decode(from data: Data) throws -> DNSMessage {
        try decode(from: [UInt8](data))
    }

    /// Encodes the message directly to a NIO `ByteBuffer` (zero-copy send path).
    @inlinable
    public func encodeToByteBuffer(allocator: ByteBufferAllocator) -> ByteBuffer {
        let bytes = encode()
        var buffer = allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return buffer
    }

    /// Decodes a message from a NIO `ByteBuffer`.
    @inlinable
    public static func decode(from buffer: ByteBuffer) throws -> DNSMessage {
        var buffer = buffer
        let bytes = buffer.readBytes(length: buffer.readableBytes) ?? []
        return try decode(from: bytes)
    }
}

// MARK: - DNSName / DNSQuestion / DNSResourceRecord / SRVRecord: Data decode bridges

extension DNSName {
    /// Decodes a DNS name from Foundation `Data`.
    @inlinable
    public static func decode(from data: Data, at offset: Int) throws -> (DNSName, Int) {
        try decode(from: [UInt8](data), at: offset)
    }
}

extension DNSQuestion {
    /// Decodes a question from Foundation `Data`.
    @inlinable
    public static func decode(from data: Data, at offset: Int) throws -> (DNSQuestion, Int) {
        try decode(from: [UInt8](data), at: offset)
    }
}

extension DNSResourceRecord {
    /// Decodes a resource record from Foundation `Data`.
    @inlinable
    public static func decode(from data: Data, at offset: Int) throws -> (DNSResourceRecord, Int) {
        try decode(from: [UInt8](data), at: offset)
    }
}

extension SRVRecord {
    /// Decodes an SRV record from Foundation `Data`.
    @inlinable
    public static func decode(from data: Data, at offset: Int) throws -> SRVRecord {
        try decode(from: [UInt8](data), at: offset)
    }
}

// MARK: - DNSRecordData: Data convenience factories

extension DNSRecordData {
    /// Creates an NSEC record from a Foundation `Data` type-bitmap.
    @inlinable
    public static func nsec(nextDomain: DNSName, typeBitmap: Data) -> DNSRecordData {
        .nsec(nextDomain: nextDomain, typeBitmap: [UInt8](typeBitmap))
    }

    /// Creates an unknown record from Foundation `Data` rdata.
    @inlinable
    public static func unknown(typeValue: UInt16, data: Data) -> DNSRecordData {
        .unknown(typeValue: typeValue, data: [UInt8](data))
    }
}

// MARK: - IP addresses: Data bridges

extension IPv4Address {
    /// Creates an IPv4 address from 4 bytes of Foundation `Data`.
    @inlinable
    public init(_ data: Data) {
        precondition(data.count == 4, "IPv4 address must be 4 bytes")
        self.init(data[data.startIndex],
                  data[data.startIndex + 1],
                  data[data.startIndex + 2],
                  data[data.startIndex + 3])
    }

    /// Returns the address as Foundation `Data`.
    @inlinable
    public var rawData: Data {
        Data(rawBytes)
    }
}

extension IPv6Address {
    /// Creates an IPv6 address from 16 bytes of Foundation `Data`.
    @inlinable
    public init(_ data: Data) {
        precondition(data.count == 16, "IPv6 address must be 16 bytes")
        var hiVal: UInt64 = 0
        var loVal: UInt64 = 0
        for i in 0..<8 {
            hiVal = (hiVal << 8) | UInt64(data[data.startIndex + i])
        }
        for i in 8..<16 {
            loVal = (loVal << 8) | UInt64(data[data.startIndex + i])
        }
        self.init(hi: hiVal, lo: loVal)
    }

    /// Returns the address as Foundation `Data`.
    @inlinable
    public var rawData: Data {
        Data(rawBytes)
    }
}

// MARK: - WriteBuffer: Data / ByteBuffer finalizers

extension WriteBuffer {
    /// Returns the buffer contents as Foundation `Data`.
    @inlinable
    public consuming func toData() -> Data {
        Data(toArray())
    }
}

// MARK: - [UInt8] <-> Data equality (decoded payloads vs. Foundation expectations)

/// Compares a decoded `[UInt8]` payload (e.g. an NSEC type-bitmap from
/// `mDNSCore`) against a Foundation `Data` value byte-for-byte.
@inlinable
public func == (lhs: [UInt8], rhs: Data) -> Bool {
    lhs.count == rhs.count && lhs.elementsEqual(rhs)
}

/// Compares a Foundation `Data` value against a decoded `[UInt8]` payload
/// byte-for-byte.
@inlinable
public func == (lhs: Data, rhs: [UInt8]) -> Bool {
    rhs == lhs
}
