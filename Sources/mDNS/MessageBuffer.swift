/// High-Performance Message Buffer
///
/// Provides zero-copy read operations and efficient write operations
/// for DNS message encoding/decoding.

import Foundation
import NIOCore

// MARK: - Read Buffer (Zero-Copy)

/// A read-only buffer for zero-copy parsing of DNS messages.
@usableFromInline
struct ReadBuffer: ~Copyable {
    @usableFromInline let base: UnsafeRawPointer
    @usableFromInline let count: Int
    @usableFromInline var offset: Int

    @inlinable
    init(data: Data) {
        self.base = data.withUnsafeBytes { $0.baseAddress! }
        self.count = data.count
        self.offset = 0
    }

    @inlinable
    init(base: UnsafeRawPointer, count: Int) {
        self.base = base
        self.count = count
        self.offset = 0
    }

    @inlinable
    var remaining: Int { count - offset }

    @inlinable
    var isAtEnd: Bool { offset >= count }

    @inlinable
    mutating func readUInt8() -> UInt8? {
        guard offset < count else { return nil }
        let value = base.load(fromByteOffset: offset, as: UInt8.self)
        offset += 1
        return value
    }

    @inlinable
    mutating func readUInt16() -> UInt16? {
        guard offset + 2 <= count else { return nil }
        let hi = UInt16(base.load(fromByteOffset: offset, as: UInt8.self))
        let lo = UInt16(base.load(fromByteOffset: offset + 1, as: UInt8.self))
        offset += 2
        return (hi << 8) | lo
    }

    @inlinable
    mutating func readUInt32() -> UInt32? {
        guard offset + 4 <= count else { return nil }
        let b0 = UInt32(base.load(fromByteOffset: offset, as: UInt8.self))
        let b1 = UInt32(base.load(fromByteOffset: offset + 1, as: UInt8.self))
        let b2 = UInt32(base.load(fromByteOffset: offset + 2, as: UInt8.self))
        let b3 = UInt32(base.load(fromByteOffset: offset + 3, as: UInt8.self))
        offset += 4
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    @inlinable
    func peekUInt8(at index: Int) -> UInt8? {
        guard index < count else { return nil }
        return base.load(fromByteOffset: index, as: UInt8.self)
    }

    @inlinable
    func peekUInt16(at index: Int) -> UInt16? {
        guard index + 2 <= count else { return nil }
        let hi = UInt16(base.load(fromByteOffset: index, as: UInt8.self))
        let lo = UInt16(base.load(fromByteOffset: index + 1, as: UInt8.self))
        return (hi << 8) | lo
    }

    /// Reads bytes without copying.
    @inlinable
    func bytes(at index: Int, count: Int) -> UnsafeRawBufferPointer? {
        guard index + count <= self.count else { return nil }
        return UnsafeRawBufferPointer(start: base + index, count: count)
    }

    @inlinable
    mutating func skip(_ n: Int) {
        offset += n
    }

    @inlinable
    mutating func seek(to position: Int) {
        offset = position
    }
}

// MARK: - Write Buffer

/// Common mDNS suffixes for compression optimization.
/// These are checked first during name compression lookups.
@usableFromInline
let commonMDNSSuffixes: [String] = [
    "local",
    "_tcp.local",
    "_udp.local",
    "_http._tcp.local",
    "_https._tcp.local",
]

/// A growable buffer for efficient DNS message encoding.
public struct WriteBuffer: ~Copyable {
    @usableFromInline var storage: ContiguousArray<UInt8>
    @usableFromInline var nameOffsets: [String: UInt16]  // For name compression

    @inlinable
    public init(capacity: Int = 512) {
        self.storage = ContiguousArray()
        self.storage.reserveCapacity(capacity)
        self.nameOffsets = Dictionary(minimumCapacity: 16)
    }

    @inlinable
    public var count: Int { storage.count }

    @inlinable
    public mutating func writeUInt8(_ value: UInt8) {
        storage.append(value)
    }

    @inlinable
    public mutating func writeUInt16(_ value: UInt16) {
        storage.append(UInt8(value >> 8))
        storage.append(UInt8(value & 0xFF))
    }

    @inlinable
    public mutating func writeUInt32(_ value: UInt32) {
        storage.append(UInt8((value >> 24) & 0xFF))
        storage.append(UInt8((value >> 16) & 0xFF))
        storage.append(UInt8((value >> 8) & 0xFF))
        storage.append(UInt8(value & 0xFF))
    }

    @inlinable
    public mutating func writeBytes(_ bytes: some Sequence<UInt8>) {
        storage.append(contentsOf: bytes)
    }

    @inlinable
    public mutating func writeBytes(_ buffer: UnsafeRawBufferPointer) {
        storage.append(contentsOf: buffer.bindMemory(to: UInt8.self))
    }

    /// Writes a DNS name with compression support.
    @inlinable
    public mutating func writeName(_ labels: [String]) {
        // Fast path: check full name first
        if !labels.isEmpty {
            let fullKey = labels.joined(separator: ".")
            if let existingOffset = nameOffsets[fullKey] {
                writeUInt16(0xC000 | existingOffset)
                return
            }
        }

        var index = 0
        let labelCount = labels.count

        while index < labelCount {
            // Build suffix key
            let suffix = labels[index...]
            let key = suffix.joined(separator: ".")

            if let existingOffset = nameOffsets[key] {
                // Write compression pointer
                writeUInt16(0xC000 | existingOffset)
                return
            }

            // Record this suffix's offset (only if within addressable range)
            if storage.count < 0x3FFF {
                nameOffsets[key] = UInt16(storage.count)
            }

            // Write this label
            let label = labels[index]
            let utf8 = label.utf8
            writeUInt8(UInt8(utf8.count))
            storage.append(contentsOf: utf8)

            index += 1
        }

        // Terminating zero
        writeUInt8(0)
    }

    /// Returns the buffer contents as Data.
    @inlinable
    public consuming func toData() -> Data {
        storage.withUnsafeBufferPointer { Data($0) }
    }

    /// Copies contents to a NIO ByteBuffer.
    @inlinable
    public func copyToByteBuffer(allocator: ByteBufferAllocator) -> ByteBuffer {
        var buffer = allocator.buffer(capacity: storage.count)
        storage.withUnsafeBufferPointer { ptr in
            _ = buffer.writeBytes(ptr)
        }
        return buffer
    }

    /// Provides access to the underlying bytes.
    @inlinable
    public func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try storage.withUnsafeBytes(body)
    }

    /// Resets the buffer for reuse (avoids reallocation).
    @inlinable
    public mutating func reset() {
        storage.removeAll(keepingCapacity: true)
        nameOffsets.removeAll(keepingCapacity: true)
    }
}

// MARK: - Inline Byte Operations

/// Fast inline byte reading utilities.
@usableFromInline
enum ByteOps {
    @inlinable
    static func readUInt16(from ptr: UnsafeRawPointer, at offset: Int) -> UInt16 {
        let hi = UInt16(ptr.load(fromByteOffset: offset, as: UInt8.self))
        let lo = UInt16(ptr.load(fromByteOffset: offset + 1, as: UInt8.self))
        return (hi << 8) | lo
    }

    @inlinable
    static func readUInt32(from ptr: UnsafeRawPointer, at offset: Int) -> UInt32 {
        let b0 = UInt32(ptr.load(fromByteOffset: offset, as: UInt8.self))
        let b1 = UInt32(ptr.load(fromByteOffset: offset + 1, as: UInt8.self))
        let b2 = UInt32(ptr.load(fromByteOffset: offset + 2, as: UInt8.self))
        let b3 = UInt32(ptr.load(fromByteOffset: offset + 3, as: UInt8.self))
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
}
