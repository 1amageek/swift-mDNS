/// High-Performance Message Buffer
///
/// Provides zero-copy read operations and efficient write operations
/// for DNS message encoding/decoding.
///
/// Foundation-free and NIO-free: the buffer owns its bytes as a
/// `ContiguousArray<UInt8>` and finalizes to `[UInt8]`. The `Data`/`ByteBuffer`
/// bridges live in the Foundation/NIO adapter (`mDNS`).

// MARK: - Write Buffer

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

    /// Returns the buffer contents as an owned byte array.
    @inlinable
    public consuming func toArray() -> [UInt8] {
        Array(storage)
    }

    /// Provides access to the underlying bytes.
    @inlinable
    public func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) -> T) -> T {
        storage.withUnsafeBytes(body)
    }

    /// Resets the buffer for reuse (avoids reallocation).
    @inlinable
    public mutating func reset() {
        storage.removeAll(keepingCapacity: true)
        nameOffsets.removeAll(keepingCapacity: true)
    }
}

// MARK: - Inline Byte Operations

/// Fast inline big-endian byte reading utilities over `[UInt8]`.
///
/// Callers are responsible for bounds-checking before each read (the DNS
/// decoders do so explicitly so they can surface a typed `DNSError` rather than
/// trapping); these helpers index directly and trap only on a programmer error.
@usableFromInline
enum ByteOps {
    @inlinable
    static func readUInt16(from bytes: [UInt8], at offset: Int) -> UInt16 {
        let hi = UInt16(bytes[offset])
        let lo = UInt16(bytes[offset + 1])
        return (hi << 8) | lo
    }

    @inlinable
    static func readUInt32(from bytes: [UInt8], at offset: Int) -> UInt32 {
        let b0 = UInt32(bytes[offset])
        let b1 = UInt32(bytes[offset + 1])
        let b2 = UInt32(bytes[offset + 2])
        let b3 = UInt32(bytes[offset + 3])
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
}
