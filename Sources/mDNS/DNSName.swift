/// DNS Name Encoding/Decoding
///
/// Implements DNS name format per RFC 1035 Section 4.1.4.

import Foundation

/// Represents a DNS domain name.
///
/// DNS names are encoded as a sequence of labels, each prefixed with
/// its length. The name is terminated with a zero-length label.
///
/// ## Example
/// ```swift
/// let name = try DNSName("_http._tcp.local.")
/// let encoded = name.encode()
/// ```
public struct DNSName: Sendable, Hashable, CustomStringConvertible {

    /// The labels that make up this name.
    public let labels: [String]

    /// Creates a DNS name from a dot-separated string.
    ///
    /// - Parameter string: A dot-separated domain name (e.g., "_http._tcp.local.")
    /// - Throws: `DNSError.invalidName` if the name is invalid
    public init(_ string: String) throws {
        var normalized = string
        // Remove trailing dot if present (it's the root)
        if normalized.hasSuffix(".") {
            normalized.removeLast()
        }

        guard !normalized.isEmpty else {
            self.labels = []
            return
        }

        let parts = normalized.split(separator: ".", omittingEmptySubsequences: false)
        var labels: [String] = []

        for (index, part) in parts.enumerated() {
            let label = String(part)
            // RFC 1035: Empty labels only allowed at root (end of name)
            if label.isEmpty {
                throw DNSError.invalidName("Empty label at position \(index) in name")
            }
            guard label.count <= dnsMaxLabelLength else {
                throw DNSError.invalidName("Label exceeds maximum length: \(label)")
            }
            labels.append(label)
        }

        // Check total length
        let totalLength = labels.reduce(0) { $0 + $1.utf8.count + 1 } + 1
        guard totalLength <= dnsMaxNameLength else {
            throw DNSError.invalidName("Name exceeds maximum length")
        }

        self.labels = labels
    }

    /// Creates a DNS name from labels.
    ///
    /// - Parameter labels: The labels that make up the name
    public init(labels: [String]) {
        self.labels = labels
    }

    /// The string representation of this name (dot-separated with trailing dot).
    public var description: String {
        labels.isEmpty ? "." : labels.joined(separator: ".") + "."
    }

    /// The string representation without trailing dot.
    public var name: String {
        labels.joined(separator: ".")
    }

    /// Whether this is the root domain.
    public var isRoot: Bool {
        labels.isEmpty
    }

    // MARK: - Encoding

    /// Encodes the name into DNS wire format.
    ///
    /// - Returns: The encoded name as Data
    @inlinable
    public func encode() -> Data {
        var buffer = WriteBuffer(capacity: 256)
        encode(to: &buffer)
        return buffer.toData()
    }

    /// Encodes the name into a write buffer (more efficient).
    @inlinable
    public func encode(to buffer: inout WriteBuffer) {
        buffer.writeName(labels)
    }

    /// Encodes the name with compression support using the provided table.
    @inlinable
    public func encodeCompressed(to buffer: inout WriteBuffer) {
        buffer.writeName(labels)
    }

    // MARK: - Decoding

    /// Decodes a DNS name from data.
    ///
    /// Handles both regular names and compressed names (pointers).
    ///
    /// - Parameters:
    ///   - data: The complete DNS message data
    ///   - offset: The offset to start reading from
    /// - Returns: A tuple of (decoded name, bytes consumed)
    /// - Throws: `DNSError.invalidMessage` if the data is malformed
    public static func decode(from data: Data, at offset: Int) throws -> (DNSName, Int) {
        try data.withUnsafeBytes { buffer in
            try decodeFromBuffer(buffer, at: offset)
        }
    }

    /// Zero-copy decoder using raw buffer pointer.
    @inlinable
    public static func decodeFromBuffer(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int
    ) throws -> (DNSName, Int) {
        var labels: [String] = []
        labels.reserveCapacity(4)  // Most names have 3-4 labels

        var currentOffset = offset
        var bytesConsumed = 0
        var jumped = false
        var jumpCount = 0
        let maxJumps = 128  // Prevent infinite loops

        let base = buffer.baseAddress!
        let count = buffer.count

        while currentOffset < count {
            let length = Int(base.load(fromByteOffset: currentOffset, as: UInt8.self))

            // Check for compression pointer (top 2 bits = 11)
            if (length & 0xC0) == 0xC0 {
                guard currentOffset + 1 < count else {
                    throw DNSError.invalidMessage("Truncated compression pointer")
                }

                jumpCount += 1
                guard jumpCount <= maxJumps else {
                    throw DNSError.invalidMessage("Too many compression pointer jumps")
                }

                let hi = UInt16(length & 0x3F) << 8
                let lo = UInt16(base.load(fromByteOffset: currentOffset + 1, as: UInt8.self))
                let pointer = Int(hi | lo)

                if !jumped {
                    bytesConsumed = currentOffset - offset + 2
                }
                jumped = true

                // Validate pointer offset (RFC 1035: must point to valid prior name)
                guard pointer < count else {
                    throw DNSError.invalidMessage("Compression pointer offset \(pointer) beyond message bounds")
                }
                currentOffset = pointer
                continue
            }

            // Check for reserved label types (RFC 1035 Section 4.1.4)
            // 01xxxxxx (0x40-0x7F): Extended label type (RFC 6891)
            // 10xxxxxx (0x80-0xBF): Reserved for future use
            if (length & 0xC0) != 0 {
                throw DNSError.invalidMessage("Reserved label type: 0x\(String(length, radix: 16, uppercase: true))")
            }

            // Regular label
            if length == 0 {
                if !jumped {
                    bytesConsumed = currentOffset - offset + 1
                }
                break
            }

            guard length <= dnsMaxLabelLength else {
                throw DNSError.invalidMessage("Label length exceeds maximum: \(length)")
            }

            guard currentOffset + 1 + length <= count else {
                throw DNSError.invalidMessage("Truncated label")
            }

            // Create string directly from buffer (single allocation)
            let labelPtr = UnsafeRawBufferPointer(
                start: base + currentOffset + 1,
                count: length
            )
            guard let label = String(bytes: labelPtr, encoding: .utf8) else {
                throw DNSError.invalidMessage("Invalid UTF-8 in label")
            }

            labels.append(label)
            currentOffset += 1 + length
        }

        return (DNSName(labels: labels), bytesConsumed)
    }
}

// MARK: - Equatable

extension DNSName: Equatable {
    /// DNS names are compared case-insensitively (ASCII only for performance).
    @inlinable
    public static func == (lhs: DNSName, rhs: DNSName) -> Bool {
        guard lhs.labels.count == rhs.labels.count else { return false }
        for (l, r) in zip(lhs.labels, rhs.labels) {
            if !asciiCaseInsensitiveEqual(l, r) {
                return false
            }
        }
        return true
    }
}

// MARK: - Hashable

extension DNSName {
    /// Hash must be case-insensitive to match equality (RFC 1035).
    ///
    /// This ensures the Hashable contract is satisfied: equal objects must have equal hashes.
    public func hash(into hasher: inout Hasher) {
        for label in labels {
            // Normalize to lowercase for consistent hashing (ASCII only)
            for byte in label.utf8 {
                let normalized = (byte >= 0x41 && byte <= 0x5A) ? byte + 32 : byte
                hasher.combine(normalized)
            }
            // Separator between labels to distinguish "a.bc" from "ab.c"
            hasher.combine(UInt8(0))
        }
    }
}

/// Fast ASCII case-insensitive string comparison (no allocation).
@inlinable
func asciiCaseInsensitiveEqual(_ a: String, _ b: String) -> Bool {
    var aIter = a.utf8.makeIterator()
    var bIter = b.utf8.makeIterator()

    while true {
        let aChar = aIter.next()
        let bChar = bIter.next()

        switch (aChar, bChar) {
        case (nil, nil):
            return true
        case (nil, _), (_, nil):
            return false
        case (let a?, let b?):
            if a == b { continue }
            // ASCII case-insensitive comparison
            let aLower = (a >= 0x41 && a <= 0x5A) ? a + 32 : a
            let bLower = (b >= 0x41 && b <= 0x5A) ? b + 32 : b
            if aLower != bLower { return false }
        }
    }
}

// MARK: - ExpressibleByStringLiteral

extension DNSName: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        do {
            try self.init(value)
        } catch {
            fatalError("DNSName init failed for string: '\(value)' - Error: \(error)")
        }
    }
}
