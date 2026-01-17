/// DNS Record Types
///
/// Implements DNS resource records per RFC 1035 and related RFCs.

import Foundation

// MARK: - DNS Question

/// A DNS question (query).
public struct DNSQuestion: Sendable, Hashable {
    /// The name being queried.
    public let name: DNSName

    /// The record type being queried.
    public let type: DNSRecordType

    /// The record class (usually IN for Internet).
    public let recordClass: DNSRecordClass

    /// Whether this is a unicast query (mDNS QU bit).
    public let unicastResponse: Bool

    public init(
        name: DNSName,
        type: DNSRecordType,
        recordClass: DNSRecordClass = .in,
        unicastResponse: Bool = false
    ) {
        self.name = name
        self.type = type
        self.recordClass = recordClass
        self.unicastResponse = unicastResponse
    }

    /// Encodes the question to wire format.
    @inlinable
    public func encode() -> Data {
        var buffer = WriteBuffer(capacity: 64)
        encode(to: &buffer)
        return buffer.toData()
    }

    /// Encodes the question into a write buffer (more efficient).
    @inlinable
    public func encode(to buffer: inout WriteBuffer) {
        name.encode(to: &buffer)

        // Type (2 bytes)
        buffer.writeUInt16(type.rawValue)

        // Class (2 bytes) with QU bit
        var classValue = recordClass.rawValue
        if unicastResponse {
            classValue |= 0x8000
        }
        buffer.writeUInt16(classValue)
    }

    /// Decodes a question from data.
    @inlinable
    public static func decode(from data: Data, at offset: Int) throws -> (DNSQuestion, Int) {
        try data.withUnsafeBytes { buffer in
            try decodeFromBuffer(buffer, at: offset)
        }
    }

    /// Zero-copy decoder using raw buffer pointer.
    @inlinable
    public static func decodeFromBuffer(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int
    ) throws -> (DNSQuestion, Int) {
        let (name, nameBytes) = try DNSName.decodeFromBuffer(buffer, at: offset)
        var currentOffset = offset + nameBytes

        guard currentOffset + 4 <= buffer.count else {
            throw DNSError.invalidMessage("Truncated question")
        }

        let base = buffer.baseAddress!
        let typeValue = ByteOps.readUInt16(from: base, at: currentOffset)
        currentOffset += 2

        let classValue = ByteOps.readUInt16(from: base, at: currentOffset)
        currentOffset += 2

        guard let type = DNSRecordType(rawValue: typeValue) else {
            throw DNSError.unsupportedRecordType(typeValue)
        }

        let unicastResponse = (classValue & 0x8000) != 0
        let recordClass = DNSRecordClass(rawValue: classValue & 0x7FFF) ?? .in

        return (
            DNSQuestion(
                name: name,
                type: type,
                recordClass: recordClass,
                unicastResponse: unicastResponse
            ),
            currentOffset - offset
        )
    }
}

// MARK: - DNS Resource Record

/// A DNS resource record.
public struct DNSResourceRecord: Sendable, Hashable {
    /// The name this record applies to.
    public let name: DNSName

    /// The record type.
    public let type: DNSRecordType

    /// The record class.
    public let recordClass: DNSRecordClass

    /// Whether this record should flush the cache (mDNS cache-flush bit).
    public let cacheFlush: Bool

    /// Time-to-live in seconds.
    public let ttl: UInt32

    /// The record data.
    public let rdata: DNSRecordData

    public init(
        name: DNSName,
        type: DNSRecordType,
        recordClass: DNSRecordClass = .in,
        cacheFlush: Bool = false,
        ttl: UInt32,
        rdata: DNSRecordData
    ) {
        self.name = name
        self.type = type
        self.recordClass = recordClass
        self.cacheFlush = cacheFlush
        self.ttl = ttl
        self.rdata = rdata
    }

    /// Encodes the resource record to wire format.
    @inlinable
    public func encode() -> Data {
        var buffer = WriteBuffer(capacity: 256)
        encode(to: &buffer)
        return buffer.toData()
    }

    /// Encodes the resource record into a write buffer (more efficient).
    @inlinable
    public func encode(to buffer: inout WriteBuffer) {
        name.encode(to: &buffer)

        // Type (2 bytes)
        buffer.writeUInt16(type.rawValue)

        // Class (2 bytes) with cache-flush bit
        var classValue = recordClass.rawValue
        if cacheFlush {
            classValue |= dnsCacheFlushBit
        }
        buffer.writeUInt16(classValue)

        // TTL (4 bytes)
        buffer.writeUInt32(ttl)

        // RDATA - encode to temporary buffer to get length
        var rdataBuffer = WriteBuffer(capacity: 128)
        rdata.encode(to: &rdataBuffer)
        buffer.writeUInt16(UInt16(rdataBuffer.count))
        rdataBuffer.withUnsafeBytes { buffer.writeBytes($0) }
    }

    /// Decodes a resource record from data.
    @inlinable
    public static func decode(from data: Data, at offset: Int) throws -> (DNSResourceRecord, Int) {
        try data.withUnsafeBytes { buffer in
            try decodeFromBuffer(buffer, at: offset)
        }
    }

    /// Zero-copy decoder using raw buffer pointer.
    @inlinable
    public static func decodeFromBuffer(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int
    ) throws -> (DNSResourceRecord, Int) {
        let (name, nameBytes) = try DNSName.decodeFromBuffer(buffer, at: offset)
        var currentOffset = offset + nameBytes

        guard currentOffset + 10 <= buffer.count else {
            throw DNSError.invalidMessage("Truncated resource record")
        }

        let base = buffer.baseAddress!

        let typeValue = ByteOps.readUInt16(from: base, at: currentOffset)
        currentOffset += 2

        let classValue = ByteOps.readUInt16(from: base, at: currentOffset)
        currentOffset += 2

        let ttl = ByteOps.readUInt32(from: base, at: currentOffset)
        currentOffset += 4

        let rdataLength = Int(ByteOps.readUInt16(from: base, at: currentOffset))
        currentOffset += 2

        guard currentOffset + rdataLength <= buffer.count else {
            throw DNSError.invalidMessage("Truncated RDATA")
        }

        currentOffset += rdataLength

        let cacheFlush = (classValue & dnsCacheFlushBit) != 0
        let recordClass = DNSRecordClass(rawValue: classValue & 0x7FFF) ?? .in

        let type = DNSRecordType(rawValue: typeValue)
        let rdata: DNSRecordData

        if let knownType = type {
            rdata = try DNSRecordData.decodeFromBuffer(
                type: knownType,
                buffer: buffer,
                rdataOffset: currentOffset - rdataLength,
                rdataLength: rdataLength
            )
        } else {
            let rdataPtr = UnsafeRawBufferPointer(
                start: base + currentOffset - rdataLength,
                count: rdataLength
            )
            rdata = .unknown(typeValue: typeValue, data: Data(rdataPtr))
        }

        return (
            DNSResourceRecord(
                name: name,
                type: type ?? .a,
                recordClass: recordClass,
                cacheFlush: cacheFlush,
                ttl: ttl,
                rdata: rdata
            ),
            currentOffset - offset
        )
    }
}

// MARK: - DNS Record Data

/// DNS record data (RDATA).
public enum DNSRecordData: Sendable, Hashable {
    /// A record: IPv4 address.
    case a(IPv4Address)

    /// AAAA record: IPv6 address.
    case aaaa(IPv6Address)

    /// PTR record: domain name pointer.
    case ptr(DNSName)

    /// SRV record: service location.
    case srv(SRVRecord)

    /// TXT record: text strings.
    case txt([String])

    /// HINFO record: host information.
    case hinfo(cpu: String, os: String)

    /// NSEC record: next secure.
    case nsec(nextDomain: DNSName, typeBitmap: Data)

    /// Unknown record type.
    case unknown(typeValue: UInt16, data: Data)

    /// Encodes the record data to wire format.
    @inlinable
    public func encode() -> Data {
        var buffer = WriteBuffer(capacity: 128)
        encode(to: &buffer)
        return buffer.toData()
    }

    /// Encodes the record data into a write buffer (more efficient).
    @inlinable
    public func encode(to buffer: inout WriteBuffer) {
        switch self {
        case .a(let address):
            address.write(to: &buffer)

        case .aaaa(let address):
            address.write(to: &buffer)

        case .ptr(let name):
            name.encode(to: &buffer)

        case .srv(let srv):
            srv.encode(to: &buffer)

        case .txt(let strings):
            encodeTXT(strings, to: &buffer)

        case .hinfo(let cpu, let os):
            let cpuBytes = cpu.utf8
            buffer.writeUInt8(UInt8(cpuBytes.count))
            buffer.writeBytes(cpuBytes)
            let osBytes = os.utf8
            buffer.writeUInt8(UInt8(osBytes.count))
            buffer.writeBytes(osBytes)

        case .nsec(let nextDomain, let typeBitmap):
            nextDomain.encode(to: &buffer)
            buffer.writeBytes(typeBitmap)

        case .unknown(_, let data):
            buffer.writeBytes(data)
        }
    }

    /// Decodes record data from wire format.
    @inlinable
    static func decode(
        type: DNSRecordType,
        from data: Data,
        rdataOffset: Int,
        rdataLength: Int
    ) throws -> DNSRecordData {
        try data.withUnsafeBytes { buffer in
            try decodeFromBuffer(type: type, buffer: buffer, rdataOffset: rdataOffset, rdataLength: rdataLength)
        }
    }

    /// Zero-copy decoder using raw buffer pointer.
    @inlinable
    static func decodeFromBuffer(
        type: DNSRecordType,
        buffer: UnsafeRawBufferPointer,
        rdataOffset: Int,
        rdataLength: Int
    ) throws -> DNSRecordData {
        let base = buffer.baseAddress!

        switch type {
        case .a:
            guard rdataLength == 4 else {
                throw DNSError.invalidMessage("Invalid A record length: \(rdataLength)")
            }
            let ptr = UnsafeRawBufferPointer(start: base + rdataOffset, count: 4)
            return .a(IPv4Address(buffer: ptr))

        case .aaaa:
            guard rdataLength == 16 else {
                throw DNSError.invalidMessage("Invalid AAAA record length: \(rdataLength)")
            }
            let ptr = UnsafeRawBufferPointer(start: base + rdataOffset, count: 16)
            return .aaaa(IPv6Address(buffer: ptr))

        case .ptr:
            let (name, _) = try DNSName.decodeFromBuffer(buffer, at: rdataOffset)
            return .ptr(name)

        case .srv:
            let srv = try SRVRecord.decodeFromBuffer(buffer, at: rdataOffset)
            return .srv(srv)

        case .txt:
            let strings = try decodeTXTFromBuffer(buffer, at: rdataOffset, length: rdataLength)
            return .txt(strings)

        case .hinfo:
            guard rdataOffset < buffer.count else {
                throw DNSError.invalidMessage("Truncated HINFO")
            }
            let cpuLen = Int(base.load(fromByteOffset: rdataOffset, as: UInt8.self))
            guard rdataOffset + 1 + cpuLen < buffer.count else {
                throw DNSError.invalidMessage("Truncated HINFO CPU")
            }
            let cpuPtr = UnsafeRawBufferPointer(start: base + rdataOffset + 1, count: cpuLen)
            let cpu = String(bytes: cpuPtr, encoding: .utf8) ?? ""

            let osOffset = rdataOffset + 1 + cpuLen
            guard osOffset < buffer.count else {
                throw DNSError.invalidMessage("Truncated HINFO OS")
            }
            let osLen = Int(base.load(fromByteOffset: osOffset, as: UInt8.self))
            guard osOffset + 1 + osLen <= rdataOffset + rdataLength else {
                throw DNSError.invalidMessage("Truncated HINFO OS data")
            }
            let osPtr = UnsafeRawBufferPointer(start: base + osOffset + 1, count: osLen)
            let os = String(bytes: osPtr, encoding: .utf8) ?? ""

            return .hinfo(cpu: cpu, os: os)

        case .nsec:
            let (nextDomain, bytesConsumed) = try DNSName.decodeFromBuffer(buffer, at: rdataOffset)
            let bitmapStart = rdataOffset + bytesConsumed
            let bitmapLength = rdataLength - bytesConsumed
            let bitmapPtr = UnsafeRawBufferPointer(start: base + bitmapStart, count: bitmapLength)
            return .nsec(nextDomain: nextDomain, typeBitmap: Data(bitmapPtr))

        default:
            let ptr = UnsafeRawBufferPointer(start: base + rdataOffset, count: rdataLength)
            return .unknown(typeValue: type.rawValue, data: Data(ptr))
        }
    }

    @inlinable
    func encodeTXT(_ strings: [String], to buffer: inout WriteBuffer) {
        if strings.isEmpty {
            // Empty TXT record has a single zero-length string
            buffer.writeUInt8(0)
            return
        }
        for string in strings {
            let utf8 = string.utf8
            // TXT strings are limited to 255 bytes each
            let length = min(utf8.count, 255)
            buffer.writeUInt8(UInt8(length))
            buffer.writeBytes(utf8.prefix(length))
        }
    }

    @inlinable
    static func decodeTXTFromBuffer(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int,
        length: Int
    ) throws -> [String] {
        var strings: [String] = []
        strings.reserveCapacity(4)

        var currentOffset = offset
        let endOffset = offset + length
        let base = buffer.baseAddress!

        while currentOffset < endOffset {
            let stringLength = Int(base.load(fromByteOffset: currentOffset, as: UInt8.self))
            currentOffset += 1

            if stringLength == 0 {
                strings.append("")
                continue
            }

            guard currentOffset + stringLength <= endOffset else {
                throw DNSError.invalidMessage("Truncated TXT string")
            }

            let ptr = UnsafeRawBufferPointer(start: base + currentOffset, count: stringLength)
            let string = String(bytes: ptr, encoding: .utf8) ?? ""
            strings.append(string)
            currentOffset += stringLength
        }

        return strings
    }
}

// MARK: - SRV Record

/// SRV record data (RFC 2782).
public struct SRVRecord: Sendable, Hashable {
    /// Priority (lower is better).
    public let priority: UInt16

    /// Weight for load balancing.
    public let weight: UInt16

    /// TCP/UDP port.
    public let port: UInt16

    /// Target hostname.
    public let target: DNSName

    public init(priority: UInt16, weight: UInt16, port: UInt16, target: DNSName) {
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target
    }

    /// Encodes to wire format.
    @inlinable
    public func encode() -> Data {
        var buffer = WriteBuffer(capacity: 64)
        encode(to: &buffer)
        return buffer.toData()
    }

    /// Encodes to a write buffer (more efficient).
    @inlinable
    public func encode(to buffer: inout WriteBuffer) {
        buffer.writeUInt16(priority)
        buffer.writeUInt16(weight)
        buffer.writeUInt16(port)
        target.encode(to: &buffer)
    }

    /// Decodes from wire format.
    @inlinable
    public static func decode(from data: Data, at offset: Int) throws -> SRVRecord {
        try data.withUnsafeBytes { buffer in
            try decodeFromBuffer(buffer, at: offset)
        }
    }

    /// Zero-copy decoder using raw buffer pointer.
    @inlinable
    public static func decodeFromBuffer(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int
    ) throws -> SRVRecord {
        guard offset + 6 <= buffer.count else {
            throw DNSError.invalidMessage("Truncated SRV record")
        }

        let base = buffer.baseAddress!
        let priority = ByteOps.readUInt16(from: base, at: offset)
        let weight = ByteOps.readUInt16(from: base, at: offset + 2)
        let port = ByteOps.readUInt16(from: base, at: offset + 4)

        let (target, _) = try DNSName.decodeFromBuffer(buffer, at: offset + 6)

        return SRVRecord(priority: priority, weight: weight, port: port, target: target)
    }
}

// MARK: - IP Addresses

/// IPv4 address (inline storage, no heap allocation).
public struct IPv4Address: Sendable, CustomStringConvertible {
    /// Inline 4-byte storage.
    public let bytes: (UInt8, UInt8, UInt8, UInt8)

    /// Packed representation for hashing/comparison.
    @inlinable
    var packed: UInt32 {
        UInt32(bytes.0) << 24 | UInt32(bytes.1) << 16 | UInt32(bytes.2) << 8 | UInt32(bytes.3)
    }

    @inlinable
    public init(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) {
        self.bytes = (a, b, c, d)
    }

    @inlinable
    public init(_ data: Data) {
        precondition(data.count == 4, "IPv4 address must be 4 bytes")
        self.bytes = (data[data.startIndex],
                      data[data.startIndex + 1],
                      data[data.startIndex + 2],
                      data[data.startIndex + 3])
    }

    @inlinable
    public init(buffer: UnsafeRawBufferPointer) {
        precondition(buffer.count >= 4, "Buffer too small for IPv4")
        let ptr = buffer.baseAddress!
        self.bytes = (ptr.load(fromByteOffset: 0, as: UInt8.self),
                      ptr.load(fromByteOffset: 1, as: UInt8.self),
                      ptr.load(fromByteOffset: 2, as: UInt8.self),
                      ptr.load(fromByteOffset: 3, as: UInt8.self))
    }

    public init?(string: String) {
        let parts = string.split(separator: ".")
        guard parts.count == 4,
              let a = UInt8(parts[0]),
              let b = UInt8(parts[1]),
              let c = UInt8(parts[2]),
              let d = UInt8(parts[3]) else { return nil }
        self.bytes = (a, b, c, d)
    }

    /// Returns raw bytes as Data (for compatibility).
    @inlinable
    public var rawData: Data {
        Data([bytes.0, bytes.1, bytes.2, bytes.3])
    }

    /// Writes to a buffer without allocation.
    @inlinable
    public func write(to buffer: inout WriteBuffer) {
        buffer.writeUInt8(bytes.0)
        buffer.writeUInt8(bytes.1)
        buffer.writeUInt8(bytes.2)
        buffer.writeUInt8(bytes.3)
    }

    public var description: String {
        "\(bytes.0).\(bytes.1).\(bytes.2).\(bytes.3)"
    }
}

extension IPv4Address: Equatable {
    @inlinable
    public static func == (lhs: IPv4Address, rhs: IPv4Address) -> Bool {
        lhs.packed == rhs.packed
    }
}

extension IPv4Address: Hashable {
    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(packed)
    }
}

/// IPv6 address (inline storage, no heap allocation).
public struct IPv6Address: Sendable, CustomStringConvertible {
    /// Inline 16-byte storage as two UInt64s.
    public let hi: UInt64
    public let lo: UInt64

    @inlinable
    public init(hi: UInt64, lo: UInt64) {
        self.hi = hi
        self.lo = lo
    }

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
        self.hi = hiVal
        self.lo = loVal
    }

    @inlinable
    public init(buffer: UnsafeRawBufferPointer) {
        precondition(buffer.count >= 16, "Buffer too small for IPv6")
        let ptr = buffer.baseAddress!
        var hiVal: UInt64 = 0
        var loVal: UInt64 = 0
        for i in 0..<8 {
            hiVal = (hiVal << 8) | UInt64(ptr.load(fromByteOffset: i, as: UInt8.self))
        }
        for i in 8..<16 {
            loVal = (loVal << 8) | UInt64(ptr.load(fromByteOffset: i, as: UInt8.self))
        }
        self.hi = hiVal
        self.lo = loVal
    }

    public init?(string: String) {
        var expanded = string

        // Handle :: expansion
        if expanded.contains("::") {
            let parts = expanded.split(separator: ":", omittingEmptySubsequences: false)
            let nonEmpty = parts.filter { !$0.isEmpty }
            let needed = 8 - nonEmpty.count
            let replacement = Array(repeating: "0", count: needed).joined(separator: ":")
            expanded = expanded.replacingOccurrences(of: "::", with: ":\(replacement):")
            if expanded.hasPrefix(":") { expanded.removeFirst() }
            if expanded.hasSuffix(":") { expanded.removeLast() }
        }

        let parts = expanded.split(separator: ":")
        guard parts.count == 8 else { return nil }

        var hiVal: UInt64 = 0
        var loVal: UInt64 = 0

        for (i, part) in parts.enumerated() {
            guard let value = UInt16(part, radix: 16) else { return nil }
            if i < 4 {
                hiVal = (hiVal << 16) | UInt64(value)
            } else {
                loVal = (loVal << 16) | UInt64(value)
            }
        }

        self.hi = hiVal
        self.lo = loVal
    }

    /// Returns raw bytes as Data (for compatibility).
    @inlinable
    public var rawData: Data {
        var data = Data(count: 16)
        data.withUnsafeMutableBytes { ptr in
            var h = hi.bigEndian
            var l = lo.bigEndian
            withUnsafeBytes(of: &h) { ptr.copyMemory(from: $0) }
            withUnsafeBytes(of: &l) { (ptr.baseAddress! + 8).copyMemory(from: $0.baseAddress!, byteCount: 8) }
        }
        return data
    }

    /// Writes to a buffer without allocation.
    @inlinable
    public func write(to buffer: inout WriteBuffer) {
        // Write hi (8 bytes, big endian)
        for shift in stride(from: 56, through: 0, by: -8) {
            buffer.writeUInt8(UInt8((hi >> shift) & 0xFF))
        }
        // Write lo (8 bytes, big endian)
        for shift in stride(from: 56, through: 0, by: -8) {
            buffer.writeUInt8(UInt8((lo >> shift) & 0xFF))
        }
    }

    public var description: String {
        var parts: [String] = []
        for shift in stride(from: 48, through: 0, by: -16) {
            parts.append(String((hi >> shift) & 0xFFFF, radix: 16))
        }
        for shift in stride(from: 48, through: 0, by: -16) {
            parts.append(String((lo >> shift) & 0xFFFF, radix: 16))
        }
        return parts.joined(separator: ":")
    }
}

extension IPv6Address: Equatable {
    @inlinable
    public static func == (lhs: IPv6Address, rhs: IPv6Address) -> Bool {
        lhs.hi == rhs.hi && lhs.lo == rhs.lo
    }
}

extension IPv6Address: Hashable {
    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(hi)
        hasher.combine(lo)
    }
}
