/// DNS Message Format
///
/// Implements DNS message encoding/decoding per RFC 1035 Section 4.

/// A DNS message.
///
/// DNS messages consist of a header followed by four sections:
/// - Questions: Queries being made
/// - Answers: Resource records answering the questions
/// - Authority: Resource records pointing to authoritative name servers
/// - Additional: Resource records with additional information
public struct DNSMessage: Sendable, Hashable {

    // MARK: - Header Fields

    /// Message ID for matching requests/responses.
    public var id: UInt16

    /// Whether this is a response (true) or query (false).
    public var isResponse: Bool

    /// Operation code.
    public var opcode: DNSOpcode

    /// Authoritative answer flag.
    public var isAuthoritative: Bool

    /// Message was truncated.
    public var isTruncated: Bool

    /// Recursion desired.
    public var recursionDesired: Bool

    /// Recursion available.
    public var recursionAvailable: Bool

    /// Response code.
    public var responseCode: DNSResponseCode

    // MARK: - Sections

    /// Questions section.
    public var questions: [DNSQuestion]

    /// Answers section.
    public var answers: [DNSResourceRecord]

    /// Authority section.
    public var authority: [DNSResourceRecord]

    /// Additional section.
    public var additional: [DNSResourceRecord]

    // MARK: - Initialization

    public init(
        id: UInt16 = 0,
        isResponse: Bool = false,
        opcode: DNSOpcode = .query,
        isAuthoritative: Bool = false,
        isTruncated: Bool = false,
        recursionDesired: Bool = false,
        recursionAvailable: Bool = false,
        responseCode: DNSResponseCode = .noError,
        questions: [DNSQuestion] = [],
        answers: [DNSResourceRecord] = [],
        authority: [DNSResourceRecord] = [],
        additional: [DNSResourceRecord] = []
    ) {
        self.id = id
        self.isResponse = isResponse
        self.opcode = opcode
        self.isAuthoritative = isAuthoritative
        self.isTruncated = isTruncated
        self.recursionDesired = recursionDesired
        self.recursionAvailable = recursionAvailable
        self.responseCode = responseCode
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional
    }

    // MARK: - Factory Methods

    /// Creates a query message.
    public static func query(
        id: UInt16 = 0,
        questions: [DNSQuestion],
        recursionDesired: Bool = false
    ) -> DNSMessage {
        DNSMessage(
            id: id,
            isResponse: false,
            recursionDesired: recursionDesired,
            questions: questions
        )
    }

    /// Creates a response message.
    public static func response(
        id: UInt16 = 0,
        questions: [DNSQuestion] = [],
        answers: [DNSResourceRecord],
        authority: [DNSResourceRecord] = [],
        additional: [DNSResourceRecord] = [],
        isAuthoritative: Bool = true
    ) -> DNSMessage {
        DNSMessage(
            id: id,
            isResponse: true,
            isAuthoritative: isAuthoritative,
            answers: answers,
            authority: authority,
            additional: additional
        )
    }

    // MARK: - Encoding

    /// Encodes the message to wire format.
    @inlinable
    public func encode() -> [UInt8] {
        var buffer = WriteBuffer(capacity: 512)
        encode(to: &buffer)
        return buffer.toArray()
    }

    /// Encodes the message into a write buffer with name compression.
    @inlinable
    public func encode(to buffer: inout WriteBuffer) {
        // Header (12 bytes)
        // ID
        buffer.writeUInt16(id)

        // Flags
        var flags: UInt16 = 0
        if isResponse { flags |= 0x8000 }
        flags |= UInt16(opcode.rawValue) << 11
        if isAuthoritative { flags |= 0x0400 }
        if isTruncated { flags |= 0x0200 }
        if recursionDesired { flags |= 0x0100 }
        if recursionAvailable { flags |= 0x0080 }
        flags |= UInt16(responseCode.rawValue)
        buffer.writeUInt16(flags)

        // Counts
        buffer.writeUInt16(UInt16(questions.count))
        buffer.writeUInt16(UInt16(answers.count))
        buffer.writeUInt16(UInt16(authority.count))
        buffer.writeUInt16(UInt16(additional.count))

        // Questions
        for question in questions {
            question.encode(to: &buffer)
        }

        // Answers
        for answer in answers {
            answer.encode(to: &buffer)
        }

        // Authority
        for auth in authority {
            auth.encode(to: &buffer)
        }

        // Additional
        for add in additional {
            add.encode(to: &buffer)
        }
    }

    // MARK: - Decoding

    /// Decodes a message from wire format.
    ///
    /// Reads via random-access indexing into `bytes` (names may use compression
    /// pointers), with typed throws and full bounds checking.
    @inlinable
    public static func decode(from bytes: [UInt8]) throws(DNSError) -> DNSMessage {
        guard bytes.count >= 12 else {
            throw DNSError.invalidMessage("Message too short: \(bytes.count) bytes")
        }

        // Header
        let id = ByteOps.readUInt16(from: bytes, at: 0)
        let flags = ByteOps.readUInt16(from: bytes, at: 2)

        let isResponse = (flags & 0x8000) != 0
        let opcodeValue = UInt8((flags >> 11) & 0x0F)
        // Preserve unrecognized opcodes as `.unknown(...)` instead of defaulting.
        let opcode = DNSOpcode(rawValue: opcodeValue)
        let isAuthoritative = (flags & 0x0400) != 0
        let isTruncated = (flags & 0x0200) != 0
        let recursionDesired = (flags & 0x0100) != 0
        let recursionAvailable = (flags & 0x0080) != 0
        let responseCodeValue = UInt8(flags & 0x000F)
        // Preserve unrecognized response codes as `.unknown(...)` instead of defaulting.
        let responseCode = DNSResponseCode(rawValue: responseCodeValue)

        let qdCount = Int(ByteOps.readUInt16(from: bytes, at: 4))
        let anCount = Int(ByteOps.readUInt16(from: bytes, at: 6))
        let nsCount = Int(ByteOps.readUInt16(from: bytes, at: 8))
        let arCount = Int(ByteOps.readUInt16(from: bytes, at: 10))

        var offset = 12

        // Questions
        var questions: [DNSQuestion] = []
        questions.reserveCapacity(qdCount)
        for _ in 0..<qdCount {
            let (question, bytesConsumed) = try DNSQuestion.decode(from: bytes, at: offset)
            questions.append(question)
            offset += bytesConsumed
        }

        // Answers
        var answers: [DNSResourceRecord] = []
        answers.reserveCapacity(anCount)
        for _ in 0..<anCount {
            let (record, bytesConsumed) = try DNSResourceRecord.decode(from: bytes, at: offset)
            answers.append(record)
            offset += bytesConsumed
        }

        // Authority
        var authority: [DNSResourceRecord] = []
        authority.reserveCapacity(nsCount)
        for _ in 0..<nsCount {
            let (record, bytesConsumed) = try DNSResourceRecord.decode(from: bytes, at: offset)
            authority.append(record)
            offset += bytesConsumed
        }

        // Additional
        var additional: [DNSResourceRecord] = []
        additional.reserveCapacity(arCount)
        for _ in 0..<arCount {
            let (record, bytesConsumed) = try DNSResourceRecord.decode(from: bytes, at: offset)
            additional.append(record)
            offset += bytesConsumed
        }

        return DNSMessage(
            id: id,
            isResponse: isResponse,
            opcode: opcode,
            isAuthoritative: isAuthoritative,
            isTruncated: isTruncated,
            recursionDesired: recursionDesired,
            recursionAvailable: recursionAvailable,
            responseCode: responseCode,
            questions: questions,
            answers: answers,
            authority: authority,
            additional: additional
        )
    }
}

// MARK: - mDNS Message Helpers

extension DNSMessage {

    /// Creates an mDNS query for a service type.
    /// - Parameter serviceType: The service type (e.g., "_http._tcp.local.")
    /// - Returns: An mDNS query message
    public static func mdnsQuery(for serviceType: String) throws(DNSError) -> DNSMessage {
        let name = try DNSName(serviceType)
        let question = DNSQuestion(
            name: name,
            type: .ptr,
            recordClass: .in,
            unicastResponse: false
        )
        return DNSMessage.query(id: 0, questions: [question])
    }

    /// Creates an mDNS query for multiple types on a name.
    public static func mdnsQuery(
        name: DNSName,
        types: [DNSRecordType],
        unicastResponse: Bool = false
    ) -> DNSMessage {
        let questions = types.map { type in
            DNSQuestion(
                name: name,
                type: type,
                recordClass: .in,
                unicastResponse: unicastResponse
            )
        }
        return DNSMessage.query(id: 0, questions: questions)
    }

    /// Whether this message is an mDNS message (ID is 0 for mDNS).
    public var isMDNS: Bool {
        id == 0
    }

    /// Creates a goodbye message (TTL=0) for the given records.
    public static func mdnsGoodbye(records: [DNSResourceRecord]) -> DNSMessage {
        let goodbyeRecords = records.map { record in
            DNSResourceRecord(
                name: record.name,
                type: record.type,
                recordClass: record.recordClass,
                cacheFlush: record.cacheFlush,
                ttl: mdnsGoodbyeTTL,
                rdata: record.rdata
            )
        }
        return DNSMessage.response(
            id: 0,
            answers: goodbyeRecords,
            isAuthoritative: true
        )
    }
}

// MARK: - Debug Description

extension DNSMessage: CustomStringConvertible {
    public var description: String {
        var lines: [String] = []

        let type = isResponse ? "Response" : "Query"
        lines.append("DNSMessage(\(type), id=\(id))")

        if !questions.isEmpty {
            lines.append("  Questions:")
            for q in questions {
                lines.append("    \(q.name) \(q.type) \(q.recordClass)")
            }
        }

        if !answers.isEmpty {
            lines.append("  Answers:")
            for a in answers {
                lines.append("    \(a.name) \(a.type) TTL=\(a.ttl) \(a.rdata)")
            }
        }

        if !authority.isEmpty {
            lines.append("  Authority:")
            for a in authority {
                lines.append("    \(a.name) \(a.type) TTL=\(a.ttl)")
            }
        }

        if !additional.isEmpty {
            lines.append("  Additional:")
            for a in additional {
                lines.append("    \(a.name) \(a.type) TTL=\(a.ttl)")
            }
        }

        return lines.joined(separator: "\n")
    }
}
