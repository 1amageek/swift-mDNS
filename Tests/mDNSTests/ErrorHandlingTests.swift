/// Error Handling Tests
///
/// Tests for proper error handling of malformed DNS messages.

import Testing
import Foundation
@testable import mDNS

@Suite("Error Handling - Malformed Message Detection")
struct ErrorHandlingTests {

    // MARK: - Truncated Header

    @Test("Truncated header (less than 12 bytes)")
    func truncatedHeader() throws {
        let shortData = Data([0x00, 0x00, 0x00, 0x00])  // Only 4 bytes

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: shortData)
        }
    }

    @Test("Empty data throws")
    func emptyData() throws {
        let emptyData = Data()

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: emptyData)
        }
    }

    @Test("Exactly 12 bytes (header only, no questions)")
    func headerOnly() throws {
        // Valid header with 0 questions, 0 answers, etc.
        var data = Data()
        data.append(contentsOf: [0x00, 0x00])  // ID
        data.append(contentsOf: [0x00, 0x00])  // Flags
        data.append(contentsOf: [0x00, 0x00])  // QDCOUNT = 0
        data.append(contentsOf: [0x00, 0x00])  // ANCOUNT = 0
        data.append(contentsOf: [0x00, 0x00])  // NSCOUNT = 0
        data.append(contentsOf: [0x00, 0x00])  // ARCOUNT = 0

        let message = try DNSMessage.decode(from: data)
        #expect(message.questions.isEmpty)
        #expect(message.answers.isEmpty)
    }

    // MARK: - Truncated Names

    @Test("Truncated name label")
    func truncatedNameLabel() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])  // 1 question
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        // Question with truncated name
        data.append(5)  // Label length = 5
        data.append(contentsOf: "abc".utf8)  // Only 3 bytes, missing 2

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Name without terminator")
    func nameWithoutTerminator() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])  // 1 question
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        // Question with name but no null terminator
        data.append(3)
        data.append(contentsOf: "www".utf8)
        // Missing null terminator and rest of question

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Truncated compression pointer")
    func truncatedCompressionPointer() throws {
        var data = Data()
        data.append(0xC0)  // Compression pointer marker
        // Missing second byte of pointer

        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: data, at: 0)
        }
    }

    // MARK: - Truncated Questions

    @Test("Truncated question (missing type)")
    func truncatedQuestionMissingType() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])  // 1 question
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        // Question with name but no type/class
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)  // Name terminator
        // Missing TYPE and CLASS fields

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Truncated question (missing class)")
    func truncatedQuestionMissingClass() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])  // 1 question
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        // Question with name and type but no class
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)  // Name terminator
        data.append(contentsOf: [0x00, 0x01])  // TYPE = A
        // Missing CLASS field

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    // MARK: - Truncated Resource Records

    @Test("Truncated resource record (missing TTL)")
    func truncatedRecordMissingTTL() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x84, 0x00])  // Response
        data.append(contentsOf: [0x00, 0x00])  // 0 questions
        data.append(contentsOf: [0x00, 0x01])  // 1 answer
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // Answer with name, type, class but no TTL
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)
        data.append(contentsOf: [0x00, 0x01])  // TYPE = A
        data.append(contentsOf: [0x00, 0x01])  // CLASS = IN
        // Missing TTL and RDATA

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Truncated resource record (missing RDATA)")
    func truncatedRecordMissingRDATA() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x84, 0x00])  // Response
        data.append(contentsOf: [0x00, 0x00])  // 0 questions
        data.append(contentsOf: [0x00, 0x01])  // 1 answer
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // Answer with header but RDLENGTH says 4 bytes, only 2 present
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)
        data.append(contentsOf: [0x00, 0x01])  // TYPE = A
        data.append(contentsOf: [0x00, 0x01])  // CLASS = IN
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x78])  // TTL = 120
        data.append(contentsOf: [0x00, 0x04])  // RDLENGTH = 4
        data.append(contentsOf: [0xC0, 0xA8])  // Only 2 bytes of IP

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    // MARK: - Invalid Record Data

    @Test("Invalid A record length (not 4 bytes)")
    func invalidARecordLength() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x84, 0x00])
        data.append(contentsOf: [0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // A record with wrong RDATA length (5 instead of 4)
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)
        data.append(contentsOf: [0x00, 0x01])  // TYPE = A
        data.append(contentsOf: [0x00, 0x01])  // CLASS = IN
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x78])  // TTL
        data.append(contentsOf: [0x00, 0x05])  // RDLENGTH = 5 (wrong!)
        data.append(contentsOf: [0xC0, 0xA8, 0x01, 0x01, 0x00])  // 5 bytes

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Invalid AAAA record length (not 16 bytes)")
    func invalidAAAARecordLength() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x84, 0x00])
        data.append(contentsOf: [0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // AAAA record with wrong RDATA length (8 instead of 16)
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)
        data.append(contentsOf: [0x00, 0x1C])  // TYPE = AAAA (28)
        data.append(contentsOf: [0x00, 0x01])  // CLASS = IN
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x78])  // TTL
        data.append(contentsOf: [0x00, 0x08])  // RDLENGTH = 8 (wrong!)
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Truncated TXT record string")
    func truncatedTXTString() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x84, 0x00])
        data.append(contentsOf: [0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // TXT record with string length > available data
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)
        data.append(contentsOf: [0x00, 0x10])  // TYPE = TXT
        data.append(contentsOf: [0x00, 0x01])  // CLASS = IN
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x78])  // TTL
        data.append(contentsOf: [0x00, 0x05])  // RDLENGTH = 5
        data.append(10)  // String length = 10, but only 4 bytes follow
        data.append(contentsOf: "test".utf8)

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Truncated SRV record")
    func truncatedSRVRecord() throws {
        var data = Data()
        // Header
        data.append(contentsOf: [0x00, 0x00, 0x84, 0x00])
        data.append(contentsOf: [0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // SRV record with truncated data
        data.append(3)
        data.append(contentsOf: "srv".utf8)
        data.append(0)
        data.append(contentsOf: [0x00, 0x21])  // TYPE = SRV (33)
        data.append(contentsOf: [0x00, 0x01])  // CLASS = IN
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x78])  // TTL
        data.append(contentsOf: [0x00, 0x10])  // RDLENGTH = 16
        // Only priority (2 bytes), missing weight, port, target
        data.append(contentsOf: [0x00, 0x0A])

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    // MARK: - Invalid Label Length

    @Test("Label length exceeds 63")
    func labelLengthExceeds63() throws {
        var data = Data()
        data.append(64)  // Invalid label length (max is 63)
        // This should fail even without the label content

        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: data, at: 0)
        }
    }

    @Test("Reserved label type (01xxxxxx)")
    func reservedLabelType() throws {
        // Label types 01xxxxxx (0x40-0x7F) and 10xxxxxx (0x80-0xBF) are reserved per RFC 1035
        var data = Data()
        data.append(0x40)  // 01000000 - reserved extended label type

        // Implementation explicitly detects reserved label types
        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: data, at: 0)
        }
    }

    @Test("Reserved label type (10xxxxxx)")
    func reservedLabelType10() throws {
        // 10xxxxxx (0x80-0xBF) is reserved for future use per RFC 1035
        var data = Data()
        data.append(0x80)  // 10000000 - reserved

        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: data, at: 0)
        }
    }

    // MARK: - Count Mismatch

    @Test("Fewer questions than QDCOUNT")
    func fewerQuestionsThanCount() throws {
        var data = Data()
        // Header says 2 questions, but only 1 follows
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x00, 0x02])  // QDCOUNT = 2
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        // Only 1 question
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)
        data.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Fewer answers than ANCOUNT")
    func fewerAnswersThanCount() throws {
        var data = Data()
        // Header says 2 answers, but only 1 follows
        data.append(contentsOf: [0x00, 0x00, 0x84, 0x00])
        data.append(contentsOf: [0x00, 0x00])  // 0 questions
        data.append(contentsOf: [0x00, 0x02])  // ANCOUNT = 2
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // Only 1 answer
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)
        data.append(contentsOf: [0x00, 0x01])  // A
        data.append(contentsOf: [0x00, 0x01])  // IN
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x78])  // TTL
        data.append(contentsOf: [0x00, 0x04])  // RDLENGTH
        data.append(contentsOf: [192, 168, 1, 1])  // IP

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }
}
