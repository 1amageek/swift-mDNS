/// RFC 1035 DNS Specification Tests
///
/// Tests for DNS name encoding/decoding and compression per RFC 1035.
/// https://tools.ietf.org/html/rfc1035

import Testing
import Foundation
@testable import mDNS

@Suite("RFC 1035 - DNS Implementation and Specification")
struct RFC1035Tests {

    // MARK: - Section 2.3.4: Size limits

    @Test("Maximum label length is 63 octets")
    func maxLabelLength() throws {
        // Exactly 63 characters should work
        let label63 = String(repeating: "a", count: 63)
        let name63 = try DNSName("\(label63).local.")
        #expect(name63.labels[0].count == 63)

        // 64 characters should fail
        let label64 = String(repeating: "a", count: 64)
        #expect(throws: DNSError.self) {
            _ = try DNSName("\(label64).local.")
        }
    }

    @Test("Maximum name length is 255 octets")
    func maxNameLength() throws {
        // Create a name close to 255 bytes
        // Each label: 1 byte length + content
        // Final null byte: 1 byte
        // 3 labels of 60 chars each = 3 * (1 + 60) + 1 = 184 bytes - should work
        let label60 = String(repeating: "a", count: 60)
        let validName = try DNSName("\(label60).\(label60).\(label60).")
        #expect(validName.labels.count == 3)

        // Create a name exceeding 255 bytes
        // Label calculation: n * (1 + label_length) + 1 (final null)
        // 5 labels of 63 chars = 5 * 64 + 1 = 321 bytes - should fail
        let label63 = String(repeating: "b", count: 63)
        #expect(throws: DNSError.self) {
            _ = try DNSName("\(label63).\(label63).\(label63).\(label63).")
        }
    }

    // MARK: - Section 4.1.4: Message compression

    @Test("Decode simple compression pointer")
    func simpleCompressionPointer() throws {
        // Build a message with compression:
        // Offset 0: \x07example\x05local\x00 (14 bytes: 1+7+1+5+1=15, but actually 14 due to how it's structured)
        // Let's recalculate: 1(len)+7(example)+1(len)+5(local)+1(null) = 15 bytes
        // Offset 15: \x03www\xC0\x00 (pointer to offset 0)
        var data = Data()

        // First name: "example.local." - total 15 bytes
        data.append(7)                          // offset 0
        data.append(contentsOf: "example".utf8) // offset 1-7
        data.append(5)                          // offset 8
        data.append(contentsOf: "local".utf8)   // offset 9-13
        data.append(0)                          // offset 14 (null terminator)

        // Second name at offset 15: "www" + pointer to offset 0
        data.append(3)                          // offset 15
        data.append(contentsOf: "www".utf8)     // offset 16-18
        data.append(0xC0)                       // offset 19 - compression pointer marker
        data.append(0x00)                       // offset 20 - point to offset 0

        let (name, bytesConsumed) = try DNSName.decode(from: data, at: 15)

        #expect(name.labels == ["www", "example", "local"])
        #expect(bytesConsumed == 6)  // 1 + 3 + 2 (pointer)
    }

    @Test("Decode chained compression pointers")
    func chainedCompressionPointers() throws {
        // Build a message with chained compression:
        // Offset 0: \x05local\x00 (7 bytes: 1+5+1=7)
        // Offset 7: \x07example\xC0\x00 (10 bytes: 1+7+2=10, pointer to offset 0 "local")
        // Offset 17: \x03www\xC0\x07 (6 bytes: 1+3+2=6, pointer to offset 7 "example.local")
        var data = Data()

        // First name: "local." at offset 0
        data.append(5)                        // offset 0
        data.append(contentsOf: "local".utf8) // offset 1-5
        data.append(0)                        // offset 6 (null)

        // Second name: "example" + pointer to offset 0 ("local") at offset 7
        data.append(7)                          // offset 7
        data.append(contentsOf: "example".utf8) // offset 8-14
        data.append(0xC0)                       // offset 15
        data.append(0x00)                       // offset 16 - points to offset 0

        // Third name: "www" + pointer to offset 7 ("example.local") at offset 17
        data.append(3)                        // offset 17
        data.append(contentsOf: "www".utf8)   // offset 18-20
        data.append(0xC0)                     // offset 21
        data.append(0x07)                     // offset 22 - points to offset 7

        let (name, bytesConsumed) = try DNSName.decode(from: data, at: 17)

        #expect(name.labels == ["www", "example", "local"])
        #expect(bytesConsumed == 6)
    }

    @Test("Compression pointer loop detection")
    func compressionPointerLoop() throws {
        // Create a pointer that points to itself
        var data = Data()
        data.append(0xC0)  // Compression pointer marker
        data.append(0x00)  // Point to offset 0 (self-reference)

        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: data, at: 0)
        }
    }

    @Test("Mutual compression pointer loop detection")
    func mutualCompressionPointerLoop() throws {
        // Create two pointers that point to each other
        // Offset 0: pointer to offset 2
        // Offset 2: pointer to offset 0
        var data = Data()
        data.append(0xC0)
        data.append(0x02)  // Point to offset 2
        data.append(0xC0)
        data.append(0x00)  // Point to offset 0

        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: data, at: 0)
        }
    }

    @Test("Compression pointer to invalid offset throws error")
    func pointerToInvalidOffset() throws {
        // Pointer to offset beyond data - RFC 1035 requires valid offsets
        var data = Data()
        data.append(0xC0)
        data.append(0x10)  // Point to offset 16 (beyond 2-byte data)

        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: data, at: 0)
        }
    }

    // MARK: - Section 3.1: Name space definitions

    @Test("Root domain encoding")
    func rootDomainEncoding() throws {
        let root = try DNSName(".")
        #expect(root.isRoot)
        #expect(root.labels.isEmpty)

        let encoded = root.encode()
        #expect(encoded.count == 1)
        #expect(encoded[0] == 0)  // Single null byte
    }

    @Test("Root domain decoding")
    func rootDomainDecoding() throws {
        let data = Data([0x00])  // Single null byte = root
        let (name, bytesConsumed) = try DNSName.decode(from: data, at: 0)

        #expect(name.isRoot)
        #expect(name.labels.isEmpty)
        #expect(bytesConsumed == 1)
    }

    @Test("Empty labels in the middle of a name are rejected")
    func emptyLabelsInMiddle() throws {
        // RFC 1035: Empty labels only allowed at root (end of name)
        // Note: Use explicit String to avoid ExpressibleByStringLiteral
        let invalidName: String = "example..local."
        #expect(throws: DNSError.self) {
            _ = try DNSName(invalidName)
        }
    }

    @Test("DNS names are case-insensitive")
    func caseInsensitiveComparison() throws {
        let name1 = try DNSName("WWW.EXAMPLE.LOCAL.")
        let name2 = try DNSName("www.example.local.")
        let name3 = try DNSName("Www.Example.Local.")

        #expect(name1 == name2)
        #expect(name2 == name3)
        #expect(name1 == name3)
    }

    @Test("DNS name can be used in Set (Hashable)")
    func canBeUsedInSet() throws {
        let name1 = try DNSName("WWW.EXAMPLE.LOCAL.")
        let name2 = try DNSName("www.example.local.")
        let name3 = try DNSName("other.example.local.")

        // Verify hash is case-insensitive (Hashable contract: equal objects must have equal hashes)
        #expect(name1.hashValue == name2.hashValue, "Equal names must have equal hashes")

        // Verify Dictionary lookup works with case-different keys
        var dict: [DNSName: Int] = [:]
        dict[name1] = 1
        dict[name3] = 2

        #expect(dict[name2] == 1, "Case-different key should find same entry")
        #expect(dict[name1] == 1)
        #expect(dict[name3] == 2)

        // Verify Set correctly deduplicates case-different names
        var set: Set<DNSName> = [name1, name2, name3]
        #expect(set.count == 2, "name1 and name2 should be deduplicated")
    }

    // MARK: - Wire format encoding/decoding roundtrip

    @Test("Name encode/decode roundtrip")
    func nameRoundtrip() throws {
        let testNames = [
            "_http._tcp.local.",
            "my-service._printer._tcp.local.",
            "a.b.c.d.e.f.g.local.",
            "single.",
            ".",
        ]

        for nameStr in testNames {
            let original = try DNSName(nameStr)
            let encoded = original.encode()
            let (decoded, _) = try DNSName.decode(from: encoded, at: 0)

            #expect(original == decoded, "Roundtrip failed for: \(nameStr)")
        }
    }

    @Test("Label with special characters")
    func labelWithSpecialCharacters() throws {
        // DNS labels can contain hyphens and underscores
        let name = try DNSName("_my-service._tcp.local.")
        #expect(name.labels == ["_my-service", "_tcp", "local"])

        let encoded = name.encode()
        let (decoded, _) = try DNSName.decode(from: encoded, at: 0)
        #expect(decoded == name)
    }

    @Test("Label with digits")
    func labelWithDigits() throws {
        let name = try DNSName("host123.example.local.")
        #expect(name.labels == ["host123", "example", "local"])
    }

    // MARK: - Section 4.1: Message format

    @Test("DNS header is 12 bytes")
    func headerSize() throws {
        let message = DNSMessage.query(id: 0, questions: [])
        let encoded = message.encode()

        // Header is exactly 12 bytes
        #expect(encoded.count == 12)
    }

    @Test("Question count in header matches questions")
    func questionCount() throws {
        let q1 = DNSQuestion(name: try DNSName("a.local."), type: .a)
        let q2 = DNSQuestion(name: try DNSName("b.local."), type: .aaaa)
        let message = DNSMessage.query(id: 0, questions: [q1, q2])

        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.questions.count == 2)
    }

    @Test("Record counts in header match sections")
    func recordCounts() throws {
        let name = try DNSName("host.local.")
        let answer = DNSResourceRecord(
            name: name,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )
        let additional = DNSResourceRecord(
            name: name,
            type: .aaaa,
            ttl: 120,
            rdata: .aaaa(IPv6Address(hi: 0, lo: 1))
        )

        let message = DNSMessage.response(
            answers: [answer],
            additional: [additional]
        )

        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.answers.count == 1)
        #expect(decoded.additional.count == 1)
        #expect(decoded.authority.isEmpty)
    }
}
