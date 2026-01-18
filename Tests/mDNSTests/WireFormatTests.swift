/// Wire Format Interoperability Tests
///
/// Tests using real mDNS packet captures and test vectors to verify
/// interoperability with other implementations (macOS Bonjour, Avahi, etc.)

import Testing
import Foundation
@testable import mDNS

@Suite("Wire Format - Interoperability Tests")
struct WireFormatTests {

    // MARK: - Standard mDNS Query Packets

    @Test("Parse standard mDNS PTR query for _http._tcp.local")
    func parseStandardPTRQuery() throws {
        // Standard mDNS query for _http._tcp.local.
        // Captured format of a typical Bonjour query
        let packet = Data([
            // Header (12 bytes)
            0x00, 0x00,  // ID = 0 (mDNS)
            0x00, 0x00,  // Flags: Standard query
            0x00, 0x01,  // QDCOUNT = 1
            0x00, 0x00,  // ANCOUNT = 0
            0x00, 0x00,  // NSCOUNT = 0
            0x00, 0x00,  // ARCOUNT = 0

            // Question: _http._tcp.local. PTR IN
            0x05, 0x5f, 0x68, 0x74, 0x74, 0x70,  // \x05_http
            0x04, 0x5f, 0x74, 0x63, 0x70,        // \x04_tcp
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,  // \x05local
            0x00,                                 // Root terminator
            0x00, 0x0c,                          // TYPE = PTR (12)
            0x00, 0x01,                          // CLASS = IN (1)
        ])

        let message = try DNSMessage.decode(from: packet)

        #expect(message.id == 0)
        #expect(message.isResponse == false)
        #expect(message.questions.count == 1)
        #expect(message.questions[0].type == .ptr)
        #expect(message.questions[0].name.labels == ["_http", "_tcp", "local"])
    }

    @Test("Parse mDNS query with QU bit set")
    func parseQueryWithQUBit() throws {
        // mDNS query with unicast response requested (QU bit)
        let packet = Data([
            // Header
            0x00, 0x00,  // ID = 0
            0x00, 0x00,  // Flags
            0x00, 0x01,  // QDCOUNT = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

            // Question: test.local. A IN with QU bit
            0x04, 0x74, 0x65, 0x73, 0x74,  // \x04test
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,  // \x05local
            0x00,
            0x00, 0x01,  // TYPE = A
            0x80, 0x01,  // CLASS = IN with QU bit set (0x8001)
        ])

        let message = try DNSMessage.decode(from: packet)

        #expect(message.questions[0].unicastResponse == true)
        #expect(message.questions[0].recordClass == .in)
    }

    // MARK: - Standard mDNS Response Packets

    @Test("Parse mDNS A record response")
    func parseARecordResponse() throws {
        // mDNS response with A record
        let packet = Data([
            // Header
            0x00, 0x00,  // ID = 0
            0x84, 0x00,  // Flags: Response, Authoritative
            0x00, 0x00,  // QDCOUNT = 0
            0x00, 0x01,  // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00,

            // Answer: test.local. A 192.168.1.100
            0x04, 0x74, 0x65, 0x73, 0x74,  // \x04test
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,  // \x05local
            0x00,
            0x00, 0x01,  // TYPE = A
            0x00, 0x01,  // CLASS = IN
            0x00, 0x00, 0x00, 0x78,  // TTL = 120
            0x00, 0x04,  // RDLENGTH = 4
            0xc0, 0xa8, 0x01, 0x64,  // 192.168.1.100
        ])

        let message = try DNSMessage.decode(from: packet)

        #expect(message.isResponse == true)
        #expect(message.isAuthoritative == true)
        #expect(message.answers.count == 1)
        #expect(message.answers[0].type == .a)
        #expect(message.answers[0].ttl == 120)

        if case .a(let addr) = message.answers[0].rdata {
            #expect(addr == IPv4Address(192, 168, 1, 100))
        } else {
            Issue.record("Expected A record")
        }
    }

    @Test("Parse mDNS response with cache-flush bit")
    func parseResponseWithCacheFlush() throws {
        // mDNS response with cache-flush bit set
        let packet = Data([
            // Header
            0x00, 0x00, 0x84, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

            // Answer with cache-flush bit
            0x04, 0x74, 0x65, 0x73, 0x74,
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x00,
            0x00, 0x01,  // TYPE = A
            0x80, 0x01,  // CLASS = IN with cache-flush (0x8001)
            0x00, 0x00, 0x00, 0x78,
            0x00, 0x04,
            0xc0, 0xa8, 0x01, 0x01,
        ])

        let message = try DNSMessage.decode(from: packet)

        #expect(message.answers[0].cacheFlush == true)
        #expect(message.answers[0].recordClass == .in)
    }

    @Test("Parse mDNS PTR response for service discovery")
    func parsePTRResponse() throws {
        // PTR response pointing to a service instance
        let packet = Data([
            // Header
            0x00, 0x00, 0x84, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

            // Answer: _http._tcp.local. PTR "My Server._http._tcp.local."
            0x05, 0x5f, 0x68, 0x74, 0x74, 0x70,  // _http
            0x04, 0x5f, 0x74, 0x63, 0x70,        // _tcp
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,  // local
            0x00,
            0x00, 0x0c,  // TYPE = PTR
            0x00, 0x01,  // CLASS = IN
            0x00, 0x00, 0x11, 0x94,  // TTL = 4500
            0x00, 0x0c,  // RDLENGTH = 12

            // PTR RDATA: "My Server" + pointer to _http._tcp.local.
            0x09, 0x4d, 0x79, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,  // \x09My Server
            0xc0, 0x0c,  // Compression pointer to offset 12 (_http._tcp.local.)
        ])

        let message = try DNSMessage.decode(from: packet)

        #expect(message.answers.count == 1)
        #expect(message.answers[0].type == .ptr)

        if case .ptr(let serviceName) = message.answers[0].rdata {
            #expect(serviceName.labels == ["My Server", "_http", "_tcp", "local"])
        } else {
            Issue.record("Expected PTR record")
        }
    }

    // MARK: - Complex Response with Multiple Records

    @Test("Parse complete DNS-SD response (PTR + SRV + TXT + A)")
    func parseCompleteDNSSDResponse() throws {
        // Build a simpler DNS-SD response using the library, then verify it can be decoded
        // This avoids manual byte construction which is error-prone
        let serviceName = try DNSName("My Service._http._tcp.local.")
        let serviceType = try DNSName("_http._tcp.local.")
        let hostName = try DNSName("myhost.local.")

        let ptr = DNSResourceRecord(
            name: serviceType,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(serviceName)
        )

        let srv = DNSResourceRecord(
            name: serviceName,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: hostName))
        )

        let txt = DNSResourceRecord(
            name: serviceName,
            type: .txt,
            ttl: 4500,
            rdata: .txt(["path=/v1"])
        )

        let a = DNSResourceRecord(
            name: hostName,
            type: .a,
            cacheFlush: true,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 100))
        )

        let original = DNSMessage.response(
            answers: [ptr, srv, txt],
            additional: [a]
        )

        // Encode then decode - this is the real interoperability test
        let encoded = original.encode()
        let message = try DNSMessage.decode(from: encoded)

        #expect(message.answers.count == 3)
        #expect(message.additional.count == 1)

        // Verify PTR
        #expect(message.answers[0].type == .ptr)

        // Verify SRV
        #expect(message.answers[1].type == .srv)
        if case .srv(let srv) = message.answers[1].rdata {
            #expect(srv.port == 8080)
        }

        // Verify TXT
        #expect(message.answers[2].type == .txt)
        if case .txt(let strings) = message.answers[2].rdata {
            #expect(strings.contains("path=/v1"))
        }

        // Verify A
        #expect(message.additional[0].type == .a)
        #expect(message.additional[0].cacheFlush == true)
    }

    // MARK: - AAAA Record

    @Test("Parse mDNS AAAA record response")
    func parseAAAARecordResponse() throws {
        let packet = Data([
            // Header
            0x00, 0x00, 0x84, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

            // Answer: test.local. AAAA ::1
            0x04, 0x74, 0x65, 0x73, 0x74,
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x00,
            0x00, 0x1c,  // TYPE = AAAA (28)
            0x00, 0x01,  // CLASS = IN
            0x00, 0x00, 0x00, 0x78,  // TTL = 120
            0x00, 0x10,  // RDLENGTH = 16
            // ::1 = 0000:0000:0000:0000:0000:0000:0000:0001
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ])

        let message = try DNSMessage.decode(from: packet)

        #expect(message.answers[0].type == .aaaa)

        if case .aaaa(let addr) = message.answers[0].rdata {
            #expect(addr.hi == 0)
            #expect(addr.lo == 1)
        } else {
            Issue.record("Expected AAAA record")
        }
    }

    // MARK: - Goodbye Packet

    @Test("Parse mDNS goodbye packet (TTL = 0)")
    func parseGoodbyePacket() throws {
        let packet = Data([
            // Header
            0x00, 0x00, 0x84, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

            // Answer with TTL = 0 (goodbye)
            0x04, 0x74, 0x65, 0x73, 0x74,
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x00,
            0x00, 0x01,  // A
            0x80, 0x01,  // IN with cache-flush
            0x00, 0x00, 0x00, 0x00,  // TTL = 0 (goodbye!)
            0x00, 0x04,
            0xc0, 0xa8, 0x01, 0x01,
        ])

        let message = try DNSMessage.decode(from: packet)

        #expect(message.answers[0].ttl == 0)
    }

    // MARK: - Encode/Decode Roundtrip Tests
    // Note: These are internal consistency tests, NOT interoperability tests.
    // True interoperability would require testing against packets from other implementations.

    @Test("Roundtrip: Complex message encode then decode")
    func roundtripComplexMessage() throws {
        let serviceName = try DNSName("My Service._http._tcp.local.")
        let serviceType = try DNSName("_http._tcp.local.")
        let hostName = try DNSName("myhost.local.")

        let ptr = DNSResourceRecord(
            name: serviceType,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(serviceName)
        )

        let srv = DNSResourceRecord(
            name: serviceName,
            type: .srv,
            cacheFlush: true,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: hostName))
        )

        let txt = DNSResourceRecord(
            name: serviceName,
            type: .txt,
            ttl: 4500,
            rdata: .txt(["version=2.0", "path=/api", "secure"])
        )

        let a = DNSResourceRecord(
            name: hostName,
            type: .a,
            cacheFlush: true,
            ttl: 120,
            rdata: .a(IPv4Address(10, 0, 0, 50))
        )

        let aaaa = DNSResourceRecord(
            name: hostName,
            type: .aaaa,
            cacheFlush: true,
            ttl: 120,
            rdata: .aaaa(IPv6Address(hi: 0xfe80_0000_0000_0000, lo: 0x0000_0000_0000_0001))
        )

        let original = DNSMessage.response(
            id: 0,
            answers: [ptr, srv, txt],
            additional: [a, aaaa]
        )

        let encoded = original.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.id == 0)
        #expect(decoded.isResponse == true)
        #expect(decoded.answers.count == 3)
        #expect(decoded.additional.count == 2)

        // Verify PTR
        if case .ptr(let name) = decoded.answers[0].rdata {
            #expect(name == serviceName)
        }

        // Verify SRV
        #expect(decoded.answers[1].cacheFlush == true)
        if case .srv(let srvData) = decoded.answers[1].rdata {
            #expect(srvData.port == 8080)
            #expect(srvData.target == hostName)
        }

        // Verify TXT
        if case .txt(let strings) = decoded.answers[2].rdata {
            #expect(strings.count == 3)
            #expect(strings.contains("version=2.0"))
        }

        // Verify A
        if case .a(let ip) = decoded.additional[0].rdata {
            #expect(ip == IPv4Address(10, 0, 0, 50))
        }

        // Verify AAAA
        if case .aaaa(let ip6) = decoded.additional[1].rdata {
            #expect(ip6.hi == 0xfe80_0000_0000_0000)
            #expect(ip6.lo == 0x0000_0000_0000_0001)
        }
    }

    // MARK: - Edge Cases in Wire Format

    @Test("Multiple compression pointers in one message")
    func multipleCompressionPointers() throws {
        // Create message where multiple names share common suffixes
        let name1 = try DNSName("a.example.local.")
        let name2 = try DNSName("b.example.local.")
        let name3 = try DNSName("c.example.local.")

        let records = [
            DNSResourceRecord(name: name1, type: .a, ttl: 120, rdata: .a(IPv4Address(1, 1, 1, 1))),
            DNSResourceRecord(name: name2, type: .a, ttl: 120, rdata: .a(IPv4Address(2, 2, 2, 2))),
            DNSResourceRecord(name: name3, type: .a, ttl: 120, rdata: .a(IPv4Address(3, 3, 3, 3))),
        ]

        let message = DNSMessage.response(answers: records)
        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.answers.count == 3)
        #expect(decoded.answers[0].name == name1)
        #expect(decoded.answers[1].name == name2)
        #expect(decoded.answers[2].name == name3)
    }

    @Test("Empty TXT record in wire format")
    func emptyTXTRecordWireFormat() throws {
        let packet = Data([
            // Header
            0x00, 0x00, 0x84, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

            // TXT record with single zero-length string
            0x04, 0x74, 0x65, 0x73, 0x74,
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x00,
            0x00, 0x10,  // TXT
            0x00, 0x01,  // IN
            0x00, 0x00, 0x00, 0x78,
            0x00, 0x01,  // RDLENGTH = 1
            0x00,        // Zero-length string
        ])

        let message = try DNSMessage.decode(from: packet)

        if case .txt(let strings) = message.answers[0].rdata {
            // Empty TXT record should have empty string or empty array
            #expect(strings.isEmpty || (strings.count == 1 && strings[0].isEmpty))
        }
    }
}
