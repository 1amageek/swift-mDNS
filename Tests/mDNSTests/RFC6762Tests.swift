/// RFC 6762 Multicast DNS Tests
///
/// Tests for mDNS-specific behavior per RFC 6762.
/// https://tools.ietf.org/html/rfc6762

import Testing
import Foundation
@testable import mDNS

@Suite("RFC 6762 - Multicast DNS")
struct RFC6762Tests {

    // MARK: - Section 6: mDNS Message ID

    @Test("mDNS queries must have ID = 0")
    func mdnsQueryIdMustBeZero() throws {
        let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
        #expect(query.id == 0)
    }

    @Test("mDNS responses must have ID = 0")
    func mdnsResponseIdMustBeZero() throws {
        let name = try DNSName("host.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )
        let response = DNSMessage.response(id: 0, answers: [record])

        #expect(response.id == 0)
    }

    @Test("isMDNS property checks ID is 0")
    func isMDNSProperty() throws {
        let mdnsMessage = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
        #expect(mdnsMessage.isMDNS == true)

        let dnsMessage = DNSMessage.query(id: 1234, questions: [])
        #expect(dnsMessage.isMDNS == false)
    }

    // MARK: - Section 5.4: mDNS Addresses and Port

    @Test("mDNS IPv4 multicast address is 224.0.0.251")
    func checkMdnsIPv4Address() {
        #expect(mDNS.mdnsIPv4Address == "224.0.0.251")
    }

    @Test("mDNS IPv6 multicast address is ff02::fb")
    func checkMdnsIPv6Address() {
        #expect(mDNS.mdnsIPv6Address == "ff02::fb")
    }

    @Test("mDNS port is 5353")
    func checkMdnsPort() {
        #expect(mDNS.mdnsPort == 5353)
    }

    // MARK: - Section 10.2: Cache-Flush Bit

    @Test("Cache-flush bit position is high bit of class field")
    func cacheFlushBitPosition() throws {
        let name = try DNSName("host.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            recordClass: .in,
            cacheFlush: true,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )

        let encoded = record.encode()

        // Find the class field (after name, type)
        // Name: 4 + 1 + 5 + 1 + 1 = 12 bytes (\x04host\x05local\x00)
        // Type: 2 bytes
        // Class: 2 bytes at offset 14
        let nameLength = 12  // \x04host\x05local\x00
        let classOffset = nameLength + 2  // After type
        let classValue = UInt16(encoded[classOffset]) << 8 | UInt16(encoded[classOffset + 1])

        // Cache-flush bit should be set (0x8001 = IN class with cache-flush)
        #expect((classValue & 0x8000) != 0, "Cache-flush bit should be set")
        #expect((classValue & 0x7FFF) == 1, "Class should be IN (1)")
    }

    @Test("Cache-flush bit is decoded correctly")
    func cacheFlushBitDecoding() throws {
        let name = try DNSName("host.local.")
        let original = DNSResourceRecord(
            name: name,
            type: .a,
            cacheFlush: true,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )

        let encoded = original.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        #expect(decoded.cacheFlush == true)
        #expect(decoded.recordClass == .in)
    }

    @Test("Record without cache-flush bit")
    func recordWithoutCacheFlush() throws {
        let name = try DNSName("host.local.")
        let original = DNSResourceRecord(
            name: name,
            type: .a,
            cacheFlush: false,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )

        let encoded = original.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        #expect(decoded.cacheFlush == false)
    }

    // MARK: - Section 5.4: QU Bit (Unicast Response)

    @Test("QU bit position is high bit of question class field")
    func quBitPosition() throws {
        let name = try DNSName("_http._tcp.local.")
        let question = DNSQuestion(
            name: name,
            type: .ptr,
            recordClass: .in,
            unicastResponse: true
        )

        let encoded = question.encode()

        // Name: 5 + 1 + 4 + 1 + 5 + 1 + 1 = 18 bytes (\x05_http\x04_tcp\x05local\x00)
        // Type: 2 bytes
        // Class: 2 bytes at offset 20
        let nameLength = 18
        let classOffset = nameLength + 2
        let classValue = UInt16(encoded[classOffset]) << 8 | UInt16(encoded[classOffset + 1])

        // QU bit should be set (0x8001)
        #expect((classValue & 0x8000) != 0, "QU bit should be set")
    }

    @Test("QU bit is decoded correctly")
    func quBitDecoding() throws {
        let name = try DNSName("_http._tcp.local.")
        let original = DNSQuestion(
            name: name,
            type: .ptr,
            unicastResponse: true
        )

        let encoded = original.encode()
        let (decoded, _) = try DNSQuestion.decode(from: encoded, at: 0)

        #expect(decoded.unicastResponse == true)
    }

    // MARK: - Section 10.1: Goodbye Packets (TTL = 0)

    @Test("Goodbye message has TTL = 0")
    func goodbyeMessageTTL() throws {
        let name = try DNSName("My Service._http._tcp.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(name)
        )

        let goodbye = DNSMessage.mdnsGoodbye(records: [record])

        #expect(goodbye.answers.count == 1)
        #expect(goodbye.answers[0].ttl == 0)
    }

    @Test("Goodbye message is a response")
    func goodbyeMessageIsResponse() throws {
        let name = try DNSName("host.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )

        let goodbye = DNSMessage.mdnsGoodbye(records: [record])

        #expect(goodbye.isResponse == true)
        #expect(goodbye.id == 0)
    }

    @Test("Goodbye message preserves record data")
    func goodbyeMessagePreservesData() throws {
        let name = try DNSName("host.local.")
        let ip = IPv4Address(192, 168, 1, 100)
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            cacheFlush: true,
            ttl: 120,
            rdata: .a(ip)
        )

        let goodbye = DNSMessage.mdnsGoodbye(records: [record])
        let goodbyeRecord = goodbye.answers[0]

        #expect(goodbyeRecord.name == name)
        #expect(goodbyeRecord.type == .a)
        #expect(goodbyeRecord.cacheFlush == true)
        #expect(goodbyeRecord.ttl == 0)

        if case .a(let addr) = goodbyeRecord.rdata {
            #expect(addr == ip)
        } else {
            Issue.record("Expected A record")
        }
    }

    @Test("Parse goodbye message (TTL = 0)")
    func parseGoodbyeMessage() throws {
        let name = try DNSName("host.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            ttl: 0,  // Goodbye
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )
        let message = DNSMessage.response(id: 0, answers: [record])

        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.answers[0].ttl == 0)
    }

    // MARK: - Section 18.12: mDNS Default TTL

    @Test("mDNS default TTL constant")
    func checkMdnsDefaultTTL() {
        #expect(mDNS.mdnsDefaultTTL == 120)
    }

    @Test("mDNS goodbye TTL constant")
    func checkMdnsGoodbyeTTL() {
        #expect(mDNS.mdnsGoodbyeTTL == 0)
    }

    // MARK: - Section 6: Authoritative Answer Flag

    @Test("mDNS responses should be authoritative")
    func mdnsResponsesAreAuthoritative() throws {
        let name = try DNSName("host.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )

        let response = DNSMessage.response(answers: [record], isAuthoritative: true)

        #expect(response.isAuthoritative == true)

        let encoded = response.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.isAuthoritative == true)
    }

    // MARK: - Section 18.14: Maximum Message Size

    @Test("mDNS maximum message size constant")
    func checkMdnsMaxMessageSize() {
        // mDNS messages can be larger than standard DNS UDP (512 bytes)
        // because multicast doesn't have the same fragmentation concerns
        #expect(mDNS.mdnsMaxMessageSize == 9000)
    }

    @Test("Standard DNS UDP max size constant")
    func checkDnsMaxUDPMessageSize() {
        #expect(mDNS.dnsMaxUDPMessageSize == 512)
    }

    // MARK: - Multiple record types in query

    @Test("mDNS query with multiple types")
    func mdnsQueryWithMultipleTypes() throws {
        let name = try DNSName("My Service._http._tcp.local.")
        let query = DNSMessage.mdnsQuery(
            name: name,
            types: [.srv, .txt, .a, .aaaa],
            unicastResponse: false
        )

        #expect(query.questions.count == 4)
        #expect(query.questions[0].type == .srv)
        #expect(query.questions[1].type == .txt)
        #expect(query.questions[2].type == .a)
        #expect(query.questions[3].type == .aaaa)
    }

    @Test("mDNS query with unicast response request")
    func mdnsQueryWithUnicastRequest() throws {
        let name = try DNSName("host.local.")
        let query = DNSMessage.mdnsQuery(
            name: name,
            types: [.a],
            unicastResponse: true
        )

        #expect(query.questions[0].unicastResponse == true)
    }
}
