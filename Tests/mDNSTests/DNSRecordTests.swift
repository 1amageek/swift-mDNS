import Testing
import Foundation
@testable import mDNS

@Suite("DNS Record Tests")
struct DNSRecordTests {

    // MARK: - IPv4Address Tests

    @Test("IPv4Address from bytes")
    func ipv4FromBytes() {
        let addr = IPv4Address(192, 168, 1, 1)
        #expect(addr.description == "192.168.1.1")
    }

    @Test("IPv4Address from string")
    func ipv4FromString() {
        let addr = IPv4Address(string: "10.0.0.1")
        #expect(addr != nil)
        #expect(addr?.description == "10.0.0.1")
    }

    @Test("IPv4Address invalid string")
    func ipv4InvalidString() {
        let addr = IPv4Address(string: "invalid")
        #expect(addr == nil)
    }

    // MARK: - IPv6Address Tests

    @Test("IPv6Address from string")
    func ipv6FromString() {
        let addr = IPv6Address(string: "::1")
        #expect(addr != nil)
        #expect(addr?.rawData.count == 16)
    }

    @Test("IPv6Address full format")
    func ipv6FullFormat() {
        let addr = IPv6Address(string: "2001:0db8:0000:0000:0000:0000:0000:0001")
        #expect(addr != nil)
    }

    // MARK: - DNSQuestion Tests

    @Test("Encode and decode DNS question")
    func questionEncodeDecode() throws {
        let name = try DNSName("_http._tcp.local.")
        let question = DNSQuestion(
            name: name,
            type: .ptr,
            recordClass: .in,
            unicastResponse: false
        )

        let encoded = question.encode()

        let (decoded, bytesConsumed) = try DNSQuestion.decode(from: encoded, at: 0)

        #expect(decoded.name == name)
        #expect(decoded.type == .ptr)
        #expect(decoded.recordClass == .in)
        #expect(decoded.unicastResponse == false)
        #expect(bytesConsumed == encoded.count)
    }

    @Test("DNS question with unicast response bit")
    func questionUnicastBit() throws {
        let name = try DNSName("test.local.")
        let question = DNSQuestion(
            name: name,
            type: .a,
            recordClass: .in,
            unicastResponse: true
        )

        let encoded = question.encode()
        let (decoded, _) = try DNSQuestion.decode(from: encoded, at: 0)

        #expect(decoded.unicastResponse == true)
    }

    // MARK: - SRVRecord Tests

    @Test("Encode and decode SRV record")
    func srvEncodeDecode() throws {
        let target = try DNSName("server.local.")
        let srv = SRVRecord(
            priority: 10,
            weight: 20,
            port: 8080,
            target: target
        )

        let encoded = srv.encode()
        let decoded = try SRVRecord.decode(from: encoded, at: 0)

        #expect(decoded.priority == 10)
        #expect(decoded.weight == 20)
        #expect(decoded.port == 8080)
        #expect(decoded.target == target)
    }

    // MARK: - DNSResourceRecord Tests

    @Test("Encode and decode A record")
    func aRecordEncodeDecode() throws {
        let name = try DNSName("host.local.")
        let addr = IPv4Address(192, 168, 1, 100)
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            ttl: 120,
            rdata: .a(addr)
        )

        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        #expect(decoded.name == name)
        #expect(decoded.type == .a)
        #expect(decoded.ttl == 120)

        if case .a(let decodedAddr) = decoded.rdata {
            #expect(decodedAddr == addr)
        } else {
            Issue.record("Expected A record")
        }
    }

    @Test("Encode and decode PTR record")
    func ptrRecordEncodeDecode() throws {
        let name = try DNSName("_http._tcp.local.")
        let target = try DNSName("My Service._http._tcp.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(target)
        )

        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        #expect(decoded.name == name)
        #expect(decoded.type == .ptr)
        #expect(decoded.ttl == 4500)

        if case .ptr(let decodedTarget) = decoded.rdata {
            #expect(decodedTarget == target)
        } else {
            Issue.record("Expected PTR record")
        }
    }

    @Test("Encode and decode TXT record")
    func txtRecordEncodeDecode() throws {
        let name = try DNSName("service.local.")
        let strings = ["key1=value1", "key2=value2", "boolkey"]
        let record = DNSResourceRecord(
            name: name,
            type: .txt,
            ttl: 120,
            rdata: .txt(strings)
        )

        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        #expect(decoded.type == .txt)

        if case .txt(let decodedStrings) = decoded.rdata {
            #expect(decodedStrings == strings)
        } else {
            Issue.record("Expected TXT record")
        }
    }

    @Test("Record with cache-flush bit")
    func cacheFlushBit() throws {
        let name = try DNSName("host.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            cacheFlush: true,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )

        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        #expect(decoded.cacheFlush == true)
    }
}
