/// RFC 2782 SRV Record Tests
///
/// Tests for SRV record format and semantics per RFC 2782.
/// https://tools.ietf.org/html/rfc2782

import Testing
import Foundation
@testable import mDNS

@Suite("RFC 2782 - DNS SRV Records")
struct RFC2782Tests {

    // MARK: - Section 4: SRV RDATA Format

    @Test("SRV record wire format: Priority, Weight, Port, Target")
    func srvRecordWireFormat() throws {
        let target = try DNSName("server.local.")
        let srv = SRVRecord(
            priority: 10,
            weight: 20,
            port: 8080,
            target: target
        )

        let encoded = srv.encode()

        // First 2 bytes: Priority (big-endian)
        let priority = UInt16(encoded[0]) << 8 | UInt16(encoded[1])
        #expect(priority == 10)

        // Next 2 bytes: Weight (big-endian)
        let weight = UInt16(encoded[2]) << 8 | UInt16(encoded[3])
        #expect(weight == 20)

        // Next 2 bytes: Port (big-endian)
        let port = UInt16(encoded[4]) << 8 | UInt16(encoded[5])
        #expect(port == 8080)

        // Remaining bytes: Target name
        let (decodedTarget, _) = try DNSName.decode(from: encoded, at: 6)
        #expect(decodedTarget == target)
    }

    @Test("SRV record encode/decode roundtrip")
    func srvRecordRoundtrip() throws {
        let target = try DNSName("myserver.example.local.")
        let original = SRVRecord(
            priority: 100,
            weight: 50,
            port: 443,
            target: target
        )

        let encoded = original.encode()
        let decoded = try SRVRecord.decode(from: encoded, at: 0)

        #expect(decoded.priority == original.priority)
        #expect(decoded.weight == original.weight)
        #expect(decoded.port == original.port)
        #expect(decoded.target == original.target)
    }

    // MARK: - Section 4: Target "." Means No Service

    @Test("SRV target root domain means service unavailable")
    func srvRootTargetMeansUnavailable() throws {
        // Per RFC 2782: "A Target of '.' means that the service is decidedly
        // not available at this domain."
        let root = try DNSName(".")
        let srv = SRVRecord(
            priority: 0,
            weight: 0,
            port: 0,
            target: root
        )

        #expect(srv.target.isRoot)
        #expect(srv.port == 0)

        let encoded = srv.encode()
        let decoded = try SRVRecord.decode(from: encoded, at: 0)

        #expect(decoded.target.isRoot)
    }

    // MARK: - Section 4: Priority

    @Test("SRV priority 0 is highest priority")
    func srvPriorityZeroHighest() throws {
        let target = try DNSName("server.local.")

        let highPriority = SRVRecord(priority: 0, weight: 0, port: 80, target: target)
        let lowPriority = SRVRecord(priority: 100, weight: 0, port: 80, target: target)

        // Lower priority value = higher priority
        #expect(highPriority.priority < lowPriority.priority)
    }

    @Test("SRV priority full range (0-65535)")
    func srvPriorityRange() throws {
        let target = try DNSName("server.local.")

        let minPriority = SRVRecord(priority: 0, weight: 0, port: 80, target: target)
        let maxPriority = SRVRecord(priority: 65535, weight: 0, port: 80, target: target)

        let minEncoded = minPriority.encode()
        let maxEncoded = maxPriority.encode()

        let minDecoded = try SRVRecord.decode(from: minEncoded, at: 0)
        let maxDecoded = try SRVRecord.decode(from: maxEncoded, at: 0)

        #expect(minDecoded.priority == 0)
        #expect(maxDecoded.priority == 65535)
    }

    // MARK: - Section 4: Weight

    @Test("SRV weight 0 means no load balancing preference")
    func srvWeightZero() throws {
        let target = try DNSName("server.local.")
        let srv = SRVRecord(priority: 0, weight: 0, port: 80, target: target)

        #expect(srv.weight == 0)
    }

    @Test("SRV weight full range (0-65535)")
    func srvWeightRange() throws {
        let target = try DNSName("server.local.")

        let minWeight = SRVRecord(priority: 0, weight: 0, port: 80, target: target)
        let maxWeight = SRVRecord(priority: 0, weight: 65535, port: 80, target: target)

        let minEncoded = minWeight.encode()
        let maxEncoded = maxWeight.encode()

        let minDecoded = try SRVRecord.decode(from: minEncoded, at: 0)
        let maxDecoded = try SRVRecord.decode(from: maxEncoded, at: 0)

        #expect(minDecoded.weight == 0)
        #expect(maxDecoded.weight == 65535)
    }

    @Test("SRV weight used for load balancing within same priority")
    func srvWeightForLoadBalancing() throws {
        let target1 = try DNSName("server1.local.")
        let target2 = try DNSName("server2.local.")

        // Same priority, different weights
        let srv1 = SRVRecord(priority: 10, weight: 70, port: 80, target: target1)
        let srv2 = SRVRecord(priority: 10, weight: 30, port: 80, target: target2)

        // Server1 should be selected ~70% of the time
        // This is a semantic test - implementation would need selection algorithm
        #expect(srv1.priority == srv2.priority)
        #expect(srv1.weight > srv2.weight)
    }

    // MARK: - Section 4: Port

    @Test("SRV port 0 means check elsewhere or default")
    func srvPortZero() throws {
        let target = try DNSName("server.local.")
        let srv = SRVRecord(priority: 0, weight: 0, port: 0, target: target)

        #expect(srv.port == 0)
    }

    @Test("SRV port full range (0-65535)")
    func srvPortRange() throws {
        let target = try DNSName("server.local.")

        let testPorts: [UInt16] = [0, 80, 443, 8080, 65535]

        for port in testPorts {
            let srv = SRVRecord(priority: 0, weight: 0, port: port, target: target)
            let encoded = srv.encode()
            let decoded = try SRVRecord.decode(from: encoded, at: 0)

            #expect(decoded.port == port, "Port \(port) should roundtrip correctly")
        }
    }

    // MARK: - SRV Record in DNS Message

    @Test("SRV record in DNS resource record")
    func srvInResourceRecord() throws {
        let serviceName = try DNSName("_http._tcp.local.")
        let target = try DNSName("webserver.local.")

        let record = DNSResourceRecord(
            name: serviceName,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: target))
        )

        #expect(record.type == .srv)

        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        #expect(decoded.type == .srv)
        #expect(decoded.ttl == 120)

        if case .srv(let srv) = decoded.rdata {
            #expect(srv.port == 8080)
            #expect(srv.target == target)
        } else {
            Issue.record("Expected SRV record")
        }
    }

    @Test("Multiple SRV records with different priorities")
    func multipleSRVRecordsPriorities() throws {
        let name = try DNSName("_http._tcp.local.")
        let primary = try DNSName("primary.local.")
        let backup = try DNSName("backup.local.")

        let primaryRecord = DNSResourceRecord(
            name: name,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 10, weight: 0, port: 80, target: primary))
        )

        let backupRecord = DNSResourceRecord(
            name: name,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 20, weight: 0, port: 80, target: backup))
        )

        let message = DNSMessage.response(answers: [primaryRecord, backupRecord])
        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.answers.count == 2)

        // Both should be SRV records
        for answer in decoded.answers {
            #expect(answer.type == .srv)
        }
    }

    @Test("Multiple SRV records with same priority different weights")
    func multipleSRVRecordsWeights() throws {
        let name = try DNSName("_http._tcp.local.")
        let server1 = try DNSName("server1.local.")
        let server2 = try DNSName("server2.local.")
        let server3 = try DNSName("server3.local.")

        let records = [
            DNSResourceRecord(
                name: name,
                type: .srv,
                ttl: 120,
                rdata: .srv(SRVRecord(priority: 10, weight: 50, port: 80, target: server1))
            ),
            DNSResourceRecord(
                name: name,
                type: .srv,
                ttl: 120,
                rdata: .srv(SRVRecord(priority: 10, weight: 30, port: 80, target: server2))
            ),
            DNSResourceRecord(
                name: name,
                type: .srv,
                ttl: 120,
                rdata: .srv(SRVRecord(priority: 10, weight: 20, port: 80, target: server3))
            ),
        ]

        let message = DNSMessage.response(answers: records)
        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.answers.count == 3)

        // Extract weights and verify they sum to 100
        var totalWeight: UInt16 = 0
        for answer in decoded.answers {
            if case .srv(let srv) = answer.rdata {
                totalWeight += srv.weight
            }
        }
        #expect(totalWeight == 100)
    }

    // MARK: - Edge Cases

    @Test("SRV with long target name")
    func srvWithLongTargetName() throws {
        let longLabel = String(repeating: "a", count: 63)
        let target = try DNSName("\(longLabel).local.")

        let srv = SRVRecord(priority: 0, weight: 0, port: 80, target: target)
        let encoded = srv.encode()
        let decoded = try SRVRecord.decode(from: encoded, at: 0)

        #expect(decoded.target == target)
    }

    @Test("SRV in message with compression")
    func srvInMessageWithCompression() throws {
        let serviceName = try DNSName("My Service._http._tcp.local.")
        let hostName = try DNSName("myhost.local.")

        let srv = DNSResourceRecord(
            name: serviceName,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: hostName))
        )

        let a = DNSResourceRecord(
            name: hostName,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )

        // Both records share ".local." suffix
        let message = DNSMessage.response(answers: [srv], additional: [a])
        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.answers.count == 1)
        #expect(decoded.additional.count == 1)

        if case .srv(let decodedSrv) = decoded.answers[0].rdata {
            #expect(decodedSrv.target == hostName)
        } else {
            Issue.record("Expected SRV record")
        }
    }
}
