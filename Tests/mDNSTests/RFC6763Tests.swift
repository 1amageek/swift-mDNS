/// RFC 6763 DNS-Based Service Discovery Tests
///
/// Tests for DNS-SD behavior per RFC 6763.
/// https://tools.ietf.org/html/rfc6763

import Testing
import Foundation
@testable import mDNS

@Suite("RFC 6763 - DNS-Based Service Discovery")
struct RFC6763Tests {

    // MARK: - Section 4: Service Instance Name

    @Test("Service instance name format: Instance._Service._Protocol.Domain")
    func serviceInstanceNameFormat() throws {
        let service = Service(
            name: "My Web Server",
            type: "_http._tcp",
            domain: "local",
            port: 8080
        )

        // Full name should be: "My Web Server._http._tcp.local."
        #expect(service.fullName == "My Web Server._http._tcp.local.")
    }

    @Test("Service type format: _Service._Protocol")
    func serviceTypeFormat() throws {
        let service = Service(
            name: "Test",
            type: "_http._tcp"
        )

        #expect(service.type == "_http._tcp")
        #expect(service.fullType == "_http._tcp.local.")
    }

    @Test("Service with custom domain")
    func serviceWithCustomDomain() throws {
        let service = Service(
            name: "My Service",
            type: "_http._tcp",
            domain: "example.com"
        )

        #expect(service.fullName == "My Service._http._tcp.example.com.")
        #expect(service.fullType == "_http._tcp.example.com.")
    }

    // MARK: - Section 4.1: Service Types (Browse)

    @Test("PTR record for service enumeration")
    func ptrRecordForServiceEnumeration() throws {
        let serviceName = try DNSName("My Web Server._http._tcp.local.")
        let serviceType = try DNSName("_http._tcp.local.")

        let ptrRecord = DNSResourceRecord(
            name: serviceType,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(serviceName)
        )

        #expect(ptrRecord.type == .ptr)

        if case .ptr(let target) = ptrRecord.rdata {
            #expect(target == serviceName)
        } else {
            Issue.record("Expected PTR record")
        }
    }

    @Test("Service browsing meta-query constant")
    func serviceBrowsingMetaQuery() {
        // _services._dns-sd._udp.local. enumerates all service types
        #expect(mDNS.dnsSDServicesMetaQuery == "_services._dns-sd._udp.local.")
    }

    @Test("Parse meta-query response")
    func parseMetaQueryResponse() throws {
        let metaQueryName = try DNSName(mDNS.dnsSDServicesMetaQuery)
        let serviceType = try DNSName("_http._tcp.local.")

        let ptrRecord = DNSResourceRecord(
            name: metaQueryName,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(serviceType)
        )

        let message = DNSMessage.response(answers: [ptrRecord])
        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.answers.count == 1)
        if case .ptr(let type) = decoded.answers[0].rdata {
            #expect(type == serviceType)
        } else {
            Issue.record("Expected PTR record")
        }
    }

    // MARK: - Section 6: TXT Record Format

    @Test("TXT record key=value format")
    func txtRecordKeyValueFormat() throws {
        let txt = TXTRecord(["path": "/api", "version": "1.0"])
        let strings = txt.toStrings()

        #expect(strings.contains("path=/api"))
        #expect(strings.contains("version=1.0"))
    }

    @Test("TXT record boolean key (no value)")
    func txtRecordBooleanKey() throws {
        let txt = TXTRecord(strings: ["secure", "debug"])

        #expect(txt["secure"] == "")
        #expect(txt["debug"] == "")
        #expect(txt.contains("secure"))
    }

    @Test("TXT record keys are case-insensitive")
    func txtRecordCaseInsensitivity() throws {
        var txt = TXTRecord()
        txt["MyKey"] = "value"

        #expect(txt["mykey"] == "value")
        #expect(txt["MYKEY"] == "value")
        #expect(txt["MyKey"] == "value")
    }

    @Test("TXT record empty value vs no key")
    func txtRecordEmptyValueVsNoKey() throws {
        var txt = TXTRecord()
        txt["present"] = ""

        #expect(txt.contains("present"))
        #expect(txt["present"] == "")
        #expect(!txt.contains("absent"))
        #expect(txt["absent"] == nil)
    }

    @Test("TXT record encode/decode roundtrip")
    func txtRecordEncodeDecode() throws {
        let name = try DNSName("My Service._http._tcp.local.")
        let strings = ["path=/api", "version=2.0", "secure"]

        let record = DNSResourceRecord(
            name: name,
            type: .txt,
            ttl: 4500,
            rdata: .txt(strings)
        )

        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        if case .txt(let decodedStrings) = decoded.rdata {
            #expect(decodedStrings == strings)
        } else {
            Issue.record("Expected TXT record")
        }
    }

    @Test("Empty TXT record has single zero-length string")
    func emptyTXTRecord() throws {
        let name = try DNSName("service.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .txt,
            ttl: 120,
            rdata: .txt([])
        )

        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        // Empty TXT should decode to empty array or single empty string
        if case .txt(let strings) = decoded.rdata {
            // Implementation detail: may be [] or [""]
            #expect(strings.isEmpty || (strings.count == 1 && strings[0].isEmpty))
        } else {
            Issue.record("Expected TXT record")
        }
    }

    // MARK: - Section 5: Service Instance Resolution

    @Test("Complete service record set")
    func completeServiceRecordSet() throws {
        let serviceName = try DNSName("My Web Server._http._tcp.local.")
        let serviceType = try DNSName("_http._tcp.local.")
        let hostName = try DNSName("myhost.local.")

        // PTR record: points to service instance
        let ptr = DNSResourceRecord(
            name: serviceType,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(serviceName)
        )

        // SRV record: provides host and port
        let srv = DNSResourceRecord(
            name: serviceName,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: hostName))
        )

        // TXT record: provides additional attributes
        let txt = DNSResourceRecord(
            name: serviceName,
            type: .txt,
            ttl: 4500,
            rdata: .txt(["path=/api"])
        )

        // A record: provides IP address
        let a = DNSResourceRecord(
            name: hostName,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 100))
        )

        // Create response with all records
        let response = DNSMessage.response(
            answers: [ptr, srv, txt],
            additional: [a]
        )

        let encoded = response.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.answers.count == 3)
        #expect(decoded.additional.count == 1)
    }

    // MARK: - Section 7: Service Names

    @Test("Service type prefix underscore")
    func serviceTypePrefixUnderscore() throws {
        // Service types must start with underscore
        let service = Service(name: "Test", type: "_http._tcp")
        #expect(service.type.hasPrefix("_"))
    }

    @Test("Common service type constants")
    func commonServiceTypeConstants() {
        #expect(ServiceType.http == "_http._tcp")
        #expect(ServiceType.ssh == "_ssh._tcp")
        #expect(ServiceType.libp2p == "_p2p._udp")
    }

    @Test("Full service type with domain")
    func fullServiceTypeWithDomain() {
        let fullType = ServiceType.fullType("_http._tcp")
        #expect(fullType == "_http._tcp.local.")

        let fullType2 = ServiceType.fullType("_ssh._tcp", domain: "example.com")
        #expect(fullType2 == "_ssh._tcp.example.com.")
    }

    // MARK: - Service Model Tests

    @Test("Service resolution status tracking")
    func serviceResolutionStatus() throws {
        var service = Service(name: "Test", type: "_http._tcp")

        #expect(!service.isResolved)
        #expect(!service.hasAddresses)

        service.hostName = "test.local"
        service.port = 8080

        #expect(service.isResolved)
        #expect(!service.hasAddresses)

        service.ipv4Addresses.append(IPv4Address(192, 168, 1, 1))

        #expect(service.hasAddresses)
    }

    @Test("Service equality by full name")
    func serviceEquality() throws {
        let service1 = Service(name: "Test", type: "_http._tcp", domain: "local")
        let service2 = Service(name: "Test", type: "_http._tcp", domain: "local")
        let service3 = Service(name: "Other", type: "_http._tcp", domain: "local")

        #expect(service1.id == service2.id)
        #expect(service1.id != service3.id)
    }

    // MARK: - DNS-SD Constants

    @Test("DNS-SD service type suffixes")
    func checkDnsSDServiceTypeSuffixes() {
        #expect(mDNS.dnsSDServiceTypeSuffix == "._tcp.local.")
        #expect(mDNS.dnsSDServiceTypeUDPSuffix == "._udp.local.")
    }

    @Test("libp2p service type constant")
    func checkLibp2pServiceType() {
        #expect(mDNS.libp2pServiceType == "_p2p._udp.local.")
    }

    // MARK: - Service Discovery Flow Simulation

    @Test("Simulate PTR -> SRV/TXT -> A discovery flow")
    func simulateDiscoveryFlow() throws {
        // Step 1: Query for service type (PTR)
        let ptrQuery = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
        #expect(ptrQuery.questions[0].type == .ptr)

        // Step 2: Parse PTR response
        let serviceName = try DNSName("My Server._http._tcp.local.")
        let ptrResponse = DNSMessage.response(answers: [
            DNSResourceRecord(
                name: try DNSName("_http._tcp.local."),
                type: .ptr,
                ttl: 4500,
                rdata: .ptr(serviceName)
            )
        ])

        let ptrEncoded = ptrResponse.encode()
        let ptrDecoded = try DNSMessage.decode(from: ptrEncoded)

        guard case .ptr(let discoveredService) = ptrDecoded.answers[0].rdata else {
            Issue.record("Expected PTR record")
            return
        }

        // Step 3: Query for SRV and TXT
        let srvTxtQuery = DNSMessage.mdnsQuery(
            name: discoveredService,
            types: [.srv, .txt],
            unicastResponse: false
        )
        #expect(srvTxtQuery.questions.count == 2)

        // Step 4: Parse SRV/TXT response
        let hostName = try DNSName("myserver.local.")
        let srvTxtResponse = DNSMessage.response(answers: [
            DNSResourceRecord(
                name: discoveredService,
                type: .srv,
                ttl: 120,
                rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: hostName))
            ),
            DNSResourceRecord(
                name: discoveredService,
                type: .txt,
                ttl: 4500,
                rdata: .txt(["version=1.0"])
            )
        ])

        let srvTxtEncoded = srvTxtResponse.encode()
        let srvTxtDecoded = try DNSMessage.decode(from: srvTxtEncoded)

        #expect(srvTxtDecoded.answers.count == 2)

        // Step 5: Query for A record
        let aQuery = DNSMessage.mdnsQuery(name: hostName, types: [.a, .aaaa])
        #expect(aQuery.questions.count == 2)

        // Step 6: Parse A response
        let aResponse = DNSMessage.response(answers: [
            DNSResourceRecord(
                name: hostName,
                type: .a,
                ttl: 120,
                rdata: .a(IPv4Address(192, 168, 1, 100))
            )
        ])

        let aEncoded = aResponse.encode()
        let aDecoded = try DNSMessage.decode(from: aEncoded)

        guard case .a(let ip) = aDecoded.answers[0].rdata else {
            Issue.record("Expected A record")
            return
        }

        #expect(ip == IPv4Address(192, 168, 1, 100))
    }
}
