import Testing
import Foundation
@testable import mDNS

@Suite("Service Tests")
struct ServiceTests {

    @Test("Create service with required fields")
    func createService() {
        let service = Service(
            name: "My Web Server",
            type: "_http._tcp",
            port: 8080
        )

        #expect(service.name == "My Web Server")
        #expect(service.type == "_http._tcp")
        #expect(service.domain == "local")
        #expect(service.port == 8080)
        #expect(service.fullName == "My Web Server._http._tcp.local.")
        #expect(service.fullType == "_http._tcp.local.")
    }

    @Test("Service with TXT record")
    func serviceWithTXT() {
        var txtRecord = TXTRecord()
        txtRecord["path"] = "/api"
        txtRecord["version"] = "1.0"

        let service = Service(
            name: "API Server",
            type: "_http._tcp",
            port: 3000,
            txtRecord: txtRecord
        )

        #expect(service.txtRecord["path"] == "/api")
        #expect(service.txtRecord["version"] == "1.0")
    }

    @Test("Service resolution status")
    func resolutionStatus() {
        var service = Service(name: "Test", type: "_test._tcp")

        #expect(service.isResolved == false)
        #expect(service.hasAddresses == false)

        service.hostName = "test.local"
        service.port = 1234

        #expect(service.isResolved == true)
        #expect(service.hasAddresses == false)

        service.ipv4Addresses.append(IPv4Address(192, 168, 1, 1))

        #expect(service.hasAddresses == true)
    }

    @Test("Service ID is full name")
    func serviceId() {
        let service = Service(
            name: "My Service",
            type: "_http._tcp",
            domain: "local"
        )

        #expect(service.id == service.fullName)
    }

    // MARK: - TXTRecord Tests

    @Test("TXTRecord from strings")
    func txtFromStrings() {
        let txt = TXTRecord(strings: [
            "key1=value1",
            "key2=value2",
            "boolkey"
        ])

        #expect(txt["key1"] == "value1")
        #expect(txt["key2"] == "value2")
        #expect(txt["boolkey"] == "")
        #expect(txt.contains("key1"))
    }

    @Test("TXTRecord case insensitivity")
    func txtCaseInsensitive() {
        var txt = TXTRecord()
        txt["MyKey"] = "value"

        #expect(txt["mykey"] == "value")
        #expect(txt["MYKEY"] == "value")
    }

    @Test("TXTRecord to strings")
    func txtToStrings() {
        let txt = TXTRecord(["path": "/api", "empty": ""])
        let strings = txt.toStrings()

        #expect(strings.contains("path=/api"))
        #expect(strings.contains("empty"))
    }

    @Test("Empty TXTRecord")
    func emptyTXT() {
        let txt = TXTRecord()
        #expect(txt.isEmpty)
        #expect(txt.toStrings().isEmpty)
    }

    // MARK: - ServiceType Tests

    @Test("Common service types")
    func commonServiceTypes() {
        #expect(ServiceType.http == "_http._tcp")
        #expect(ServiceType.ssh == "_ssh._tcp")
        #expect(ServiceType.libp2p == "_p2p._udp")
    }

    @Test("Full service type with domain")
    func fullServiceType() {
        let fullType = ServiceType.fullType("_http._tcp")
        #expect(fullType == "_http._tcp.local.")
    }
}
