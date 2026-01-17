import Testing
import Foundation
@testable import mDNS

@Suite("DNSName Tests")
struct DNSNameTests {

    @Test("Create DNS name from string")
    func createFromString() throws {
        let name = try DNSName("_http._tcp.local.")
        #expect(name.labels == ["_http", "_tcp", "local"])
        #expect(name.description == "_http._tcp.local.")
        #expect(name.name == "_http._tcp.local")
    }

    @Test("Create DNS name without trailing dot")
    func createWithoutTrailingDot() throws {
        let name = try DNSName("example.local")
        #expect(name.labels == ["example", "local"])
        #expect(name.description == "example.local.")
    }

    @Test("Create root DNS name")
    func createRoot() throws {
        let name = try DNSName(".")
        #expect(name.labels.isEmpty)
        #expect(name.isRoot)
        #expect(name.description == ".")
    }

    @Test("Encode DNS name")
    func encode() throws {
        let name = try DNSName("www.example.local.")
        let encoded = name.encode()

        // Expected: \x03www\x07example\x05local\x00
        // 1 + 3 + 1 + 7 + 1 + 5 + 1 = 19 bytes
        #expect(encoded.count == 19)
        #expect(encoded[0] == 3)  // "www" length
        #expect(encoded[4] == 7)  // "example" length
        #expect(encoded[12] == 5) // "local" length
        #expect(encoded[18] == 0) // Terminator
    }

    @Test("Decode DNS name")
    func decode() throws {
        // Encode "\x03www\x07example\x05local\x00"
        var data = Data()
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(7)
        data.append(contentsOf: "example".utf8)
        data.append(5)
        data.append(contentsOf: "local".utf8)
        data.append(0)

        let (name, bytesConsumed) = try DNSName.decode(from: data, at: 0)

        #expect(name.labels == ["www", "example", "local"])
        // 1 + 3 + 1 + 7 + 1 + 5 + 1 = 19 bytes
        #expect(bytesConsumed == 19)
    }

    @Test("Decode DNS name with compression pointer")
    func decodeWithCompression() throws {
        // First name at offset 0: "\x03www\x07example\x05local\x00" (19 bytes)
        // Second name at offset 19: "\x04mail\xc0\x04" (pointer to offset 4 = "example.local")
        var data = Data()

        // First name (19 bytes total)
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(7)
        data.append(contentsOf: "example".utf8)
        data.append(5)
        data.append(contentsOf: "local".utf8)
        data.append(0)

        // Second name with pointer
        data.append(4)
        data.append(contentsOf: "mail".utf8)
        data.append(0xC0) // Compression pointer marker
        data.append(0x04) // Pointer to offset 4 ("example.local")

        let (name, bytesConsumed) = try DNSName.decode(from: data, at: 19)

        #expect(name.labels == ["mail", "example", "local"])
        #expect(bytesConsumed == 7) // 1 + 4 + 2 (pointer)
    }

    @Test("DNS names are case-insensitive")
    func caseInsensitiveEquality() throws {
        let name1 = try DNSName("WWW.Example.LOCAL.")
        let name2 = try DNSName("www.example.local.")

        #expect(name1 == name2)
    }

    @Test("Invalid label length throws")
    func invalidLabelLength() throws {
        let longLabel = String(repeating: "a", count: 64)
        #expect(throws: DNSError.self) {
            _ = try DNSName("\(longLabel).local.")
        }
    }

    @Test("ExpressibleByStringLiteral conformance")
    func stringLiteral() {
        let name: DNSName = "_http._tcp.local."
        #expect(name.labels == ["_http", "_tcp", "local"])
    }
}
