import Testing
import Foundation
@testable import mDNS

@Suite("DNS Message Tests")
struct DNSMessageTests {

    @Test("Create query message")
    func createQuery() throws {
        let name = try DNSName("_http._tcp.local.")
        let question = DNSQuestion(name: name, type: .ptr)
        let message = DNSMessage.query(id: 1234, questions: [question])

        #expect(message.id == 1234)
        #expect(message.isResponse == false)
        #expect(message.questions.count == 1)
        #expect(message.answers.isEmpty)
    }

    @Test("Create response message")
    func createResponse() throws {
        let name = try DNSName("host.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )
        let message = DNSMessage.response(id: 0, answers: [record])

        #expect(message.id == 0)
        #expect(message.isResponse == true)
        #expect(message.isAuthoritative == true)
        #expect(message.answers.count == 1)
    }

    @Test("Encode and decode query message")
    func queryEncodeDecode() throws {
        let name = try DNSName("_http._tcp.local.")
        let question = DNSQuestion(name: name, type: .ptr)
        let message = DNSMessage.query(
            id: 0,
            questions: [question],
            recursionDesired: false
        )

        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.id == 0)
        #expect(decoded.isResponse == false)
        #expect(decoded.questions.count == 1)
        #expect(decoded.questions[0].name == name)
        #expect(decoded.questions[0].type == .ptr)
    }

    @Test("Encode and decode response message")
    func responseEncodeDecode() throws {
        let name = try DNSName("My Service._http._tcp.local.")
        let ptrName = try DNSName("_http._tcp.local.")

        let answer = DNSResourceRecord(
            name: ptrName,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(name)
        )

        let additional = DNSResourceRecord(
            name: name,
            type: .txt,
            ttl: 4500,
            rdata: .txt(["version=1.0"])
        )

        let message = DNSMessage.response(
            id: 0,
            answers: [answer],
            additional: [additional]
        )

        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.isResponse == true)
        #expect(decoded.isAuthoritative == true)
        #expect(decoded.answers.count == 1)
        #expect(decoded.additional.count == 1)

        if case .ptr(let decodedName) = decoded.answers[0].rdata {
            #expect(decodedName == name)
        } else {
            Issue.record("Expected PTR record")
        }
    }

    @Test("mDNS query factory")
    func mdnsQueryFactory() throws {
        let message = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")

        #expect(message.id == 0)
        #expect(message.isResponse == false)
        #expect(message.isMDNS == true)
        #expect(message.questions.count == 1)
        #expect(message.questions[0].type == .ptr)
    }

    @Test("mDNS goodbye message")
    func mdnsGoodbye() throws {
        let name = try DNSName("host.local.")
        let record = DNSResourceRecord(
            name: name,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 1))
        )

        let goodbye = DNSMessage.mdnsGoodbye(records: [record])

        #expect(goodbye.id == 0)
        #expect(goodbye.isResponse == true)
        #expect(goodbye.answers.count == 1)
        #expect(goodbye.answers[0].ttl == 0)
    }

    @Test("Header flags encoding")
    func headerFlags() throws {
        let message = DNSMessage(
            id: 1234,
            isResponse: true,
            opcode: .query,
            isAuthoritative: true,
            isTruncated: false,
            recursionDesired: true,
            recursionAvailable: true,
            responseCode: .noError
        )

        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.id == 1234)
        #expect(decoded.isResponse == true)
        #expect(decoded.opcode == .query)
        #expect(decoded.isAuthoritative == true)
        #expect(decoded.isTruncated == false)
        #expect(decoded.recursionDesired == true)
        #expect(decoded.recursionAvailable == true)
        #expect(decoded.responseCode == .noError)
    }

    @Test("Multiple questions")
    func multipleQuestions() throws {
        let name1 = try DNSName("service.local.")
        let name2 = try DNSName("other.local.")

        let q1 = DNSQuestion(name: name1, type: .a)
        let q2 = DNSQuestion(name: name2, type: .aaaa)

        let message = DNSMessage.query(id: 0, questions: [q1, q2])
        let encoded = message.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        #expect(decoded.questions.count == 2)
        #expect(decoded.questions[0].type == .a)
        #expect(decoded.questions[1].type == .aaaa)
    }

    @Test("Truncated message throws")
    func truncatedMessageThrows() {
        let data = Data([0x00, 0x00]) // Only 2 bytes, header needs 12
        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Message description")
    func messageDescription() throws {
        let name = try DNSName("_http._tcp.local.")
        let question = DNSQuestion(name: name, type: .ptr)
        let message = DNSMessage.query(id: 0, questions: [question])

        let description = message.description
        #expect(description.contains("Query"))
        #expect(description.contains("Questions"))
    }
}
