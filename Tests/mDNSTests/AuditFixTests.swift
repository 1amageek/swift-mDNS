/// Audit Fix Tests
///
/// Regression tests for the security/robustness fixes applied to the DNS wire
/// decoder: NSEC RDATA bounds, decode-time name-length enforcement, strict UTF-8
/// in TXT/HINFO, preservation of unknown enum values, and hostile-input safety.

import Testing
import Foundation
@testable import mDNS

@Suite("Audit Fix Tests")
struct AuditFixTests {

    // MARK: - Helpers

    /// Builds a single-answer DNS response message wrapping the given record body.
    ///
    /// Layout: 12-byte header (ANCOUNT = 1), an owner name of `www` + root, the
    /// supplied type/class/TTL, then `rdata` prefixed with its 2-byte length.
    private func makeSingleAnswerMessage(
        type: UInt16,
        rdata: [UInt8],
        recordClass: UInt16 = 0x0001,
        rdataLengthOverride: UInt16? = nil
    ) -> Data {
        var data = Data()
        // Header: response, 0 questions, 1 answer, 0 authority, 0 additional.
        data.append(contentsOf: [0x00, 0x00, 0x84, 0x00])
        data.append(contentsOf: [0x00, 0x00])  // QDCOUNT
        data.append(contentsOf: [0x00, 0x01])  // ANCOUNT
        data.append(contentsOf: [0x00, 0x00])  // NSCOUNT
        data.append(contentsOf: [0x00, 0x00])  // ARCOUNT

        // Owner name: "www".
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)

        // TYPE / CLASS / TTL.
        data.append(UInt8(type >> 8))
        data.append(UInt8(type & 0xFF))
        data.append(UInt8(recordClass >> 8))
        data.append(UInt8(recordClass & 0xFF))
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x78])  // TTL = 120

        // RDLENGTH + RDATA.
        let rdLength = rdataLengthOverride ?? UInt16(rdata.count)
        data.append(UInt8(rdLength >> 8))
        data.append(UInt8(rdLength & 0xFF))
        data.append(contentsOf: rdata)

        return data
    }

    // MARK: - NSEC RDATA Bounds (Finding #1)

    @Test("NSEC next-domain name that over-consumes RDATA throws instead of trapping")
    func nsecNameOverConsumesRdata() throws {
        // A compression pointer is always 2 bytes in-stream. By declaring RDLENGTH = 1
        // while placing a 2-byte pointer (0xC0 0x0C) as the next-domain name, the name
        // decode consumes 2 bytes — more than the 1-byte RDATA window. Without bounds
        // validation `bitmapLength = rdataLength - bytesConsumed` (1 - 2) goes negative,
        // producing an out-of-bounds slice / trap. We expect a thrown error instead.
        let rdata: [UInt8] = [0xC0, 0x0C]
        let data = makeSingleAnswerMessage(type: 47, rdata: rdata, rdataLengthOverride: 1)

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("NSEC with name claiming more bytes than RDATA window throws")
    func nsecNameExceedsRdataWindow() throws {
        // A valid uncompressed name "a" + root is 3 bytes, but we declare RDLENGTH = 2
        // so the name overruns the window. Must throw, not read past the window.
        let rdata: [UInt8] = [
            0x01, UInt8(ascii: "a"), 0x00,  // name "a." = 3 bytes
            0x00, 0x06,                      // bitmap window byte + length (won't be reached)
        ]
        let data = makeSingleAnswerMessage(type: 47, rdata: rdata, rdataLengthOverride: 2)

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Valid NSEC round-trips through encode/decode")
    func nsecValidRoundTrip() throws {
        // Build a valid NSEC record with an uncompressed next-domain name and a
        // small type bitmap, encode it, decode it, and confirm fields survive.
        let nextDomain = try DNSName("host.local.")
        let typeBitmap = Data([0x00, 0x04, 0x40, 0x00, 0x00, 0x08])  // window 0, len 4
        let record = DNSResourceRecord(
            name: try DNSName("host.local."),
            type: .nsec,
            ttl: 120,
            rdata: .nsec(nextDomain: nextDomain, typeBitmap: typeBitmap)
        )

        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)

        #expect(decoded.type == .nsec)
        guard case .nsec(let decodedNext, let decodedBitmap) = decoded.rdata else {
            Issue.record("Expected NSEC rdata")
            return
        }
        #expect(decodedNext == nextDomain)
        #expect(decodedBitmap == typeBitmap)
    }

    // MARK: - Decode-Time Name Length / Label Count (Finding #2)

    @Test("Wire name exceeding 255 bytes via many labels throws")
    func wireNameExceedsMaxLengthManyLabels() throws {
        // Build a name made of many 4-byte labels ("aaa" => 1 length + 3 bytes) so
        // the encoded total exceeds dnsMaxNameLength (255). 70 labels * 4 = 280 > 255.
        var name = Data()
        for _ in 0..<70 {
            name.append(3)
            name.append(contentsOf: "aaa".utf8)
        }
        name.append(0)  // terminator

        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: name, at: 0)
        }
    }

    @Test("Wire name inflated by compression beyond 255 bytes throws")
    func wireNameInflatedByCompressionThrows() throws {
        // Construct a message whose final name uses a compression pointer chain that
        // assembles an over-length name. We place a long base name, then a name that
        // references it via a pointer plus additional labels, pushing total > 255.
        var data = Data()
        // Header (12 bytes), QDCOUNT = 1.
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])  // QDCOUNT
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        // Base name at offset 12: 60 labels of "aaa" (60 * 4 = 240 bytes) + terminator.
        let baseOffset = data.count
        for _ in 0..<60 {
            data.append(3)
            data.append(contentsOf: "aaa".utf8)
        }
        data.append(0)
        _ = baseOffset

        // This question's name is too short on its own but the message is already
        // malformed (only one name region and no question fields after it). The
        // decoder reading the question name will walk the 240-byte region and then
        // require type/class which are missing, so this throws either on length or
        // truncation. To specifically exercise the length cap, decode the base name
        // region directly with a trailing pointer appended.
        var nameWithPointer = Data()
        for _ in 0..<60 {
            nameWithPointer.append(3)
            nameWithPointer.append(contentsOf: "aaa".utf8)
        }
        // Append a pointer back to offset 0 of this standalone buffer, which points
        // to the first label, re-walking the whole 240 bytes again -> > 255.
        nameWithPointer.append(0xC0)
        nameWithPointer.append(0x00)

        #expect(throws: DNSError.self) {
            _ = try DNSName.decode(from: nameWithPointer, at: 0)
        }
    }

    @Test("Valid maximum-ish name decodes successfully")
    func validNameDecodes() throws {
        // A name comfortably under the limit must still decode.
        var name = Data()
        for _ in 0..<10 {
            name.append(3)
            name.append(contentsOf: "abc".utf8)
        }
        name.append(0)

        let (decoded, consumed) = try DNSName.decode(from: name, at: 0)
        #expect(decoded.labels.count == 10)
        #expect(consumed == name.count)
    }

    // MARK: - Strict UTF-8 in TXT / HINFO (Finding #3)

    @Test("Malformed UTF-8 in TXT string throws instead of substituting empty string")
    func malformedUTF8InTXTThrows() throws {
        // TXT RDATA: one string of length 2 containing an invalid UTF-8 sequence
        // (0xFF 0xFE are never valid UTF-8 lead bytes here).
        let rdata: [UInt8] = [0x02, 0xFF, 0xFE]
        let data = makeSingleAnswerMessage(type: 16, rdata: rdata)

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Valid TXT decodes correctly")
    func validTXTDecodes() throws {
        let rdata: [UInt8] = [0x05] + Array("hello".utf8)
        let data = makeSingleAnswerMessage(type: 16, rdata: rdata)

        let message = try DNSMessage.decode(from: data)
        guard case .txt(let strings) = message.answers.first?.rdata else {
            Issue.record("Expected TXT rdata")
            return
        }
        #expect(strings == ["hello"])
    }

    @Test("Malformed UTF-8 in HINFO CPU throws instead of substituting empty string")
    func malformedUTF8InHINFOCPUThrows() throws {
        // HINFO RDATA: CPU length 2 with invalid UTF-8, then OS length 0.
        let rdata: [UInt8] = [0x02, 0xFF, 0xFE, 0x00]
        let data = makeSingleAnswerMessage(type: 13, rdata: rdata)

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Malformed UTF-8 in HINFO OS throws instead of substituting empty string")
    func malformedUTF8InHINFOOSThrows() throws {
        // HINFO RDATA: CPU "x" (len 1), then OS length 2 with invalid UTF-8.
        let rdata: [UInt8] = [0x01, UInt8(ascii: "x"), 0x02, 0xFF, 0xFE]
        let data = makeSingleAnswerMessage(type: 13, rdata: rdata)

        #expect(throws: DNSError.self) {
            _ = try DNSMessage.decode(from: data)
        }
    }

    @Test("Valid HINFO decodes correctly")
    func validHINFODecodes() throws {
        let rdata: [UInt8] = [0x03] + Array("x86".utf8) + [0x05] + Array("Linux".utf8)
        let data = makeSingleAnswerMessage(type: 13, rdata: rdata)

        let message = try DNSMessage.decode(from: data)
        guard case .hinfo(let cpu, let os) = message.answers.first?.rdata else {
            Issue.record("Expected HINFO rdata")
            return
        }
        #expect(cpu == "x86")
        #expect(os == "Linux")
    }

    // MARK: - Unknown Enum Preservation (Finding #5)

    @Test("Unknown opcode is preserved as .unknown, not defaulted to .query")
    func unknownOpcodePreserved() throws {
        // Opcode field is bits 11-14 of the flags word. Use opcode value 9 (unknown).
        // flags = opcode(9) << 11 = 0x4800.
        var data = Data()
        data.append(contentsOf: [0x00, 0x00])  // ID
        data.append(contentsOf: [0x48, 0x00])  // flags: opcode = 9
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        let message = try DNSMessage.decode(from: data)
        #expect(message.opcode == .unknown(9))
        #expect(message.opcode != .query)
        #expect(message.opcode.rawValue == 9)
    }

    @Test("Unknown response code is preserved as .unknown, not defaulted to .noError")
    func unknownResponseCodePreserved() throws {
        // Response code is the low 4 bits of flags. Use value 9 (unknown).
        var data = Data()
        data.append(contentsOf: [0x00, 0x00])  // ID
        data.append(contentsOf: [0x00, 0x09])  // flags: rcode = 9
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        let message = try DNSMessage.decode(from: data)
        #expect(message.responseCode == .unknown(9))
        #expect(message.responseCode != .noError)
        #expect(message.responseCode.rawValue == 9)
    }

    @Test("Unknown record class is preserved as .unknown, not defaulted to .in")
    func unknownRecordClassPreserved() throws {
        // A record with a known type (A) but an unknown class value (7).
        let rdata: [UInt8] = [192, 168, 1, 1]
        let data = makeSingleAnswerMessage(type: 1, rdata: rdata, recordClass: 0x0007)

        let message = try DNSMessage.decode(from: data)
        let record = try #require(message.answers.first)
        #expect(record.recordClass == .unknown(7))
        #expect(record.recordClass != .in)
        #expect(record.recordClass.rawValue == 7)
    }

    @Test("Unknown record type is preserved and NOT aliased to .a")
    func unknownRecordTypeNotAliasedToA() throws {
        // Use an unassigned type value (e.g. 9999). The decoder must store
        // type == .unknown(9999) and rdata == .unknown(typeValue: 9999, ...),
        // never type == .a.
        let rdata: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let data = makeSingleAnswerMessage(type: 9999, rdata: rdata)

        let message = try DNSMessage.decode(from: data)
        let record = try #require(message.answers.first)
        #expect(record.type == .unknown(9999))
        #expect(record.type != .a)
        #expect(record.type.rawValue == 9999)

        guard case .unknown(let typeValue, let payload) = record.rdata else {
            Issue.record("Expected unknown rdata")
            return
        }
        #expect(typeValue == 9999)
        #expect(Array(payload) == rdata)
    }

    @Test("Unknown question type is preserved, not rejected")
    func unknownQuestionTypePreserved() throws {
        // A question with an unassigned type value (8888) must decode with the type
        // preserved as .unknown, rather than throwing unsupportedRecordType.
        var data = Data()
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x00, 0x01])  // QDCOUNT = 1
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        data.append(3)
        data.append(contentsOf: "www".utf8)
        data.append(0)
        data.append(contentsOf: [0x22, 0xB8])  // TYPE = 8888
        data.append(contentsOf: [0x00, 0x01])  // CLASS = IN

        let message = try DNSMessage.decode(from: data)
        let question = try #require(message.questions.first)
        #expect(question.type == .unknown(8888))
        #expect(question.type.rawValue == 8888)
    }

    @Test("Round-trip preserves an unknown record type's wire value")
    func unknownRecordTypeRoundTrip() throws {
        let record = DNSResourceRecord(
            name: try DNSName("host.local."),
            type: .unknown(5000),
            ttl: 60,
            rdata: .unknown(typeValue: 5000, data: Data([0x01, 0x02, 0x03]))
        )
        let encoded = record.encode()
        let (decoded, _) = try DNSResourceRecord.decode(from: encoded, at: 0)
        #expect(decoded.type == .unknown(5000))
        guard case .unknown(let typeValue, let payload) = decoded.rdata else {
            Issue.record("Expected unknown rdata")
            return
        }
        #expect(typeValue == 5000)
        #expect(Array(payload) == [0x01, 0x02, 0x03])
    }

    // MARK: - Hostile-Input Fuzz / Property Test (Finding: never traps)

    @Test("Random and truncated buffers never trap, only throw or decode")
    func hostileInputNeverTraps() throws {
        var generator = SystemRandomNumberGenerator()

        // 1) Truncations of a known-good message: every prefix must throw or decode,
        //    never trap.
        let good = makeSingleAnswerMessage(type: 1, rdata: [192, 168, 1, 1])
        for length in 0...good.count {
            let slice = good.prefix(length)
            decodeSafely(Data(slice))
        }

        // 2) Fully random buffers of assorted sizes.
        for _ in 0..<2000 {
            let size = Int.random(in: 0...64, using: &generator)
            var bytes = [UInt8]()
            bytes.reserveCapacity(size)
            for _ in 0..<size {
                bytes.append(UInt8.random(in: 0...255, using: &generator))
            }
            decodeSafely(Data(bytes))
        }

        // 3) Random buffers carrying a plausible header claiming records, to drive
        //    the record/name decode paths with hostile content.
        for _ in 0..<2000 {
            var bytes: [UInt8] = [0x00, 0x00, 0x84, 0x00]
            // Random non-zero counts to force the section loops to run.
            bytes.append(0x00); bytes.append(UInt8.random(in: 0...3, using: &generator)) // QDCOUNT
            bytes.append(0x00); bytes.append(UInt8.random(in: 0...3, using: &generator)) // ANCOUNT
            bytes.append(0x00); bytes.append(UInt8.random(in: 0...3, using: &generator)) // NSCOUNT
            bytes.append(0x00); bytes.append(UInt8.random(in: 0...3, using: &generator)) // ARCOUNT
            let tail = Int.random(in: 0...48, using: &generator)
            for _ in 0..<tail {
                bytes.append(UInt8.random(in: 0...255, using: &generator))
            }
            decodeSafely(Data(bytes))
        }
    }

    /// Decodes a buffer, tolerating any thrown `Error` but failing the test on a trap.
    /// (A trap would crash the process; reaching here at all proves no trap occurred.)
    private func decodeSafely(_ data: Data) {
        do {
            _ = try DNSMessage.decode(from: data)
        } catch {
            // Expected: malformed input must surface as a thrown error.
        }
    }
}
