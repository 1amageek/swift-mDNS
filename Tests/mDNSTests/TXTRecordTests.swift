/// TXTRecord Tests
///
/// Tests for DNS-SD and libp2p TXT record functionality.

import Testing
@testable import mDNS

@Suite("TXTRecord Tests")
struct TXTRecordTests {

    // MARK: - Basic Construction

    @Test("Empty initialization")
    func testEmptyInit() {
        let txt = TXTRecord()
        #expect(txt.isEmpty)
        #expect(txt.toStrings().isEmpty)
    }

    @Test("Dictionary initialization")
    func testDictionaryInit() {
        let txt = TXTRecord(["key1": "value1", "key2": "value2"])
        #expect(!txt.isEmpty)
        #expect(txt["key1"] == "value1")
        #expect(txt["key2"] == "value2")
    }

    @Test("Strings initialization - single values")
    func testStringsInitSingleValues() {
        let txt = TXTRecord(strings: ["key1=value1", "key2=value2"])
        #expect(txt["key1"] == "value1")
        #expect(txt["key2"] == "value2")
    }

    @Test("Strings initialization - duplicate keys")
    func testStringsInitDuplicateKeys() {
        let txt = TXTRecord(strings: [
            "dnsaddr=/ip4/127.0.0.1/tcp/4001",
            "dnsaddr=/ip6/::1/tcp/4001"
        ])

        // subscript returns first value only (DNS-SD behavior)
        #expect(txt["dnsaddr"] == "/ip4/127.0.0.1/tcp/4001")

        // values(forKey:) returns all values (libp2p behavior)
        let values = txt.values(forKey: "dnsaddr")
        #expect(values.count == 2)
        #expect(values[0] == "/ip4/127.0.0.1/tcp/4001")
        #expect(values[1] == "/ip6/::1/tcp/4001")
    }

    @Test("Boolean attributes")
    func testBooleanAttributes() {
        let txt = TXTRecord(strings: ["flag1", "flag2"])
        #expect(txt["flag1"] == "")
        #expect(txt["flag2"] == "")
        #expect(txt.contains("flag1"))
        #expect(txt.contains("flag2"))
    }

    // MARK: - Case Insensitivity

    @Test("Case insensitive keys")
    func testCaseInsensitiveKeys() {
        var txt = TXTRecord()
        txt["Key1"] = "value1"

        #expect(txt["key1"] == "value1")
        #expect(txt["KEY1"] == "value1")
        #expect(txt["Key1"] == "value1")
    }

    @Test("Case insensitive contains")
    func testCaseInsensitiveContains() {
        var txt = TXTRecord()
        txt["MyKey"] = "value"

        #expect(txt.contains("mykey"))
        #expect(txt.contains("MYKEY"))
        #expect(txt.contains("MyKey"))
    }

    // MARK: - DNS-SD API (Single Value)

    @Test("Subscript get - first value only")
    func testSubscriptGetFirstValue() {
        let txt = TXTRecord(strings: ["key=first", "key=second", "key=third"])
        #expect(txt["key"] == "first")
    }

    @Test("Subscript set - replaces all values")
    func testSubscriptSetReplacesAll() {
        var txt = TXTRecord(strings: ["key=first", "key=second"])
        #expect(txt.values(forKey: "key").count == 2)

        txt["key"] = "replacement"

        #expect(txt.values(forKey: "key").count == 1)
        #expect(txt["key"] == "replacement")
    }

    @Test("Subscript set nil - removes all values")
    func testSubscriptSetNilRemovesAll() {
        var txt = TXTRecord(strings: ["key=first", "key=second"])
        #expect(txt.values(forKey: "key").count == 2)

        txt["key"] = nil

        #expect(txt.values(forKey: "key").isEmpty)
        #expect(!txt.contains("key"))
    }

    // MARK: - libp2p API (Multiple Values)

    @Test("appendValue - adds without replacing")
    func testAppendValue() {
        var txt = TXTRecord()

        txt.appendValue("first", forKey: "key")
        #expect(txt.values(forKey: "key") == ["first"])

        txt.appendValue("second", forKey: "key")
        #expect(txt.values(forKey: "key") == ["first", "second"])

        txt.appendValue("third", forKey: "key")
        #expect(txt.values(forKey: "key") == ["first", "second", "third"])
    }

    @Test("setValues - replaces all values")
    func testSetValues() {
        var txt = TXTRecord(strings: ["key=old1", "key=old2"])
        #expect(txt.values(forKey: "key").count == 2)

        txt.setValues(["new1", "new2", "new3"], forKey: "key")

        let values = txt.values(forKey: "key")
        #expect(values.count == 3)
        #expect(values == ["new1", "new2", "new3"])
    }

    @Test("removeValues - removes all values for key")
    func testRemoveValues() {
        var txt = TXTRecord(strings: ["key1=v1", "key2=v2a", "key2=v2b", "key3=v3"])

        txt.removeValues(forKey: "key2")

        #expect(!txt.contains("key2"))
        #expect(txt.values(forKey: "key2").isEmpty)
        #expect(txt.contains("key1"))
        #expect(txt.contains("key3"))
    }

    @Test("values(forKey:) - empty when key not found")
    func testValuesForKeyNotFound() {
        let txt = TXTRecord()
        #expect(txt.values(forKey: "nonexistent").isEmpty)
    }

    // MARK: - Multiple dnsaddr (libp2p Use Case)

    @Test("Multiple dnsaddr values - libp2p mDNS spec")
    func testMultipleDnsaddr() {
        var txt = TXTRecord()

        txt.appendValue("/ip4/192.168.1.1/tcp/4001/p2p/QmId1", forKey: "dnsaddr")
        txt.appendValue("/ip6/::1/tcp/4001/p2p/QmId1", forKey: "dnsaddr")
        txt.appendValue("/ip4/10.0.0.1/tcp/4001/p2p/QmId1", forKey: "dnsaddr")

        let values = txt.values(forKey: "dnsaddr")
        #expect(values.count == 3)
        #expect(values[0] == "/ip4/192.168.1.1/tcp/4001/p2p/QmId1")
        #expect(values[1] == "/ip6/::1/tcp/4001/p2p/QmId1")
        #expect(values[2] == "/ip4/10.0.0.1/tcp/4001/p2p/QmId1")
    }

    @Test("Multiple dnsaddr - subscript returns first only")
    func testMultipleDnsaddrSubscriptFirst() {
        var txt = TXTRecord()

        txt.appendValue("/ip4/192.168.1.1/tcp/4001", forKey: "dnsaddr")
        txt.appendValue("/ip6/::1/tcp/4001", forKey: "dnsaddr")

        // DNS-SD behavior: subscript returns first value
        #expect(txt["dnsaddr"] == "/ip4/192.168.1.1/tcp/4001")
    }

    // MARK: - Wire Format

    @Test("toStrings - preserves order")
    func testToStringsPreservesOrder() {
        var txt = TXTRecord()

        txt.appendValue("first", forKey: "key1")
        txt.appendValue("second", forKey: "key2")
        txt.appendValue("third", forKey: "key1")

        let strings = txt.toStrings()
        #expect(strings.count == 3)
        #expect(strings[0] == "key1=first")
        #expect(strings[1] == "key2=second")
        #expect(strings[2] == "key1=third")
    }

    @Test("toStrings - round trip")
    func testToStringsRoundTrip() {
        let original = [
            "dnsaddr=/ip4/127.0.0.1/tcp/4001",
            "dnsaddr=/ip6/::1/tcp/4001",
            "pubkey=abc123",
            "version=1.0"
        ]

        let txt1 = TXTRecord(strings: original)
        let reconstructed = txt1.toStrings()
        let txt2 = TXTRecord(strings: reconstructed)

        // Values should match
        #expect(txt1.values(forKey: "dnsaddr") == txt2.values(forKey: "dnsaddr"))
        #expect(txt1["pubkey"] == txt2["pubkey"])
        #expect(txt1["version"] == txt2["version"])
    }

    @Test("toStrings - boolean attributes")
    func testToStringsBooleanAttributes() {
        var txt = TXTRecord()
        txt.appendValue("", forKey: "flag1")
        txt.appendValue("", forKey: "flag2")

        let strings = txt.toStrings()
        #expect(strings.contains("flag1"))
        #expect(strings.contains("flag2"))
    }

    // MARK: - Index Rebuilding

    @Test("removeValues rebuilds index correctly")
    func testRemoveValuesRebuildsIndex() {
        var txt = TXTRecord(strings: [
            "a=1",
            "b=2",
            "c=3",
            "b=4",
            "d=5"
        ])

        txt.removeValues(forKey: "b")

        // Verify other keys still accessible
        #expect(txt["a"] == "1")
        #expect(txt["c"] == "3")
        #expect(txt["d"] == "5")
        #expect(!txt.contains("b"))
    }

    @Test("Multiple modifications maintain consistency")
    func testMultipleModificationsMaintainConsistency() {
        var txt = TXTRecord()

        // Add values
        txt.appendValue("v1", forKey: "key1")
        txt.appendValue("v2", forKey: "key2")
        txt.appendValue("v3", forKey: "key1")

        #expect(txt.values(forKey: "key1").count == 2)

        // Remove key2
        txt.removeValues(forKey: "key2")
        #expect(!txt.contains("key2"))
        #expect(txt.values(forKey: "key1").count == 2)

        // Set new values for key1
        txt.setValues(["new1", "new2"], forKey: "key1")
        #expect(txt.values(forKey: "key1") == ["new1", "new2"])

        // Add new key
        txt["key3"] = "v3"
        #expect(txt["key3"] == "v3")
    }

    // MARK: - Edge Cases

    @Test("Empty string value")
    func testEmptyStringValue() {
        var txt = TXTRecord()
        txt["key"] = ""

        #expect(txt.contains("key"))
        #expect(txt["key"] == "")
    }

    @Test("Value with equals sign")
    func testValueWithEqualsSign() {
        var txt = TXTRecord()
        txt["key"] = "value=with=equals"

        #expect(txt["key"] == "value=with=equals")
    }

    @Test("Empty strings array")
    func testEmptyStringsArray() {
        let txt = TXTRecord(strings: [])
        #expect(txt.isEmpty)
    }

    @Test("Strings with empty entries")
    func testStringsWithEmptyEntries() {
        let txt = TXTRecord(strings: ["", "key=value", ""])
        #expect(txt["key"] == "value")
        #expect(txt.toStrings().count == 1)
    }
}
