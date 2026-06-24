/// DNS-SD TXT Record helper (Tier-1 facade)
///
/// A string-keyed convenience over DNS TXT records per RFC 6763 Section 6.
/// Foundation-free. The raw `[UInt8]` TXT values live on `MDNSService.txt`; this
/// helper offers an ergonomic string-based API for building / parsing TXT
/// attributes.

/// A DNS TXT record containing key-value attributes.
///
/// Per RFC 6763 Section 6, TXT records contain zero or more strings,
/// each in the format "key=value" or just "key" for boolean attributes.
///
/// This implementation supports both DNS-SD (single value per key) and
/// libp2p extensions (multiple values per key, e.g. multiple `dnsaddr=` entries).
///
/// ## Design
///
/// - **Storage**: Raw DNS wire-string form (`[String]`) with index for O(1) lookup
/// - **DNS-SD API**: `subscript` returns the first value only (RFC 6763 compliant)
/// - **libp2p API**: `values(forKey:)`, `appendValue(_:forKey:)` for multiple values
public struct TXTRecord: Sendable, Hashable {

    // MARK: - Storage

    /// DNS wire-string form (preserves order).
    private var rawStrings: [String]

    /// Index for fast lookup (key -> indices into `rawStrings`).
    private var index: [String: [Int]]

    // MARK: - Initialization

    /// Creates an empty TXT record.
    public init() {
        self.rawStrings = []
        self.index = [:]
    }

    /// Creates a TXT record from DNS TXT strings.
    public init(strings: [String]) {
        // Filter out empty strings (per RFC 6763 Section 6.1)
        self.rawStrings = strings.filter { !$0.isEmpty }
        self.index = Self.buildIndex(from: rawStrings)
    }

    /// Creates a TXT record from key-value pairs.
    public init(_ attributes: [String: String]) {
        self.rawStrings = attributes.map { key, value in
            value.isEmpty ? key : "\(key)=\(value)"
        }.sorted()
        self.index = Self.buildIndex(from: rawStrings)
    }

    // MARK: - DNS-SD Compatible API (single value)

    /// Gets or sets the first value for a key (case-insensitive).
    ///
    /// Per RFC 6763, keys SHOULD NOT appear more than once.
    /// This subscript follows that convention by returning only the first value.
    public subscript(key: String) -> String? {
        get { values(forKey: key).first }
        set {
            removeValues(forKey: key)
            if let newValue {
                appendValue(newValue, forKey: key)
            }
        }
    }

    /// Whether the TXT record contains a key (case-insensitive).
    public func contains(_ key: String) -> Bool {
        !values(forKey: key).isEmpty
    }

    // MARK: - libp2p Extended API (multiple values)

    /// Returns all values for a key (case-insensitive).
    ///
    /// Use this when you need to access multiple values for the same key
    /// (e.g. libp2p's multiple `dnsaddr=` entries).
    public func values(forKey key: String) -> [String] {
        let lowercasedKey = key.lowercased()
        guard let indices = index[lowercasedKey] else { return [] }
        return indices.compactMap { idx in
            parseValue(from: rawStrings[idx], key: lowercasedKey)
        }
    }

    /// Appends a value for a key (case-insensitive).
    ///
    /// Unlike subscript assignment (which replaces all values),
    /// this method adds a new value while preserving existing ones.
    public mutating func appendValue(_ value: String, forKey key: String) {
        let string = value.isEmpty ? key : "\(key)=\(value)"
        rawStrings.append(string)
        let newIndex = rawStrings.count - 1
        let lowercasedKey = key.lowercased()
        index[lowercasedKey, default: []].append(newIndex)
    }

    /// Sets all values for a key (case-insensitive), replacing any existing values.
    public mutating func setValues(_ values: [String], forKey key: String) {
        removeValues(forKey: key)
        for value in values {
            appendValue(value, forKey: key)
        }
    }

    /// Removes all values for a key (case-insensitive).
    public mutating func removeValues(forKey key: String) {
        let lowercasedKey = key.lowercased()
        guard let indices = index[lowercasedKey] else { return }

        // Remove in reverse order to keep earlier indices valid.
        for idx in indices.sorted().reversed() {
            rawStrings.remove(at: idx)
        }

        // Rebuild the index.
        index = Self.buildIndex(from: rawStrings)
    }

    // MARK: - Wire Format

    /// Converts to DNS TXT string format.
    public func toStrings() -> [String] {
        rawStrings
    }

    /// Whether this TXT record is empty.
    public var isEmpty: Bool {
        rawStrings.isEmpty
    }

    // MARK: - Helpers

    private static func buildIndex(from strings: [String]) -> [String: [Int]] {
        var index: [String: [Int]] = [:]
        for (idx, string) in strings.enumerated() {
            if let equalIndex = string.firstIndex(of: "=") {
                let key = String(string[..<equalIndex]).lowercased()
                index[key, default: []].append(idx)
            } else if !string.isEmpty {
                let key = string.lowercased()
                index[key, default: []].append(idx)
            }
        }
        return index
    }

    private func parseValue(from string: String, key: String) -> String? {
        if let equalIndex = string.firstIndex(of: "=") {
            let k = String(string[..<equalIndex]).lowercased()
            if k == key {
                return String(string[string.index(after: equalIndex)...])
            }
        } else if string.lowercased() == key {
            return ""  // Boolean attribute
        }
        return nil
    }
}
