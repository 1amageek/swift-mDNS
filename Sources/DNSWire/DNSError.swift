/// DNS Errors
///
/// Error types for DNS/mDNS operations.

/// Errors that can occur during DNS operations.
public enum DNSError: Error, Sendable, Equatable {
    /// The DNS name is invalid.
    case invalidName(String)

    /// The DNS message is malformed.
    case invalidMessage(String)

    /// The DNS record type is not supported.
    case unsupportedRecordType(UInt16)

    /// The data is truncated or incomplete.
    case truncatedData

    /// The operation timed out.
    case timeout

    /// Network error occurred.
    case networkError(String)

    /// No response received.
    case noResponse

    /// Service not found.
    case serviceNotFound(String)

    /// The transport required for the requested address family is unavailable.
    case transportUnavailable(String)
}
