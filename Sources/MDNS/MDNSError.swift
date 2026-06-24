/// MDNS Errors
///
/// The single public error type for the Tier-1 `MDNS` facade.

import DNSWire

/// Errors surfaced by the `MDNS` facade (`MDNSBrowser` / `MDNSResponder`).
///
/// This is the one public, exhaustive error enum for the facade. The Tier-3
/// `DNSWire` codec keeps its own `DNSError`; where a codec failure reaches the
/// facade it is wrapped as `.codec(_:)` so a caller has a single `catch`.
public enum MDNSError: Error, Equatable, Sendable {
    /// The facade was used before `start()`/before being ready.
    case notStarted

    /// A required field was missing or invalid (e.g. a service without a port).
    case invalidService(String)

    /// The requested service was not registered.
    case serviceNotFound(String)

    /// The network transport for the requested address family is unavailable.
    case transportUnavailable(String)

    /// A network-level failure occurred.
    case networkError(String)

    /// The underlying DNS wire codec rejected a message.
    case codec(DNSError)

    /// Maps an arbitrary transport / codec error to an `MDNSError`.
    ///
    /// A `DNSError` becomes `.codec`; anything else becomes `.networkError` with
    /// the supplied context. Performed in a non-typed-throws context so that
    /// callers inside `throws(MDNSError)` functions need only a single bare
    /// `catch` plus one `throw` of a precomputed value.
    static func mapping(_ error: any Error, context: String) -> MDNSError {
        if let dnsError = error as? DNSError {
            return .codec(dnsError)
        }
        return .networkError("\(context): \(error)")
    }
}
