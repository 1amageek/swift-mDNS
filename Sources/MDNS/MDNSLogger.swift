/// The facade's logger seam.
///
/// `swift-log`'s `Logging.Logger` is host-only (it imports Foundation), so the
/// facade addresses logging through `MDNSLogger`:
///
///   Logging present: MDNSLogger = Logging.Logger   (the real logger)
///   no Logging:      MDNSLogger = a no-op shim with the same `debug/info/error` surface
///
/// Both expose `debug` / `info` / `error` taking an `@autoclosure () -> String`,
/// so every `logger?.debug("…")` call site compiles unchanged in both builds and
/// the message is never evaluated under Embedded (the closure is dropped). The
/// public `Configuration.logger` property is itself host-only (`Logging.Logger`
/// has no Embedded analogue); the internal `logger` accessor returns `nil` under
/// Embedded, so all logging compiles to nothing.

#if !hasFeature(Embedded) && canImport(Logging)
import Logging

/// On host the facade logger is the standard `swift-log` `Logger`.
typealias MDNSLogger = Logger

#else

/// No-op logger: the same `debug/info/error` surface as `swift-log`'s `Logger`,
/// evaluating to nothing. Present so logging call sites type-check where
/// `swift-log` is not part of the module graph.
struct MDNSLogger: Sendable {
    @inline(__always) func debug(_ message: @autoclosure () -> String) {}
    @inline(__always) func info(_ message: @autoclosure () -> String) {}
    @inline(__always) func error(_ message: @autoclosure () -> String) {}
    @inline(__always) func warning(_ message: @autoclosure () -> String) {}
}
#endif
