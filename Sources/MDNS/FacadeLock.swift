/// The facade's value-protecting lock — `Synchronization.Mutex` on host, an
/// `Atomic`-spinlock box under Embedded (where `Synchronization.Mutex` is
/// unavailable).
///
/// The Tier-1 `MDNS` facade actors (`MDNSBrowser` / `MDNSResponder`) already
/// serialise their own mutable state through actor isolation; this lock guards
/// the small pieces of `Sendable` state shared with the host transport's
/// detached receive loops (e.g. the decode-failure counter) that the swift-tls
/// facade pattern keeps behind a uniform lock seam. It mirrors swift-tls's
/// `FacadeLock` byte-for-byte so the two facades share one lock story.
///
/// Host: `FacadeLock<V>` IS `Synchronization.Mutex<V>` (same `init(_:)` and
/// `withLock { … }` surface).
///
/// Embedded: `Mutex` is not provided by `Synchronization`, so `FacadeLock<V>` is a
/// `final class` holding the value behind a tiny test-and-test-and-set spinlock over
/// `Atomic<Bool>`. `nonisolated(unsafe)` on the storage (NOT `@unchecked Sendable`)
/// confines the unsafety to the storage member; the spinlock provides the mutual
/// exclusion that makes the access safe. Embedded targets are typically single- or
/// few-threaded, so contention is negligible; correctness (not throughput) is the goal.

#if !hasFeature(Embedded)
import Synchronization

/// On host the facade lock is the standard `Synchronization.Mutex`.
typealias FacadeLock<Value> = Mutex<Value>

#else
import Synchronization

/// Embedded facade lock: an `Atomic<Bool>` spinlock guarding the stored value.
/// `withLock` is non-throwing (every facade call site stays non-throwing inside
/// the closure).
final class FacadeLock<Value>: Sendable {
    private let locked = Atomic<Bool>(false)
    private nonisolated(unsafe) var value: Value

    init(_ value: Value) {
        self.value = value
    }

    /// Runs `body` with exclusive access to the protected value.
    func withLock<R>(_ body: (inout Value) -> R) -> R {
        // Test-and-test-and-set acquire.
        while true {
            if locked.compareExchange(
                expected: false, desired: true, ordering: .acquiring
            ).exchanged {
                break
            }
        }
        defer { locked.store(false, ordering: .releasing) }
        return body(&value)
    }
}
#endif
