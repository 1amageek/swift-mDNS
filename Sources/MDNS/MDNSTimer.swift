/// The facade's timer seam selection.
///
/// `MDNSBrowser` / `MDNSResponder` schedule their periodic query / announcement
/// refresh and the per-announcement back-off through the `AsyncTimer` seam
/// (declared in `P2PCoreCrypto`) rather than `Task.sleep` / `ContinuousClock`,
/// both of which are `@available(*, unavailable)` under Embedded Swift. The
/// facade stores a concrete `MDNSDefaultTimer` (no `any`); this file is the only
/// place that selects which concrete timer the build uses.
///
///   host  (default):   MDNSDefaultTimer = MDNSHostTimer   (ContinuousClock + Task.sleep)
///   Embedded POSIX:    MDNSDefaultTimer = MDNSEmbeddedTimer (clock_gettime + park)
///   Embedded WASI:     MDNSDefaultTimer = MDNSUnavailableTimer
///
/// The mDNS package defines its own timers (rather than depending on
/// swift-p2p-transport's `DefaultAsyncTimer`) so the Embedded build is driven by
/// the SAME `P2P_CORE_EMBEDDED=1` flag as the rest of this package — pulling in
/// `P2PTransportPOSIX` would key its Embedded mode off a different flag
/// (`P2P_TRANSPORT_EMBEDDED`) and desynchronise the Embedded module graph.

import P2PCoreCrypto

extension Duration {
    /// This duration as whole nanoseconds (saturating, non-negative), for the
    /// `AsyncTimer.sleep(untilNanos:)` deadline math. `components` is Embedded-clean
    /// (unlike `ContinuousClock`), so this works in both builds.
    var facadeNanoseconds: UInt64 {
        let (seconds, attoseconds) = components
        let secNanos = UInt64(max(0, seconds)) &* 1_000_000_000
        let fracNanos = UInt64(max(0, attoseconds) / 1_000_000_000)
        return secNanos &+ fracNanos
    }
}

#if hasFeature(Embedded) && canImport(WASILibc)
import _Concurrency

/// The Embedded WASI default timer. The default WASI transport fails at start, so
/// periodic loops never depend on a real clock in this build configuration.
typealias MDNSDefaultTimer = MDNSUnavailableTimer

struct MDNSUnavailableTimer: AsyncTimer {
    init() {}

    func monotonicNanos() -> UInt64 {
        0
    }

    func monotonicMillis() -> UInt64 {
        0
    }

    func sleep(untilNanos deadlineNanos: UInt64) async throws(CancellationError) {
        if Task.isCancelled {
            throw CancellationError()
        }
    }
}

#elseif !hasFeature(Embedded)
import _Concurrency

/// The host default timer: `ContinuousClock` for time, `Task.sleep` for the wait.
typealias MDNSDefaultTimer = MDNSHostTimer

/// A host `AsyncTimer` backed by `ContinuousClock` + `Task.sleep(until:clock:)`.
struct MDNSHostTimer: AsyncTimer {
    private let origin: ContinuousClock.Instant
    private let clock = ContinuousClock()

    init() {
        self.origin = ContinuousClock.now
    }

    func monotonicNanos() -> UInt64 {
        let elapsed = ContinuousClock.now - origin
        let (seconds, attoseconds) = elapsed.components
        return UInt64(max(0, seconds)) &* 1_000_000_000
            &+ UInt64(max(0, attoseconds) / 1_000_000_000)
    }

    func monotonicMillis() -> UInt64 {
        monotonicNanos() / 1_000_000
    }

    func sleep(untilNanos deadlineNanos: UInt64) async throws(CancellationError) {
        let now = monotonicNanos()
        if deadlineNanos <= now { return }
        let waitNanos = deadlineNanos - now
        let instant = ContinuousClock.now.advanced(by: .nanoseconds(waitNanos))
        do {
            try await Task.sleep(until: instant, clock: clock)
        } catch {
            // `Task.sleep` throws only `CancellationError`; re-surface it typed.
            throw CancellationError()
        }
    }
}

#else
import _Concurrency

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// The Embedded default timer: `clock_gettime(CLOCK_MONOTONIC)` for time.
typealias MDNSDefaultTimer = MDNSEmbeddedTimer

/// An Embedded-clean `AsyncTimer` over the POSIX C library.
///
/// `monotonicNanos()` reads `CLOCK_MONOTONIC`. `sleep(untilNanos:)` parks on a
/// detached thread running a sliced `nanosleep`, honoring cancellation between
/// slices. Embedded-clean: only the platform C library + `_Concurrency`; no
/// Foundation, no NIO, no `any`, no `ContinuousClock`, no `Task.sleep`.
///
/// In the current Embedded `MDNS` build this timer never actually parks: the
/// Embedded transport fails `start()` (multicast is unavailable), so the periodic
/// query / announcement loops that would call `sleep` never run. It is present so
/// the facade type-checks and links under Embedded with a real `AsyncTimer`. A
/// production embedder is expected to inject its own timer parked on the
/// platform's real executor.
struct MDNSEmbeddedTimer: AsyncTimer {

    init() {}

    func monotonicNanos() -> UInt64 {
        Self.nowNanos()
    }

    func monotonicMillis() -> UInt64 {
        Self.nowNanos() / 1_000_000
    }

    func sleep(untilNanos deadlineNanos: UInt64) async throws(CancellationError) {
        if Task.isCancelled { throw CancellationError() }
        if deadlineNanos <= Self.nowNanos() { return }

        // Park in fixed slices, re-checking cancellation and the deadline each
        // slice. A throwing continuation (`any Error`) is forbidden under
        // Embedded, so this loops with short non-throwing suspensions rather than
        // resuming a thrown error across a continuation boundary.
        let sliceNanos: UInt64 = 20_000_000   // 20 ms
        while true {
            if Task.isCancelled { throw CancellationError() }
            let now = Self.nowNanos()
            if now >= deadlineNanos { return }
            let remaining = deadlineNanos - now
            Self.nanosleepFor(min(remaining, sliceNanos))
        }
    }

    @inline(__always)
    static func nowNanos() -> UInt64 {
        var ts = timespec()
        let result = clock_gettime(CLOCK_MONOTONIC, &ts)
        precondition(result == 0, "clock_gettime(CLOCK_MONOTONIC) failed")
        let seconds = UInt64(ts.tv_sec)
        let nanos = UInt64(ts.tv_nsec)
        return seconds &* 1_000_000_000 &+ nanos
    }

    @inline(__always)
    static func nanosleepFor(_ nanos: UInt64) {
        var req = timespec(
            tv_sec: Int(nanos / 1_000_000_000),
            tv_nsec: Int(nanos % 1_000_000_000)
        )
        var rem = timespec()
        _ = nanosleep(&req, &rem)
    }
}

#endif
