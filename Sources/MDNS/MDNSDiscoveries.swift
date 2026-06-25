/// Typed discovery sequence for `MDNSBrowser`.
///
/// Wraps an `AsyncStream<Result<MDNSService, MDNSError>>` so the facade can vend
/// `some AsyncSequence<MDNSService, MDNSError>` (typed throws) rather than an
/// untyped `AsyncThrowingStream`, whose `Failure` is pinned to `any Error`.

import _Concurrency   // REQUIRED under Embedded for AsyncSequence/AsyncStream

/// A typed async sequence of discovered services.
///
/// Iteration yields `MDNSService` values and throws `MDNSError`. A `.removed`
/// or `.updated` discovery is delivered as a fresh `MDNSService` value carrying
/// the current state; consumers key on `MDNSService.id` to deduplicate.
public struct MDNSDiscoveries: AsyncSequence, Sendable {
    public typealias Element = MDNSService
    #if !hasFeature(Embedded)
    // On host the typed `Failure` lets a consumer's `for try await … catch`
    // surface a systemic browser error (swift-libp2p relies on this). Under
    // Embedded, `AsyncIteratorProtocol` cannot carry a typed throw without erasing
    // it to `any Error`, so the Embedded iterator is non-throwing and terminates
    // on a failure (the same shape as `POSIXIncomingDatagrams`).
    public typealias Failure = MDNSError
    #endif

    @usableFromInline
    let base: AsyncStream<Result<MDNSService, MDNSError>>

    @usableFromInline
    init(base: AsyncStream<Result<MDNSService, MDNSError>>) {
        self.base = base
    }

    public struct AsyncIterator: AsyncIteratorProtocol {
        @usableFromInline
        var inner: AsyncStream<Result<MDNSService, MDNSError>>.AsyncIterator

        @usableFromInline
        init(inner: AsyncStream<Result<MDNSService, MDNSError>>.AsyncIterator) {
            self.inner = inner
        }

        #if !hasFeature(Embedded)
        @inlinable
        public mutating func next() async throws(MDNSError) -> MDNSService? {
            guard let result = await inner.next() else { return nil }
            switch result {
            case .success(let service):
                return service
            case .failure(let error):
                throw error
            }
        }
        #else
        @inlinable
        public mutating func next() async -> MDNSService? {
            // Embedded: a failure terminates the sequence rather than throwing
            // (typed throws cannot cross `AsyncIteratorProtocol` under Embedded).
            guard let result = await inner.next() else { return nil }
            switch result {
            case .success(let service):
                return service
            case .failure:
                return nil
            }
        }
        #endif
    }

    @inlinable
    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(inner: base.makeAsyncIterator())
    }
}
