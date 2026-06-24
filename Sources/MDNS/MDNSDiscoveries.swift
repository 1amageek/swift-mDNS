/// Typed discovery sequence for `MDNSBrowser`.
///
/// Wraps an `AsyncStream<Result<MDNSService, MDNSError>>` so the facade can vend
/// `some AsyncSequence<MDNSService, MDNSError>` (typed throws) rather than an
/// untyped `AsyncThrowingStream`, whose `Failure` is pinned to `any Error`.

/// A typed async sequence of discovered services.
///
/// Iteration yields `MDNSService` values and throws `MDNSError`. A `.removed`
/// or `.updated` discovery is delivered as a fresh `MDNSService` value carrying
/// the current state; consumers key on `MDNSService.id` to deduplicate.
public struct MDNSDiscoveries: AsyncSequence, Sendable {
    public typealias Element = MDNSService
    public typealias Failure = MDNSError

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
    }

    @inlinable
    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(inner: base.makeAsyncIterator())
    }
}
