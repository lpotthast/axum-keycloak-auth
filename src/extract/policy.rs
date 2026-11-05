/// Controls how an unusable credential source affects lower-priority extractors.
///
/// An absent source, reported by an extractor as `Ok(None)`, always falls through to the next
/// extractor. The policy only decides what happens when a source is present but unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TokenExtractionErrorPolicy {
    /// Reject authentication when a present credential source is unusable. This is the default.
    ///
    /// RFC 6750 forbids clients to send a token by more than one method in a request. This policy
    /// therefore prevents a request that carries, for example, a malformed `Authorization: Bearer`
    /// header and a valid query token from authenticating with the query token.
    #[default]
    Reject,

    /// Ignore an unusable credential source and try the next configured extractor.
    ///
    /// This accepts requests that send a malformed token by one method and a valid one by
    /// another, which RFC 6750 forbids clients to do. Use it only for clients that cannot be
    /// fixed.
    Fallthrough,
}
