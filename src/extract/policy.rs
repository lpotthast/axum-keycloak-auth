/// Controls how errors from one token extractor affect lower-priority extractors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TokenExtractionErrorPolicy {
    /// Ignore an unusable credential source and try the next configured extractor.
    #[default]
    Fallback,

    /// Reject authentication when a present credential source is unusable.
    ///
    /// This prevents a request that carries, for example, a malformed `Authorization` header and a
    /// valid query token from authenticating with the query token.
    ///
    /// An absent source, reported by an extractor as `Ok(None)`, still falls through to the next
    /// extractor. Any error rejects the request.
    Reject,
}
