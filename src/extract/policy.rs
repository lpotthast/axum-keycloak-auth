/// Controls how errors from one token extractor affect lower-priority extractors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TokenExtractionErrorPolicy {
    /// Ignore an unusable credential source and try the next configured extractor.
    ///
    /// This is the default and preserves the behavior of earlier releases.
    #[default]
    Fallback,

    /// Reject authentication when a present credential source is unusable.
    ///
    /// This prevents a request that carries, for example, a malformed `Authorization` header and a
    /// valid query token from authenticating with the query token.
    ///
    /// Custom extractors must report an absent source with a missing-credential
    /// [`crate::error::AuthError`] variant, preferably [`crate::error::AuthError::MissingToken`].
    /// Any other error rejects the request. The built-in extractors classify absence correctly.
    Reject,
}
