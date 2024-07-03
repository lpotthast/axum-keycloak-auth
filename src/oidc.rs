use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// See: `https://openid.net/specs/openid-connect-discovery-1_0.html#WellKnownContents`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OidcConfig {
    #[serde(flatten)]
    pub standard_claims: OpenIDConnectStandardDiscoveryClaims,

    #[serde(flatten)]
    pub session_claims: OidcDiscoverySessionDiscoveryClaims,

    #[serde(flatten)]
    pub front_channel_logout_claims: OpenIDConnectFrontChannelLogoutDiscoveryClaims,

    #[serde(flatten)]
    pub back_channel_logout_claims: OpenIDConnectBackChannelLogoutDiscoveryClaims,

    #[serde(flatten)]
    pub oauth_claims: OAuthDiscoveryClaims,

    #[serde(flatten)]
    pub jarm_claims: OpenIDConnectJARMDiscoveryClaims,

    #[serde(flatten)]
    pub rp_initialized_claims: OpenIDConnectRPInitiatedLogoutClaims,

    /// OPTIONAL. Session ID - String identifier for a Session.
    /// This represents a Session of a User Agent or device for a logged-in End-User at an RP.
    /// Different sid values are used to identify distinct sessions at an OP.
    /// The sid value need only be unique in the context of a particular issuer.
    /// Its contents are opaque to the RP.
    /// Its syntax is the same as an OAuth 2.0 Client Identifier.
    pub sid: Option<String>, // Note: Moved here, as it would otherwise need to be defined in both OpenIDConnectFrontChannelLogoutDiscoveryClaims and OpenIDConnectBackChannelLogoutDiscoveryClaims

    /// Contains all the additional fields not otherwise parsable.
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

/// See: `https://www.rfc-editor.org/rfc/rfc8414.html#section-2`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthDiscoveryClaims {
    /// OPTIONAL. URL of the authorization server's OAuth 2.0
    /// introspection endpoint [RFC7662].
    introspection_endpoint: Option<String>,

    /// OPTIONAL. JSON array containing a list of client authentication
    /// methods supported by this introspection endpoint.  The valid
    /// client authentication method values are those registered in the
    /// IANA "OAuth Token Endpoint Authentication Methods" registry
    /// [IANA.OAuth.Parameters] or those registered in the IANA "OAuth
    /// Access Token Types" registry [IANA.OAuth.Parameters].  (These
    /// values are and will remain distinct, due to Section 7.2.)  If
    /// omitted, the set of supported authentication methods MUST be
    /// determined by other means.
    introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWS signing
    /// algorithms ("alg" values) supported by the introspection endpoint
    /// for the signature on the JWT (JWT) used to authenticate the client
    /// at the introspection endpoint for the "private_key_jwt" and
    /// "client_secret_jwt" authentication methods.  This metadata entry
    /// MUST be present if either of these authentication methods are
    /// specified in the "introspection_endpoint_auth_methods_supported"
    /// entry.  No default algorithms are implied if this entry is
    /// omitted.  The value "none" MUST NOT be used.
    introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
}

/// See: `https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenIDConnectFrontChannelLogoutDiscoveryClaims {
    /// OPTIONAL. Boolean value specifying whether the OP supports HTTP-based logout, with true indicating support.
    /// If omitted, the default value is false.
    /// It SHOULD also register this related metadata value:
    pub frontchannel_logout_supported: Option<bool>,

    /// OPTIONAL. Boolean value specifying whether the OP can pass iss (issuer) and sid (session ID) query parameters to identify the RP session with the OP when the frontchannel_logout_uri is used.
    /// If supported, the sid Claim is also included in ID Tokens issued by the OP.
    /// If omitted, the default value is false.
    /// The sid (session ID) Claim used in ID Tokens and as a frontchannel_logout_uri parameter has the following definition:
    pub frontchannel_logout_session_supported: Option<bool>,
    // Omitted the `sid` field. It would have to be defined in multiple places, so we simple added it to `OidcConfig` directly.
}

/// See: `https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenIDConnectBackChannelLogoutDiscoveryClaims {
    /// OPTIONAL. Boolean value specifying whether the OP supports back-channel logout, with true indicating support.
    /// If omitted, the default value is false.
    pub backchannel_logout_supported: Option<bool>,

    /// OPTIONAL. Boolean value specifying whether the OP can pass a sid (session ID) Claim in the Logout Token to identify the RP session with the OP.
    /// If supported, the sid Claim is also included in ID Tokens issued by the OP.
    /// If omitted, the default value is false.
    pub backchannel_logout_session_supported: Option<bool>,
    // Omitted the `sid` field. It would have to be defined in multiple places, so we simple added it to `OidcConfig` directly.
}

/// See: `https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenIDConnectRPInitiatedLogoutClaims {
    /// REQUIRED. URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.
    /// This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
    pub end_session_endpoint: Option<String>, // Note: Required, but we do not now if the extension is even used...
}

/// See: `https://openid.net/specs/oauth-v2-jarm.html#name-authorization-server-metada`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenIDConnectJARMDiscoveryClaims {
    /// OPTIONAL. A JSON array containing a list of the JWS (RFC7515) signing algorithms (alg values) supported by the authorization endpoint to sign the response.
    pub authorization_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. A JSON array containing a list of the JWE (RFC7516) encryption algorithms (alg values) supported by the authorization endpoint to encrypt the response.
    pub authorization_encryption_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. A JSON array containing a list of the JWE (RFC7516) encryption algorithms (enc values) supported by the authorization endpoint to encrypt the response.
    pub authorization_encryption_enc_values_supported: Option<Vec<String>>,
}

/// See: `https://openid.net/specs/openid-connect-session-1_0.html#OPMetadata`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OidcDiscoverySessionDiscoveryClaims {
    /// REQUIRED. URL of an OP iframe that supports cross-origin communications for session state information with the RP Client, using the HTML5 postMessage API.
    /// This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
    /// The page is loaded from an invisible iframe embedded in an RP page so that it can run in the OP's security context.
    /// It accepts postMessage requests from the relevant RP iframe and uses postMessage to post back the login status of the End-User at the OP.
    pub check_session_iframe: Option<String>, // Note: Required, but we do not now if the extension is even used...
}

/// See: `https://openid.net/specs/openid-connect-discovery-1_0.html#WellKnownContents`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenIDConnectStandardDiscoveryClaims {
    /// REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.
    /// If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value returned by WebFinger.
    /// This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
    pub issuer: String,

    /// REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
    pub authorization_endpoint: String,

    /// OPTIONAL: URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core].
    /// This is REQUIRED unless only the Implicit Flow is used.
    pub token_endpoint: Option<String>,

    /// RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core].
    /// This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
    pub userinfo_endpoint: Option<String>,

    /// REQUIRED. URL of the OP's JSON Web Key Set (JWK) document.
    /// This contains the signing key(s) the RP uses to validate signatures from the OP.
    /// The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt requests to the Server.
    /// When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
    /// Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure.
    /// The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
    pub jwks_uri: String,

    /// RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].
    pub registration_endpoint: Option<String>,

    /// RECOMMENDED. JSON array containing a list of the OAuth 2.0 (RFC6749) scope values that this server supports.
    /// The server MUST support the openid scope value.
    /// Servers MAY choose not to advertise some supported scope values even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
    pub scopes_supported: Option<Vec<String>>,

    /// REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.
    /// Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
    pub response_types_supported: Vec<String>,

    /// OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses].
    /// If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
    pub response_modes_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
    /// Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types.
    /// If omitted, the default value is ["authorization_code", "implicit"].
    pub grant_types_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
    pub acr_values_supported: Option<Vec<String>>,

    /// REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports.
    /// Valid types include pairwise and public.
    pub subject_types_supported: Vec<String>,

    /// REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT (JWT).
    /// The algorithm RS256 MUST be included.
    /// The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow).
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT (JWT).
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT (JWT).
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWS (JWS) signing algorithms (alg values) (JWA) supported by the UserInfo Endpoint to encode the Claims in a JWT (JWT).
    /// The value none MAY be included.
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWE (JWE) encryption algorithms (alg values) (JWA) supported by the UserInfo Endpoint to encode the Claims in a JWT (JWT).
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) (JWA) supported by the UserInfo Endpoint to encode the Claims in a JWT (JWT).
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core].
    /// These algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
    /// Servers SHOULD support none and RS256.
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for Request Objects.
    /// These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects.
    /// These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
    /// The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core].
    /// Other authentication methods MAY be defined by extensions.
    /// If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 (RFC6749).
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for the signature on the JWT (JWT)
    /// used to authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods.
    /// Servers SHOULD support RS256. The value none MUST NOT be used.
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports.
    /// These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
    pub display_values_supported: Option<Vec<String>>,

    /// OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports.
    /// These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core].
    /// Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
    pub claim_types_supported: Option<Vec<String>>,

    /// RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.
    /// Note that for privacy or other reasons, this might not be an exhaustive list.
    pub claims_supported: Option<Vec<String>>,

    /// OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider.
    /// In particular, if the OpenID Provider does not support Dynamic Client Registration, then information on how to register Clients needs to be provided in this documentation.
    pub service_documentation: Option<String>,

    /// OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of BCP47 (RFC5646) language tag values.
    /// Not all languages and scripts are necessarily supported for all Claim values.
    pub claims_locales_supported: Option<Vec<String>>,

    /// OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 (RFC5646) language tag values.
    pub ui_locales_supported: Option<Vec<String>>,

    /// OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support.
    /// If omitted, the default value is false.
    pub claims_parameter_supported: Option<bool>,

    /// OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating support.
    /// If omitted, the default value is false.
    pub request_parameter_supported: Option<bool>,

    /// OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support.
    /// If omitted, the default value is true.
    pub request_uri_parameter_supported: Option<bool>,

    /// OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter.
    /// Pre-registration is REQUIRED when the value is true.
    /// If omitted, the default value is false.
    pub require_request_uri_registration: Option<bool>,

    /// OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP.
    /// The registration process SHOULD display this URL to the person registering the Client if it is given.
    pub op_policy_uri: Option<String>,

    /// OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service.
    /// The registration process SHOULD display this URL to the person registering the Client if it is given.
    pub op_tos_uri: Option<String>,
}
