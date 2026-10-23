// Package jose provides the JOSE (JSON Object Signing and Encryption) components of
// the KrakenD API Gateway: validation of the JWT received by the endpoints and signing
// of the payloads returned by them.
//
// The validator is configured under the ValidatorNamespace of the endpoint extra config
// (see SignatureConfig and GetSignatureConfig) and built with NewValidator. Besides the
// signature, issuer and audience checks, the package offers helpers to authorize the
// requests by roles (AccessCheck, AccessNestedCheck) and scopes (AllScopesMatcher,
// AnyScopesMatcher), and to propagate claims to the backends as headers
// (NewPropagators, HeadersToPropagate).
//
// The signer is configured under the SignerNamespace of the endpoint extra config (see
// SignerConfig) and built with NewSigner. SignFields replaces fields of a response with
// their signed version.
//
// Keys are retrieved from a remote JWK endpoint or a local file through a JWKClient
// (see SecretProvider), with support for certificate pinning, custom root CAs, several
// key identify strategies and in-memory caches that can be shared between endpoints
// (see SetGlobalCacher).
//
// Tokens can also be rejected by custom rules after their validation (see Rejecter and
// RejecterFactory).
//
// The router integrations live in the gin and mux subpackages.
package jose
