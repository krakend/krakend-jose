package jose

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/textproto"
	"strconv"
	"strings"
	"unicode"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/krakend/go-auth0/v2"
	"github.com/luraproject/lura/v3/config"
)

const (
	// ValidatorNamespace is the extra config namespace of the JWT validator
	ValidatorNamespace = "auth/validator"
	// SignerNamespace is the extra config namespace of the JWT signer
	SignerNamespace = "auth/signer"
	defaultRolesKey = "roles"
)

// SignatureConfig is the configuration of the JWT validator, declared under the
// ValidatorNamespace of the endpoint extra config.
type SignatureConfig struct {
	// Alg is the algorithm used to sign the tokens (see SupportedAlgorithm)
	Alg string `json:"alg"`
	// AuthHeaderName is the header holding the token
	AuthHeaderName string `json:"auth_header_name,omitempty"`
	// URI is the URL of the JWK endpoint
	URI string `json:"jwk_url"`
	// CacheEnabled enables the in-memory cache of the keys
	CacheEnabled bool `json:"cache,omitempty"`
	// CacheDuration is the max age of the cached keys, in seconds
	CacheDuration uint32 `json:"cache_duration,omitempty"`
	// Issuer is the expected value of the iss claim
	Issuer string `json:"issuer,omitempty"`
	// Audience is the list of accepted values of the aud claim
	Audience []string `json:"audience,omitempty"`
	// Roles is the list of roles granting access (any of them is enough)
	Roles []string `json:"roles,omitempty"`
	// PropagateClaimsToHeader is a list of [claim, header] pairs to propagate to the backends
	PropagateClaimsToHeader [][]string `json:"propagate_claims,omitempty"`
	// PropagateClaimsPreserveArray propagates array claims as multiple header values
	PropagateClaimsPreserveArray bool `json:"propagate_claims_preserve_array"`
	// RolesKey is the claim holding the roles (defaults to "roles")
	RolesKey string `json:"roles_key,omitempty"`
	// RolesKeyIsNested enables the dot notation in RolesKey (see ShouldExtractNested)
	RolesKeyIsNested bool `json:"roles_key_is_nested,omitempty"`
	// CookieKey is the cookie holding the token, when it is not sent in a header
	CookieKey string `json:"cookie_key,omitempty"`
	// CipherSuites are the TLS cipher suites to use with the JWK endpoint
	CipherSuites []uint16 `json:"cipher_suites,omitempty"`
	// DisableJWKSecurity allows plain http and invalid certificates on the JWK endpoint
	DisableJWKSecurity bool `json:"disable_jwk_security"`
	// Fingerprints are the base64 encoded SHA-256 fingerprints of the pinned public keys
	Fingerprints []string `json:"jwk_fingerprints,omitempty"`
	// LocalCA is the path of a PEM file with extra root CAs to trust
	LocalCA string `json:"jwk_local_ca,omitempty"`
	// LocalPath is the path of a local file with the JWK set, used instead of URI
	LocalPath string `json:"jwk_local_path,omitempty"`
	// SecretURL is the URL of the secret keeper used to decrypt the file at LocalPath
	SecretURL string `json:"secret_url,omitempty"`
	// CipherKey is the encrypted key used to decrypt the file at LocalPath
	CipherKey []byte `json:"cypher_key,omitempty"`
	// Scopes is the list of required scopes
	Scopes []string `json:"scopes,omitempty"`
	// ScopesKey is the claim holding the scopes, in dot notation
	ScopesKey string `json:"scopes_key,omitempty"`
	// ScopesMatcher is the scope validation strategy: "all" or "any" (default)
	ScopesMatcher string `json:"scopes_matcher,omitempty"`
	// KeyIdentifyStrategy selects how keys are matched with tokens (see TokenIDGetterFactory)
	KeyIdentifyStrategy string `json:"key_identify_strategy"`
	// OperationDebug logs the reasons why a token was rejected
	OperationDebug bool `json:"operation_debug,omitempty"`
	// Leeway is the tolerated clock skew when validating time claims (defaults to 1s)
	Leeway string `json:"leeway"`
	// UnknownKeysTTL is the cooldown for keys not found in the JWK (see JWKClientOptions)
	UnknownKeysTTL string `json:"failed_jwk_key_cooldown"`
	// WWWAuthenticate is the header advertising the HTTP authentication methods
	// or challenges that might be used to gain access
	WWWAuthenticate *WWWAuthenticateHeader `json:"www_authenticate"`
}

// SignerConfig is the configuration of the JWT signer, declared under the
// SignerNamespace of the endpoint extra config.
type SignerConfig struct {
	// Alg is the algorithm used to sign the tokens
	Alg string `json:"alg"`
	// KeyID is the id of the signing key in the JWK
	KeyID string `json:"kid"`
	// Type is the value of the typ header (defaults to "JWT")
	Type string `json:"typ"`
	// URI is the URL of the JWK endpoint
	URI string `json:"jwk_url"`
	// FullSerialization enables the JSON serialization instead of the compact one
	FullSerialization bool `json:"full,omitempty"`
	// KeysToSign are the fields of the response to replace with signed tokens
	KeysToSign []string `json:"keys_to_sign,omitempty"`
	// CipherSuites are the TLS cipher suites to use with the JWK endpoint
	CipherSuites []uint16 `json:"cipher_suites,omitempty"`
	// DisableJWKSecurity allows plain http and invalid certificates on the JWK endpoint
	DisableJWKSecurity bool `json:"disable_jwk_security"`
	// Fingerprints are the base64 encoded SHA-256 fingerprints of the pinned public keys
	Fingerprints []string `json:"jwk_fingerprints,omitempty"`
	// LocalCA is the path of a PEM file with extra root CAs to trust
	LocalCA string `json:"jwk_local_ca,omitempty"`
	// LocalPath is the path of a local file with the JWK set, used instead of URI
	LocalPath string `json:"jwk_local_path,omitempty"`
	// SecretURL is the URL of the secret keeper used to decrypt the file at LocalPath
	SecretURL string `json:"secret_url,omitempty"`
	// CipherKey is the encrypted key used to decrypt the file at LocalPath
	CipherKey []byte `json:"cypher_key,omitempty"`
}

type AuthenticateParam struct {
	Key string `json:"key"`
	Val string `json:"value"`
}

func (p *AuthenticateParam) String() string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	b.Grow(p.len())
	p.writeTo(&b)
	return b.String()
}

// len returns the expected length of the rendered param, assuming
// that its value does not need escaping.
func (p *AuthenticateParam) len() int {
	return len(p.Key) + len(p.Val) + 3 // = and the two quotes
}

// writeTo renders the param as key="value". The value is quoted
// the same way as with %q.
func (p *AuthenticateParam) writeTo(b *strings.Builder) {
	var scratch [64]byte
	b.WriteString(p.Key)
	b.WriteByte('=')
	b.Write(strconv.AppendQuote(scratch[:0], p.Val))
}

type WWWAuthenticateHeader struct {
	AuthScheme string              `json:"auth_scheme"`
	Token68    string              `json:"token68"`
	Params     []AuthenticateParam `json:"params"`
}

// Validate checks that the header can be rendered as a valid challenge.
// A nil header is valid (the header is disabled).
func (h *WWWAuthenticateHeader) Validate() error {
	if h == nil {
		return nil
	}
	if h.AuthScheme == "" {
		return errors.New("auth_scheme cannot be empty")
	}
	if strings.IndexFunc(h.AuthScheme, unicode.IsSpace) >= 0 {
		return errors.New("auth_scheme cannot have spaces")
	}
	if h.Token68 != "" {
		if len(h.Params) > 0 {
			return errors.New("cannot have both token68 and params")
		}
		if strings.IndexFunc(h.Token68, unicode.IsSpace) >= 0 {
			return errors.New("token68 cannot have spaces")
		}
	}
	return nil
}

// String renders the header value. It returns an empty string when the
// header is not configured, meaning that no header should be sent.
func (h *WWWAuthenticateHeader) String() string {
	if h == nil || h.AuthScheme == "" {
		return ""
	}
	if h.Token68 != "" {
		return h.AuthScheme + " " + h.Token68
	}
	if len(h.Params) == 0 {
		return h.AuthScheme
	}
	const sep = ", "
	n := len(h.AuthScheme) + 1 + len(sep)*(len(h.Params)-1)
	for i := range h.Params {
		n += h.Params[i].len()
	}
	var b strings.Builder
	b.Grow(n)
	b.WriteString(h.AuthScheme)
	b.WriteByte(' ')
	for i := range h.Params {
		if i > 0 {
			b.WriteString(sep)
		}
		h.Params[i].writeTo(&b)
	}
	return b.String()
}

var (
	// ErrNoValidatorCfg is returned when the validator namespace is not configured
	ErrNoValidatorCfg = errors.New("no validator config")
	// ErrNoSignerCfg is returned when the signer namespace is not configured
	ErrNoSignerCfg = errors.New("no signer config")
)

// GetSignatureConfig parses the validator config of the endpoint. RolesKey defaults to
// "roles" and AuthHeaderName is canonicalized. If the JWK URL does not use https and the
// JWK security is not disabled, it returns the parsed config along with
// ErrInsecureJWKSource.
func GetSignatureConfig(cfg *config.EndpointConfig) (*SignatureConfig, error) {
	tmp, ok := cfg.ExtraConfig[ValidatorNamespace]
	if !ok {
		return nil, ErrNoValidatorCfg
	}
	data, _ := json.Marshal(tmp)
	res := new(SignatureConfig)
	if err := json.Unmarshal(data, res); err != nil {
		return nil, err
	}

	if res.RolesKey == "" {
		res.RolesKey = defaultRolesKey
	}
	if !strings.HasPrefix(res.URI, "https://") && !res.DisableJWKSecurity {
		return res, ErrInsecureJWKSource
	}
	if res.AuthHeaderName != "" {
		res.AuthHeaderName = textproto.CanonicalMIMEHeaderKey(res.AuthHeaderName)
	}

	return res, nil
}

func getSignerConfig(cfg *config.EndpointConfig) (*SignerConfig, error) {
	tmp, ok := cfg.ExtraConfig[SignerNamespace]
	if !ok {
		return nil, ErrNoSignerCfg
	}
	data, _ := json.Marshal(tmp)
	res := new(SignerConfig)
	if err := json.Unmarshal(data, res); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(res.URI, "https://") && !res.DisableJWKSecurity {
		return res, ErrInsecureJWKSource
	}
	return res, nil
}

// NewSigner returns the signer config of the endpoint and a Signer using the key KeyID
// from the configured JWK. Tokens include the kid and typ headers (typ defaults to "JWT")
// and use the compact serialization unless FullSerialization is enabled. On error, it
// returns a Signer producing empty strings, along with the parsed config, if any.
func NewSigner(cfg *config.EndpointConfig, te auth0.RequestTokenExtractor) (*SignerConfig, Signer, error) {
	signerCfg, err := getSignerConfig(cfg)
	if err != nil {
		return signerCfg, nopSigner, err
	}

	decodedFs, err := DecodeFingerprints(signerCfg.Fingerprints)
	if err != nil {
		return signerCfg, nopSigner, err
	}

	spcfg := SecretProviderConfig{
		URI:           signerCfg.URI,
		Cs:            signerCfg.CipherSuites,
		Fingerprints:  decodedFs,
		LocalCA:       signerCfg.LocalCA,
		AllowInsecure: signerCfg.DisableJWKSecurity,
		LocalPath:     signerCfg.LocalPath,
		SecretURL:     signerCfg.SecretURL,
		CipherKey:     signerCfg.CipherKey,
	}

	sp, err := SecretProvider(spcfg, te)
	if err != nil {
		return signerCfg, nopSigner, err
	}
	key, err := sp.GetKey(signerCfg.KeyID)
	if err != nil {
		return signerCfg, nopSigner, err
	}
	// if key.IsPublic() {
	// 	// TODO: we should not sign with a public key
	// }
	signingKey := jose.SigningKey{
		Key:       key.Key,
		Algorithm: jose.SignatureAlgorithm(signerCfg.Alg),
	}
	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): key.KeyID,
			jose.HeaderKey("typ"): "JWT",
		},
	}
	if signerCfg.Type != "" {
		opts.ExtraHeaders[jose.HeaderKey("typ")] = signerCfg.Type
	}
	s, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return signerCfg, nopSigner, err
	}

	if signerCfg.FullSerialization {
		return signerCfg, fullSerializeSigner{signer{s}}.Sign, nil
	}
	return signerCfg, compactSerializeSigner{signer{s}}.Sign, nil
}

// Signer signs a payload and returns the serialized JWS.
type Signer func(interface{}) (string, error)

func nopSigner(_ interface{}) (string, error) { return "", nil }

type signer struct {
	signer jose.Signer
}

func (s signer) sign(v interface{}) (*jose.JSONWebSignature, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize payload: %s", err.Error())
	}
	return s.signer.Sign(data)
}

type fullSerializeSigner struct {
	signer
}

func (f fullSerializeSigner) Sign(v interface{}) (string, error) {
	obj, err := f.sign(v)
	if err != nil {
		return "", fmt.Errorf("unable to sign payload: %s", err.Error())
	}
	return obj.FullSerialize(), nil
}

type compactSerializeSigner struct {
	signer
}

func (c compactSerializeSigner) Sign(v interface{}) (string, error) {
	obj, err := c.sign(v)
	if err != nil {
		return "", fmt.Errorf("unable to sign payload: %s", err.Error())
	}
	return obj.CompactSerialize()
}
