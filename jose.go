package jose

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/krakend/dotnotation"
	"github.com/krakend/go-auth0/v2"
	"github.com/luraproject/lura/v3/proxy"
)

// ErrNoHeadersToPropagate is returned by NewPropagators when the configuration
// does not declare any claim to be propagated as a header.
var ErrNoHeadersToPropagate = fmt.Errorf("header propagation is disabled because there is no propagate_claims attribute")

// ExtractorFactory builds a function that extracts a JSON web token from a request.
// The string argument is the name of the header or cookie holding the token.
type ExtractorFactory func(string) func(r *http.Request) (*jwt.JSONWebToken, error)

// NewValidator returns a JWT validator for the given signature config. The token is
// looked up first in the header built by headerEf (using AuthHeaderName) and then in
// the cookie built by cookieEf (using CookieKey). The keys are obtained from the
// SecretProvider configured with the JWK settings of signatureConfig.
//
// It returns an error if the algorithm is not supported, the fingerprints cannot be
// decoded or the secret provider cannot be created. An invalid or empty Leeway
// defaults to one second.
func NewValidator(signatureConfig *SignatureConfig, cookieEf, headerEf ExtractorFactory) (*auth0.JWTValidator, error) {
	sa, ok := supportedAlgorithms[signatureConfig.Alg]
	if !ok {
		return nil, fmt.Errorf("JOSE: unknown algorithm %s", signatureConfig.Alg)
	}
	te := auth0.FromMultiple(
		auth0.RequestTokenExtractorFunc(headerEf(signatureConfig.AuthHeaderName)),
		auth0.RequestTokenExtractorFunc(cookieEf(signatureConfig.CookieKey)),
	)

	decodedFs, err := DecodeFingerprints(signatureConfig.Fingerprints)
	if err != nil {
		return nil, err
	}

	cfg := SecretProviderConfig{
		URI:                 signatureConfig.URI,
		CacheEnabled:        signatureConfig.CacheEnabled,
		CacheDuration:       signatureConfig.CacheDuration,
		Fingerprints:        decodedFs,
		Cs:                  signatureConfig.CipherSuites,
		LocalCA:             signatureConfig.LocalCA,
		AllowInsecure:       signatureConfig.DisableJWKSecurity,
		LocalPath:           signatureConfig.LocalPath,
		SecretURL:           signatureConfig.SecretURL,
		CipherKey:           signatureConfig.CipherKey,
		KeyIdentifyStrategy: signatureConfig.KeyIdentifyStrategy,
		UnknownKeysTTL:      signatureConfig.UnknownKeysTTL,
	}

	sp, err := SecretProvider(cfg, te)
	if err != nil {
		return nil, err
	}

	leeway, err := time.ParseDuration(signatureConfig.Leeway)
	if err != nil {
		leeway = time.Second
	}

	return auth0.NewValidatorWithLeeway(
		auth0.NewConfiguration(
			sp,
			signatureConfig.Audience,
			signatureConfig.Issuer,
			sa,
		),
		te,
		leeway,
	), nil
}

var (
	successCheck = func(map[string]interface{}) bool { return true }
	failCheck    = func(map[string]interface{}) bool { return false }
)

// ShouldExtractNested reports whether the roles key of the config must be resolved
// as a nested path in dot notation. That requires RolesKeyIsNested to be enabled and a
// RolesKey containing a dot that is not a URL (some identity providers name their
// claims after URLs, and those must be used as plain keys).
func ShouldExtractNested(sc *SignatureConfig) bool {
	return sc.RolesKeyIsNested && strings.Contains(sc.RolesKey, ".") && !strings.HasPrefix(sc.RolesKey, "http://") && !strings.HasPrefix(sc.RolesKey, "https://")
}

// AccessNestedCheck returns a function that reports whether the claims hold at least
// one of the required roles under roleKey, a path in dot notation. The roles claim
// can be an array of strings or a space-separated string. If no roles are required,
// the returned function always grants access. It returns an error if roleKey is not a
// valid dot notation expression.
func AccessNestedCheck(roleKey string, required []string) (func(map[string]interface{}) bool, error) {
	if len(required) == 0 {
		return successCheck, nil
	}

	ex, err := dotnotation.CompileExtractor(roleKey)
	if err != nil {
		return failCheck, err
	}

	return func(claims map[string]interface{}) bool {
		res := ex.Extract(claims)
		if len(res) != 1 {
			return false
		}

		return checkRequired(res[0], required)
	}, nil
}

// CanAccessNested reports whether the claims hold at least one of the required roles
// under roleKey, a path in dot notation.
//
// Deprecated: use AccessNestedCheck
func CanAccessNested(roleKey string, claims map[string]interface{}, required []string) bool {
	f, _ := AccessNestedCheck(roleKey, required)
	return f(claims)
}

// CanAccess reports whether the claims hold at least one of the required roles under
// the top-level claim roleKey.
//
// Deprecated: use AccessCheck
func CanAccess(roleKey string, claims map[string]interface{}, required []string) bool {
	return AccessCheck(roleKey, required)(claims)
}

// AccessCheck returns a function that reports whether the claims hold at least one of
// the required roles under the top-level claim roleKey. The roles claim can be an array
// of strings or a space-separated string. If no roles are required, the returned
// function always grants access.
func AccessCheck(roleKey string, required []string) func(map[string]interface{}) bool {
	if len(required) == 0 {
		return successCheck
	}

	return func(claims map[string]interface{}) bool {
		tmp, ok := claims[roleKey]
		if !ok {
			return false
		}

		return checkRequired(tmp, required)
	}
}

func checkRequired(tmp interface{}, required []string) bool {
	roles, ok := tmp.([]interface{})
	if ok {
		for _, role := range required {
			for _, r := range roles {
				if r.(string) == role {
					return true
				}
			}
		}
		return false
	}

	roleString, ok := tmp.(string)
	if !ok {
		return false
	}
	roless := strings.Split(roleString, " ")

	for _, role := range required {
		for _, r := range roless {
			if r == role {
				return true
			}
		}
	}
	return false
}

// AllScopesMatcher returns a function that reports whether the claims hold all the
// required scopes under scopesKey, a path in dot notation. The scopes claim can be an
// array of strings or a space-separated string. If no scopes are required, the
// returned function always matches. It returns an error if scopesKey is not a valid
// dot notation expression.
func AllScopesMatcher(scopesKey string, requiredScopes []string) (func(claims map[string]interface{}) bool, error) {
	return matcher(scopesKey, requiredScopes, allMatcher)
}

// AnyScopesMatcher returns a function that reports whether the claims hold at least
// one of the required scopes under scopesKey, a path in dot notation. The scopes claim
// can be an array of strings or a space-separated string. If no scopes are required,
// the returned function always matches. It returns an error if scopesKey is not a
// valid dot notation expression.
func AnyScopesMatcher(scopesKey string, requiredScopes []string) (func(claims map[string]interface{}) bool, error) {
	return matcher(scopesKey, requiredScopes, anyMatcher)
}

// DefaultScopesMatcher returns a function that matches any set of claims. It is used
// when no scope validation is configured.
func DefaultScopesMatcher(_ string, _ []string) func(claims map[string]interface{}) bool {
	return successCheck
}

func matcher(scopesKey string, requiredScopes []string, m func(required []string, given []string) bool) (func(claims map[string]interface{}) bool, error) {
	if len(requiredScopes) == 0 {
		return successCheck, nil
	}

	ex, err := dotnotation.CompileExtractor(scopesKey)
	if err != nil {
		return failCheck, err
	}
	return func(claims map[string]interface{}) bool {
		v := ex.Extract(claims)
		if len(v) != 1 {
			return false
		}
		scopes, ok := v[0].([]interface{})
		if ok {
			if len(scopes) > 0 {
				return m(requiredScopes, convertToStringSlice(scopes))
			}
			return false
		}

		scopeString, ok := v[0].(string)
		if !ok {
			return false
		}

		presentScopes := strings.Split(scopeString, " ")
		if len(presentScopes) > 0 {
			return m(requiredScopes, presentScopes)
		}

		return false
	}, nil
}

func allMatcher(required, given []string) bool {
	for _, rScope := range required {
		matched := false
		for _, pScope := range given {
			if rScope == pScope {
				matched = true
			}
		}
		if !matched { // required scope was not found --> immediately return
			return false
		}
	}
	// all required scopes have been found in provided (claims) scopes
	return true
}

func anyMatcher(required, given []string) bool {
	for _, rScope := range required {
		for _, pScope := range given {
			if rScope == pScope {
				return true // found any of the required scopes --> return
			}
		}
	}

	// none of the scopes have been found in provided (claims) scopes
	return false
}

// ScopesAnyMatcher reports whether the claims hold at least one of the required scopes
// under scopesKey.
//
// Deprecated: use AnyScopesMatcher
func ScopesAnyMatcher(scopesKey string, claims map[string]interface{}, requiredScopes []string) bool {
	m, _ := AnyScopesMatcher(scopesKey, requiredScopes)
	return m(claims)
}

// ScopesAllMatcher reports whether the claims hold all the required scopes under
// scopesKey.
//
// Deprecated: use AllScopesMatcher
func ScopesAllMatcher(scopesKey string, claims map[string]interface{}, requiredScopes []string) bool {
	m, _ := AllScopesMatcher(scopesKey, requiredScopes)
	return m(claims)
}

// ScopesDefaultMatcher always returns true.
//
// Deprecated: use DefaultScopesMatcher
func ScopesDefaultMatcher(_ string, _ map[string]interface{}, _ []string) bool {
	return true
}

// SignFields replaces, for every key in keys, the object stored under that key in the
// response data with the token produced by the signer. Keys that are missing or do not
// hold an object are skipped. It stops at the first signing error.
func SignFields(keys []string, signer Signer, response *proxy.Response) error {
	for _, key := range keys {
		tmp, ok := response.Data[key]
		if !ok {
			continue
		}
		data, ok := tmp.(map[string]interface{})
		if !ok {
			continue
		}
		token, err := signer(data)
		if err != nil {
			return err
		}
		response.Data[key] = token
	}
	return nil
}

// Claims is a set of JWT claims with helpers to read them as strings.
type Claims map[string]interface{}

const epsilon = 1e-6

// Get returns the claim name as a string and whether it was present. Integral numbers
// are rendered without decimals, arrays as comma-separated values and any other
// non-string value as JSON.
func (c Claims) Get(name string) (string, bool) {
	tmp, ok := c[name]
	if !ok {
		return "", ok
	}

	return toString(tmp), ok
}

// List returns the claim name as a list of strings and whether it was present. Arrays
// return one element per item and scalars a single element. If the claim is missing,
// the returned slice holds a single empty string.
func (c Claims) List(name string) ([]string, bool) {
	tmp, ok := c[name]
	if !ok {
		// if the claim is not present, return an slice with one empty element to keep compatibility
		return []string{""}, ok
	}

	return toList(tmp), ok
}

// Propagator copies the value of a claim, selected with a dot notation path, into a
// request header.
type Propagator struct {
	e *dotnotation.Extractor
	h string
}

// NewPropagators builds a Propagator for every [claim, header] pair in propagationCfg.
// Pairs with a different number of elements or an invalid claim path are skipped. It
// returns ErrNoHeadersToPropagate if propagationCfg is empty.
func NewPropagators(propagationCfg [][]string) ([]Propagator, error) {
	if len(propagationCfg) == 0 {
		return nil, ErrNoHeadersToPropagate
	}
	p := make([]Propagator, 0, len(propagationCfg))
	for _, tuple := range propagationCfg {
		if len(tuple) != 2 {
			continue
		}
		e, err := dotnotation.CompileExtractor(tuple[0])
		if err != nil {
			continue
		}
		p = append(p, Propagator{
			e: e,
			h: tuple[1],
		})
	}
	return p, nil
}

func toString(tmp interface{}) string {
	var normalized string

	switch v := tmp.(type) {
	case string:
		normalized = v
	case int:
		normalized = fmt.Sprintf("%d", v)
	case float64:
		if r := math.Round(v); math.Abs(v-r) <= epsilon {
			return fmt.Sprintf("%d", int(r))
		}
		normalized = fmt.Sprintf("%f", v)
	case []interface{}:
		if len(v) > 0 {
			normalized = fmt.Sprintf("%v", v[0])
			for _, elem := range v[1:] {
				normalized += fmt.Sprintf(",%v", elem)
			}
		}
	default:
		b, _ := json.Marshal(v)
		normalized = string(b)
	}

	return normalized
}

func toList(tmp interface{}) []string {
	var normalized []string

	switch v := tmp.(type) {
	case string:
		normalized = []string{v}
	case int:
		normalized = []string{fmt.Sprintf("%d", v)}
	case float64:
		if r := math.Round(v); math.Abs(v-r) <= epsilon {
			return []string{fmt.Sprintf("%d", int(r))}
		}
		normalized = []string{fmt.Sprintf("%f", v)}
	case []interface{}:
		if len(v) > 0 {
			for _, elem := range v {
				normalized = append(normalized, fmt.Sprintf("%v", elem))
			}
		}
	default:
		b, _ := json.Marshal(v)
		normalized = []string{string(b)}
	}

	return normalized
}

// HeadersToPropagate returns the headers to add to the request, indexed by name, with
// the values of the claims selected by the propagators. Values are normalized as in
// Claims.Get and missing claims are propagated as empty strings.
func HeadersToPropagate(ps []Propagator, claims map[string]interface{}) map[string]string {
	propagated := make(map[string]string)
	for _, p := range ps {
		v := p.e.Extract(claims)
		if len(v) != 1 {
			propagated[p.h] = ""
			continue
		}
		propagated[p.h] = toString(v[0])
	}
	return propagated
}

// ArrayHeadersToPropagate is like HeadersToPropagate but keeps array claims as lists
// of values, as in Claims.List. Missing claims are propagated as a single empty string.
func ArrayHeadersToPropagate(ps []Propagator, claims map[string]interface{}) map[string][]string {
	propagated := make(map[string][]string)
	for _, p := range ps {
		v := p.e.Extract(claims)
		if len(v) != 1 {
			propagated[p.h] = []string{""}
			continue
		}
		propagated[p.h] = toList(v[0])
	}
	return propagated
}

// CalculateHeadersToPropagate builds the propagators described by propagationCfg and
// returns the headers to propagate for the given claims.
//
// Deprecated: use NewPropagators and HeadersToPropagate
func CalculateHeadersToPropagate(propagationCfg [][]string, claims map[string]interface{}) (map[string]string, error) {
	ps, err := NewPropagators(propagationCfg)
	if err != nil {
		return nil, err
	}

	return HeadersToPropagate(ps, claims), nil
}

// CalculateArrayHeadersToPropagate builds the propagators described by propagationCfg
// and returns the headers to propagate for the given claims, keeping arrays as lists.
//
// Deprecated: use NewPropagators and ArrayHeadersToPropagate
func CalculateArrayHeadersToPropagate(propagationCfg [][]string, claims map[string]interface{}) (map[string][]string, error) {
	ps, err := NewPropagators(propagationCfg)
	if err != nil {
		return nil, err
	}

	return ArrayHeadersToPropagate(ps, claims), nil
}

var supportedAlgorithms = map[string]jose.SignatureAlgorithm{
	"EdDSA": jose.EdDSA,
	"HS256": jose.HS256,
	"HS384": jose.HS384,
	"HS512": jose.HS512,
	"RS256": jose.RS256,
	"RS384": jose.RS384,
	"RS512": jose.RS512,
	"ES256": jose.ES256,
	"ES384": jose.ES384,
	"ES512": jose.ES512,
	"PS256": jose.PS256,
	"PS384": jose.PS384,
	"PS512": jose.PS512,
}

// SupportedAlgorithm returns the signature algorithm named s and whether the validator
// supports it.
func SupportedAlgorithm(s string) (jose.SignatureAlgorithm, bool) {
	a, ok := supportedAlgorithms[s]
	return a, ok
}

func convertToStringSlice(input []interface{}) []string {
	result := make([]string, len(input))

	for i, v := range input {
		result[i] = v.(string)
	}

	return result
}
