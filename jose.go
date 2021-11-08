package jose

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/krakend/go-auth0"
	"github.com/luraproject/lura/v2/proxy"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var ErrNoHeadersToPropagate = fmt.Errorf("header propagation is disabled because there is no propagate_claims attribute")

type ExtractorFactory func(string) func(r *http.Request) (*jwt.JSONWebToken, error)

func NewValidator(signatureConfig *SignatureConfig, ef ExtractorFactory) (*auth0.JWTValidator, error) {
	sa, ok := supportedAlgorithms[signatureConfig.Alg]
	if !ok {
		return nil, fmt.Errorf("JOSE: unknown algorithm %s", signatureConfig.Alg)
	}
	te := auth0.FromMultiple(
		auth0.RequestTokenExtractorFunc(auth0.FromHeader),
		auth0.RequestTokenExtractorFunc(ef(signatureConfig.CookieKey)),
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
	}

	sp, err := SecretProvider(cfg, te)
	if err != nil {
		return nil, err
	}

	return auth0.NewValidator(
		auth0.NewConfiguration(
			sp,
			signatureConfig.Audience,
			signatureConfig.Issuer,
			sa,
		),
		te,
	), nil
}

func CanAccessNested(roleKey string, claims map[string]interface{}, required []string) bool {
	if len(required) == 0 {
		return true
	}

	tmp := claims
	keys := strings.Split(roleKey, ".")

	for _, key := range keys[:len(keys)-1] {
		v, ok := tmp[key]
		if !ok {
			return false
		}
		tmp, ok = v.(map[string]interface{})
		if !ok {
			return false
		}
	}
	return CanAccess(keys[len(keys)-1], tmp, required)
}

func CanAccess(roleKey string, claims map[string]interface{}, required []string) bool {
	if len(required) == 0 {
		return true
	}

	tmp, ok := claims[roleKey]
	if !ok {
		return false
	}

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

func getNestedClaim(nestedKey string, claims map[string]interface{}) (string, map[string]interface{}) {
	tmp := claims
	keys := strings.Split(nestedKey, ".")

	for _, key := range keys[:len(keys)-1] {
		v, ok := tmp[key]
		if !ok {
			return nestedKey, nil
		}
		tmp, ok = v.(map[string]interface{})
		if !ok {
			return nestedKey, nil
		}
	}

	return keys[len(keys)-1], tmp
}

func ScopesAllMatcher(scopesKey string, claims map[string]interface{}, requiredScopes []string) bool {
	if len(requiredScopes) == 0 {
		return true
	}

	tmpClaims := claims
	tmpKey := scopesKey

	if strings.Contains(scopesKey, ".") {
		tmpKey, tmpClaims = getNestedClaim(scopesKey, claims)
	}

	tmp, ok := tmpClaims[tmpKey]
	if !ok {
		return false
	}

	matchAll := func(required []string, given []string) bool {
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

	scopes, ok := tmp.([]interface{})
	if ok {
		if len(scopes) > 0 {
			return matchAll(requiredScopes, convertToStringSlice(scopes))
		}
	}

	scopeString, ok := tmp.(string)
	if !ok {
		return false
	}

	presentScopes := strings.Split(scopeString, " ")
	if len(presentScopes) > 0 {
		return matchAll(requiredScopes, presentScopes)
	}

	return false
}

func ScopesDefaultMatcher(_ string, _ map[string]interface{}, _ []string) bool {
	return true
}

func ScopesAnyMatcher(scopesKey string, claims map[string]interface{}, requiredScopes []string) bool {
	if len(requiredScopes) == 0 {
		return true
	}

	tmpClaims := claims
	tmpKey := scopesKey

	if strings.Contains(scopesKey, ".") {
		tmpKey, tmpClaims = getNestedClaim(scopesKey, claims)
	}

	tmp, ok := tmpClaims[tmpKey]
	if !ok {
		return false
	}

	matchAny := func(required []string, given []string) bool {
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

	scopes, ok := tmp.([]interface{})
	if ok {
		if len(scopes) > 0 {
			return matchAny(requiredScopes, convertToStringSlice(scopes))
		}
	}

	scopeClaim, ok := tmp.(string)
	if !ok {
		return false
	}

	presentScopes := strings.Split(scopeClaim, " ")
	if len(presentScopes) > 0 {
		return matchAny(requiredScopes, presentScopes)
	}

	return false
}

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

type Claims map[string]interface{}

const epsilon = 1e-6

func (c Claims) Get(name string) (string, bool) {
	tmp, ok := c[name]
	if !ok {
		return "", ok
	}

	var normalized string

	switch v := tmp.(type) {
	case string:
		normalized = v
	case int:
		normalized = fmt.Sprintf("%d", v)
	case float64:
		if r := math.Round(v); math.Abs(v-r) <= epsilon {
			return fmt.Sprintf("%d", int(r)), ok
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

	return normalized, ok
}

func CalculateHeadersToPropagate(propagationCfg [][]string, claims map[string]interface{}) (map[string]string, error) {
	if len(propagationCfg) == 0 {
		return nil, ErrNoHeadersToPropagate
	}
	propagated := make(map[string]string)

	var err error
	for _, tuple := range propagationCfg {
		if len(tuple) != 2 {
			err = fmt.Errorf("invalid number of claims to propagate: %+v", tuple)
			continue
		}
		fromClaim := tuple[0]
		toHeader := tuple[1]

		c := Claims(claims)
		if strings.Contains(fromClaim, ".") && (len(fromClaim) < 4 || fromClaim[:4] != "http") {
			var claimsMap map[string]interface{}
			fromClaim, claimsMap = getNestedClaim(fromClaim, claims)
			c = Claims(claimsMap)
		}
		v, _ := c.Get(fromClaim)
		propagated[toHeader] = v
	}

	return propagated, err
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

func convertToStringSlice(input []interface{}) []string {
	result := make([]string, len(input))

	for i, v := range input {
		result[i] = v.(string)
	}

	return result
}
