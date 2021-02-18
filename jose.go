package jose

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/auth0-community/go-auth0"
	"github.com/devopsfaith/krakend/proxy"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

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
	scopeClaim, ok := tmp.(string)
	if !ok {
		return false
	}

	presentScopes := strings.Split(scopeClaim, " ")
	if len(presentScopes) > 0 {
		for _, rScope := range requiredScopes {
			matched := false
			for _, pScope := range presentScopes {
				if rScope == fmt.Sprintf("%s", pScope) {
					matched = true
				}
			}
			if matched == false { // required scope was not found --> immediately return
				return false
			}
		}
		// all required scopes have been found in provided (claims) scopes
		return true
	}

	return false
}

func ScopesDefaultMatcher(scopesKey string, claims map[string]interface{}, requiredScopes []string) bool {
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
	scopeClaim, ok := tmp.(string)
	if !ok {
		return false
	}

	presentScopes := strings.Split(scopeClaim, " ")
	if len(presentScopes) > 0 {
		for _, rScope := range requiredScopes {
			for _, pScope := range presentScopes {
				if rScope == fmt.Sprintf("%s", pScope) {
					return true // found any of the required scopes --> return
				}
			}
		}
		// none of the scopes have been found in provided (claims) scopes
		return false
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

func CalculateHeadersToPropagate(propagationCfg [][]string, claims map[string]interface{}) (map[string]string, error) {
	if len(propagationCfg) == 0 {
		return nil, fmt.Errorf("JOSE: no headers to propagate. Config size: %d", len(propagationCfg))
	}

	propagated := make(map[string]string)

	for _, tuple := range propagationCfg {
		fromClaim := tuple[0]
		toHeader := tuple[1]
		tmp, ok := claims[fromClaim].(string)
		if !ok {
			continue
		}
		propagated[toHeader] = tmp
	}

	return propagated, nil

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
