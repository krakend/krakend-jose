package jose

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	auth0 "github.com/krakend/go-auth0/v2"
	"github.com/luraproject/lura/v3/logging"
)

// StripBearerAndParse converts a string to a jwt.JSONWebToken
// extracting the "Bearer " prefix if exists.
func StripBearerAndParse(token string) (*jwt.JSONWebToken, error) {
	if len(token) > 7 && strings.EqualFold(token[0:7], "BEARER ") {
		token = token[7:]
	}
	if token == "" {
		return nil, auth0.ErrTokenNotFound
	}
	return jwt.ParseSigned(token)
}

// NewJWTValidator eturns a JWT validator for the given signature config.
// The keys are obtained from the SecretProvider configured with the JWK settings of signatureConfig.
//
// It configures an auth0.JWTValidator almost in the same way
// that NewValidator, with the exception that extractor functions ae optional,
// (in not provided, a call to `.ValidateRequest(*http.Request)`
// will fail, because there ir no way to extract tokens), instead the
// `.ValidateToken` function must be used (a string to token conversion
// can be made externally using the StripBearerAndParse function).
//
// Delegating the work of extracting the token and parsing it to the
// caller, we avoid coupling with an `http.Request` type can be avoided
//
// It returns an error if the algorithm is not supported, the fingerprints cannot be
// decoded or the secret provider cannot be created. An invalid or empty Leeway
// defaults to one second.
func NewJWTValidator(signatureConfig *SignatureConfig, extr ...auth0.RequestTokenExtractor) (*auth0.JWTValidator, error) {
	sa, ok := SupportedAlgorithm(signatureConfig.Alg)
	if !ok {
		return nil, fmt.Errorf("JOSE: unknown algorithm %s", signatureConfig.Alg)
	}
	te := auth0.FromMultiple(extr...)

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

	// te complies to this interface, so we can not use this kind of extractor:
	// Extract(r *http.Request) (*jwt.JSONWebToken, error).
	// but, we can use the NewValidatorWitLeeway as long as we call
	// ValidateToken directly, instead of ValidateRequest (that would fail
	// with a token not found error with this implementation below).
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

// ACLCheck creates a function to for ACL and returns if the key used for ACL
// is a nested one.
func ACLCheck(scfg *SignatureConfig, logger logging.Logger,
	logPrefix string,
) (func(map[string]interface{}) bool, error) {
	if scfg.RolesKeyIsNested && strings.Contains(scfg.RolesKey, ".") &&
		!strings.HasPrefix(scfg.RolesKey, "http") {

		logger.Debug(logPrefix,
			fmt.Sprintf("Roles will be matched against the nested key: '%s'", scfg.RolesKey))

		aclCheck, err := AccessNestedCheck(scfg.RolesKey, scfg.Roles)
		if err != nil {
			return nil, fmt.Errorf("error preparing nested acl check: %s", err.Error())
		}
		return aclCheck, err
	}

	logger.Debug(logPrefix,
		fmt.Sprintf("Roles will be matched against the key: '%s'", scfg.RolesKey))
	aclCheck := AccessCheck(scfg.RolesKey, scfg.Roles)
	return aclCheck, nil
}

func ScopesMatcher(scfg *SignatureConfig, logger logging.Logger,
	logPrefix string,
) (func(map[string]interface{}) bool, error) {
	if len(scfg.Scopes) == 0 || scfg.ScopesKey == "" {
		logger.Debug(logPrefix, "No scope validation required")
		return DefaultScopesMatcher(scfg.ScopesKey, scfg.Scopes), nil
	}
	if scfg.ScopesMatcher == "all" {
		logger.Debug(logPrefix,
			fmt.Sprintf("Constraint added: tokens must contain a claim '%s' with all these scopes: %v", scfg.ScopesKey, scfg.Scopes))

		scopesMatcher, err := AllScopesMatcher(scfg.ScopesKey, scfg.Scopes)
		if err != nil {
			logger.Warning(logPrefix,
				fmt.Sprintf("error preparing all scopes matcher: %s", err.Error()))
			return nil, err
		}
		return scopesMatcher, err
	}
	logger.Debug(logPrefix,
		fmt.Sprintf("Constraint added: tokens must contain a claim '%s' with any of these scopes: %v", scfg.ScopesKey, scfg.Scopes))

	scopesMatcher, err := AnyScopesMatcher(scfg.ScopesKey, scfg.Scopes)
	if err != nil {
		logger.Warning(logPrefix, fmt.Sprintf("error preparing any scopes matcher: %s", err.Error()))
	}
	return scopesMatcher, err
}

type JWTChecks struct {
	rejecter    Rejecter
	validator   *auth0.JWTValidator
	acl         func(map[string]interface{}) bool
	scopesCheck func(map[string]interface{}) bool
	scfg        *SignatureConfig
	logger      logging.Logger
	logPrefix   string
}

func NewJWTChecks(scfg *SignatureConfig, logger logging.Logger,
	logPrefix string, rejecter Rejecter,
) (*JWTChecks, error) {
	if rejecter == nil {
		rejecter = FixedRejecter(false)
	}

	validator, err := NewJWTValidator(scfg)
	if err != nil {
		logger.Fatal(logPrefix, "Unable to create the validator:", err.Error())
		// TODO: in the krakend-jose/gin/jose.go implementation, if gails with a panic
		// instead of disabling the endpoints that cannot be secured with JWT.
		// What should we do here ?
		return nil, err
	}

	aclCheck, err := ACLCheck(scfg, logger, logPrefix)
	if err != nil {
		return nil, err
	}

	scopesMatcher, err := ScopesMatcher(scfg, logger, logPrefix)
	if err != nil {
		return nil, err
	}

	if scfg.OperationDebug {
		logger.Debug(logPrefix, "Validator enabled. Operation debug is enabled")
	} else {
		logger.Debug(logPrefix, "Validator enabled")
	}

	return &JWTChecks{
		rejecter:    rejecter,
		validator:   validator,
		acl:         aclCheck,
		scopesCheck: scopesMatcher,
		scfg:        scfg,
		logger:      logger,
		logPrefix:   logPrefix,
	}, nil
}

var (
	ErrRequiredRoles  = fmt.Errorf("Token sent by client does not have sufficient roles")    // skipcq: SCC-ST1005
	ErrRequiredScopes = fmt.Errorf("Token sent by client does not have the required scopes") // skipcq: SCC-ST1005
	ErrTokenRejected  = fmt.Errorf("Token sent by client rejected")                          // skipcq: SCC-ST1005
)

// Check validates a jwt and returns a list of values to propagate
func (j *JWTChecks) Check(bearer string) (Claims, error) {
	token, err := StripBearerAndParse(bearer)
	if err != nil {
		return nil, err
	}

	token, err = j.validator.ValidateToken(token)
	if err != nil {
		e := fmt.Errorf("Unable to validate token: %s", err.Error()) // skipcq: SCC-ST1005
		if j.scfg.OperationDebug {
			j.logger.Error(j.logPrefix, e.Error())
		}
		return nil, e
	}

	claims := make(Claims)
	err = j.validator.ClaimsFromToken(token, &claims)
	if err != nil {
		e := fmt.Errorf("Token sent by client is invalid: %s", err.Error()) // skipcq: SCC-ST1005
		if j.scfg.OperationDebug {
			j.logger.Error(j.logPrefix, e.Error())
		}
		return nil, e
	}

	if j.rejecter.Reject(claims) {
		e := ErrTokenRejected
		if j.scfg.OperationDebug {
			j.logger.Error(j.logPrefix, e.Error())
		}
		return nil, e
	}

	if !j.acl(claims) {
		e := ErrRequiredRoles
		if j.scfg.OperationDebug {
			j.logger.Error(j.logPrefix, e.Error())
		}
		return nil, e
	}

	if !j.scopesCheck(claims) {
		e := ErrRequiredScopes
		if j.scfg.OperationDebug {
			j.logger.Error(j.logPrefix, e.Error())
		}
		return nil, e
	}

	return claims, nil
}

func (j *JWTChecks) Scopes() []string {
	return j.scfg.Scopes
}
