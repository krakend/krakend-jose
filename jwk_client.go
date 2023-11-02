package jose

import (
	"net/http"

	"github.com/krakend/go-auth0"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TokenIDGetter extracts the keyID from the JSON web token
type TokenIDGetter interface {
	Get(*jwt.JSONWebToken) string
}

// TokenKeyIDGetterFunc function conforming
// to the TokenIDGetter interface.
type TokenKeyIDGetterFunc func(*jwt.JSONWebToken) string

// Extract calls f(r)
func (f TokenKeyIDGetterFunc) Get(token *jwt.JSONWebToken) string {
	return f(token)
}

// DefaultTokenKeyIDGetter returns the default kid as the JSONWebKey key id
func DefaultTokenKeyIDGetter(token *jwt.JSONWebToken) string {
	return token.Headers[0].KeyID
}

// X5TTokenKeyIDGetter extracts the key id from the jSONWebToken as the x5t
func X5TTokenKeyIDGetter(token *jwt.JSONWebToken) string {
	x5t, ok := token.Headers[0].ExtraHeaders["x5t"].(string)
	if !ok {
		return token.Headers[0].KeyID
	}
	return x5t
}

// CompoundX5TTokenKeyIDGetter extracts the key id from the jSONWebToken as a compound string of the kid and x5t
func CompoundX5TTokenKeyIDGetter(token *jwt.JSONWebToken) string {
	return token.Headers[0].KeyID + X5TTokenKeyIDGetter(token)
}

// TokenIDGetterFactory returns the TokenIDGetter from the keyIdentifyStrategy configuration string
func TokenIDGetterFactory(keyIdentifyStrategy string) TokenIDGetter {
	supportedKeyIdentifyStrategy := map[string]TokenKeyIDGetterFunc{
		"kid":     DefaultTokenKeyIDGetter,
		"x5t":     X5TTokenKeyIDGetter,
		"kid_x5t": CompoundX5TTokenKeyIDGetter,
	}

	if tokenGetter, ok := supportedKeyIdentifyStrategy[keyIdentifyStrategy]; ok {
		return tokenGetter
	}
	return TokenKeyIDGetterFunc(DefaultTokenKeyIDGetter)
}

type JWKClientOptions struct {
	auth0.JWKClientOptions
	KeyIdentifyStrategy string
}

type JWKClient struct {
	*auth0.JWKClient
	extractor     auth0.RequestTokenExtractor
	tokenIDGetter TokenIDGetter
}

// NewJWKClientWithCache creates a new JWKClient instance from the provided options and custom extractor and keycacher.
// Passing nil to keyCacher will create a persistent key cacher.
// the extractor is also saved in the extended JWKClient.
func NewJWKClientWithCache(options JWKClientOptions, extractor auth0.RequestTokenExtractor, keyCacher auth0.KeyCacher) *JWKClient {
	return &JWKClient{
		JWKClient:     auth0.NewJWKClientWithCache(options.JWKClientOptions, extractor, keyCacher),
		extractor:     extractor,
		tokenIDGetter: TokenIDGetterFactory(options.KeyIdentifyStrategy),
	}
}

// GetSecret implements the GetSecret method of the SecretProvider interface.
func (j *JWKClient) GetSecret(r *http.Request) (interface{}, error) {
	token, err := j.extractor.Extract(r)
	if err != nil {
		return nil, err
	}

	if len(token.Headers) < 1 {
		return nil, auth0.ErrNoJWTHeaders
	}
	keyID := j.tokenIDGetter.Get(token)
	return j.GetKey(keyID)
}
