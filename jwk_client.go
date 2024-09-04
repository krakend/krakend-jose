package jose

import (
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/krakend/go-auth0/v2"
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
	EnableUnknownList   bool
}

type JWKClient struct {
	*auth0.JWKClient
	extractor     auth0.RequestTokenExtractor
	tokenIDGetter TokenIDGetter
	misses        missTracker
}

// NewJWKClientWithCache creates a new JWKClient instance from the provided options and custom extractor and keycacher.
// Passing nil to keyCacher will create a persistent key cacher.
// the extractor is also saved in the extended JWKClient.
func NewJWKClientWithCache(options JWKClientOptions, extractor auth0.RequestTokenExtractor, keyCacher auth0.KeyCacher) *JWKClient {
	c := &JWKClient{
		JWKClient:     auth0.NewJWKClientWithCache(options.JWKClientOptions, extractor, keyCacher),
		extractor:     extractor,
		tokenIDGetter: TokenIDGetterFactory(options.KeyIdentifyStrategy),
		misses:        noTracker,
	}

	if options.EnableUnknownList {
		c.misses = &memoryMissTracker{
			keys: []unknownKey{},
			mu:   new(sync.Mutex),
		}
	}

	return c
}

// GetSecret implements the GetSecret method of the SecretProvider interface.
func (j *JWKClient) GetSecret(r *http.Request) (interface{}, error) {
	token, err := j.extractor.Extract(r)
	if err != nil {
		return nil, err
	}
	return j.SecretFromToken(token)
}

// SecretFromToken implements the GetSecret method of the SecretProvider interface.
func (j *JWKClient) SecretFromToken(token *jwt.JSONWebToken) (interface{}, error) {
	if len(token.Headers) < 1 {
		return nil, auth0.ErrNoJWTHeaders
	}
	keyID := j.tokenIDGetter.Get(token)
	return j.GetKey(keyID)
}

// GetKey wraps the internal key getter so it can manage the misses and avoid smashing the JWK
// provider looking for unknown keys
func (j *JWKClient) GetKey(keyID string) (jose.JSONWebKey, error) {
	if j.misses.Exists(keyID) {
		return jose.JSONWebKey{}, ErrNoKeyFound
	}

	k, err := j.JWKClient.GetKey(keyID)
	if err != nil {
		j.misses.Add(keyID)
	}
	return k, err
}

type missTracker interface {
	Exists(string) bool
	Add(string)
}

var noTracker = noopMissTracker{}

type noopMissTracker struct{}

func (noopMissTracker) Exists(_ string) bool { return false }
func (noopMissTracker) Add(_ string)         {}

type memoryMissTracker struct {
	keys []unknownKey
	mu   *sync.Mutex
}

type unknownKey struct {
	name string
	time time.Time
}

func (u *memoryMissTracker) Exists(key string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()

	now := time.Now()
	cutPosition := -1
	var found bool

	for i, uk := range u.keys {
		if uk.name == key {
			found = true
			break
		}
		if now.Sub(uk.time) > time.Minute {
			cutPosition = i
		}
	}

	if cutPosition == -1 {
		return found
	}

	if len(u.keys) > cutPosition+1 {
		u.keys = u.keys[cutPosition+1:]
	} else {
		u.keys = []unknownKey{}
	}

	return found
}

func (u *memoryMissTracker) Add(key string) {
	u.mu.Lock()
	u.keys = append(u.keys, unknownKey{name: key, time: time.Now()})
	u.mu.Unlock()
}
