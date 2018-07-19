package jose

import (
	"sync"
	"time"

	auth0 "github.com/auth0-community/go-auth0"
)

func secretProvider(URI string, cacheEnabled bool, tokenExtractor auth0.RequestTokenExtractor) *auth0.JWKClient {
	mu.RLock()
	if c, ok := jwkClient[URI]; ok && c != nil {
		mu.RUnlock()
		return c
	}
	mu.RUnlock()

	opts := auth0.JWKClientOptions{URI: URI}
	if !cacheEnabled {
		return auth0.NewJWKClient(opts, tokenExtractor)
	}

	keyCacher := auth0.NewMemoryKeyCacher(15*time.Minute, 100)
	c := auth0.NewJWKClientWithCache(opts, tokenExtractor, keyCacher)

	mu.Lock()
	jwkClient[URI] = c
	mu.Unlock()

	return c
}

var (
	jwkClient = map[string]*auth0.JWKClient{}
	mu        = new(sync.RWMutex)
)
