package jose

import (
	"crypto/tls"
	"net"
	"net/http"
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

	opts := auth0.JWKClientOptions{
		URI: URI,
		Client: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
				MaxIdleConns:          10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					},
				},
			},
		},
	}
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
