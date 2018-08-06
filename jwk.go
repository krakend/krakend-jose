package jose

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	auth0 "github.com/auth0-community/go-auth0"
)

func secretProvider(URI string, cacheEnabled bool, cs []uint16, te auth0.RequestTokenExtractor) *auth0.JWKClient {
	if len(cs) == 0 {
		cs = DefaultEnabledCipherSuites
	}

	tlsConfig := &tls.Config{
		CipherSuites: cs,
		MinVersion:   tls.VersionTLS12,
	}

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
				TLSClientConfig:       tlsConfig,
			},
		},
	}

	if !cacheEnabled {
		return auth0.NewJWKClient(opts, te)
	}
	keyCacher := auth0.NewMemoryKeyCacher(15*time.Minute, 100)
	return auth0.NewJWKClientWithCache(opts, te, keyCacher)
}

var (
	// DefaultEnabledCipherSuites is a collection of secure cipher suites to use
	DefaultEnabledCipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
)
