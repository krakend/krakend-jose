package jose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	auth0 "github.com/krakend/go-auth0"
	"github.com/luraproject/lura/v2/core"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/krakendio/krakend-jose/v2/secrets"
)

type SecretProviderConfig struct {
	URI                 string
	CacheEnabled        bool
	CacheDuration       uint32
	Fingerprints        [][]byte
	Cs                  []uint16
	LocalCA             string
	AllowInsecure       bool
	LocalPath           string
	SecretURL           string
	CipherKey           []byte
	KeyIdentifyStrategy string
}

var (
	ErrInsecureJWKSource = errors.New("JWK client is using an insecure connection to the JWK service")
	ErrPinnedKeyNotFound = errors.New("JWK client did not find a pinned key")

	cacheWorkers   = runtime.GOMAXPROCS(-1)
	cacheSemaphore = make(chan struct{}, cacheWorkers)
	cacheOnce      = new(sync.Once)
)

func SecretProvider(cfg SecretProviderConfig, te auth0.RequestTokenExtractor) (*JWKClient, error) {
	opts, err := newJWKClientOptions(cfg)
	if err != nil {
		return nil, err
	}

	if !cfg.CacheEnabled {
		if cfg.LocalPath == "" {
			return NewJWKClientWithCache(opts, te, NewMemoryKeyCacher(0, 0, opts.KeyIdentifyStrategy)), nil
		}
		return newLocalSecretProvider(opts, cfg, te)
	}

	if cfg.LocalPath != "" {
		return nil, fmt.Errorf("cache could not be used with jwk_local_path")
	}
	var cacheDuration time.Duration
	cacheDuration = time.Duration(cfg.CacheDuration) * time.Second
	// Set default duration to 15 minute
	if cacheDuration == 0 {
		cacheDuration = 15 * time.Minute
	}

	// init the semaphore
	cacheOnce.Do(func() {
		for i := 0; i < cacheWorkers; i++ {
			cacheSemaphore <- struct{}{}
		}
	})

	client := NewJWKClientWithCache(
		opts,
		te,
		NewGlobalMemoryKeyCacher(cacheDuration, auth0.MaxCacheSizeNoCheck, opts.KeyIdentifyStrategy),
	)

	// request an unexistent key in order to cache all the actual ones
	<-cacheSemaphore
	go func() {
		client.GetKey("unknown")
		cacheSemaphore <- struct{}{}
	}()

	return client, nil
}

func newLocalSecretProvider(opts JWKClientOptions, cfg SecretProviderConfig, te auth0.RequestTokenExtractor) (*JWKClient, error) {
	data, err := os.ReadFile(cfg.LocalPath)
	if err != nil {
		return nil, err
	}

	if cfg.SecretURL != "" {
		ctx := context.Background()
		sk, err := secrets.New(ctx, cfg.SecretURL)
		if err != nil {
			return nil, err
		}
		data, err = sk.Decrypt(ctx, data, cfg.CipherKey)
		if err != nil {
			return nil, err
		}
		sk.Close()
	}

	keyCacher, err := NewFileKeyCacher(data, opts.KeyIdentifyStrategy)
	if err != nil {
		return nil, err
	}
	return NewJWKClientWithCache(opts, te, keyCacher), nil
}

func NewFileKeyCacher(data []byte, keyIdentifyStrategy string) (*FileKeyCacher, error) {
	keys := jose.JSONWebKeySet{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	keyMap := map[string]*jose.JSONWebKey{}
	keyIDGetter := KeyIDGetterFactory(keyIdentifyStrategy)
	for _, k := range keys.Keys {
		keyToStore := k
		keyMap[keyIDGetter.Get(&keyToStore)] = &keyToStore
	}
	return &FileKeyCacher{keys: keyMap}, nil
}

type FileKeyCacher struct {
	keys map[string]*jose.JSONWebKey
}

func (f *FileKeyCacher) Get(keyID string) (*jose.JSONWebKey, error) {
	v, ok := f.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key '%s' not found in the key set", keyID)
	}
	return v, nil
}

func (f *FileKeyCacher) Add(keyID string, _ []jose.JSONWebKey) (*jose.JSONWebKey, error) {
	return f.keys[keyID], nil
}

func newJWKClientOptions(cfg SecretProviderConfig) (JWKClientOptions, error) {
	if len(cfg.Cs) == 0 {
		cfg.Cs = DefaultEnabledCipherSuites
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if cfg.LocalCA != "" {
		certs, err := os.ReadFile(cfg.LocalCA)
		if err != nil {
			return JWKClientOptions{}, fmt.Errorf("failed to append %q to RootCAs: %v", cfg.LocalCA, err)
		}
		rootCAs.AppendCertsFromPEM(certs)
	}

	tlsConfig := &tls.Config{
		CipherSuites:       cfg.Cs,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.AllowInsecure, // skipcq: GSC-G402
		RootCAs:            rootCAs,
	}
	dialer := NewDialer(cfg, tlsConfig)

	transport := krakendTransport{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsConfig,
		},
	}

	if len(cfg.Fingerprints) > 0 {
		transport.DialTLSContext = dialer.DialTLSContext
	}

	return JWKClientOptions{
		JWKClientOptions: auth0.JWKClientOptions{
			URI: cfg.URI,
			Client: &http.Client{
				Transport: transport,
			},
		},
		KeyIdentifyStrategy: cfg.KeyIdentifyStrategy,
	}, nil
}

type krakendTransport struct {
	*http.Transport
}

func (k krakendTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", core.KrakendUserAgent)
	return k.Transport.RoundTrip(req)
}

func DecodeFingerprints(in []string) ([][]byte, error) {
	out := make([][]byte, len(in))
	for i, f := range in {
		r, err := base64.URLEncoding.DecodeString(f)
		if err != nil {
			return out, fmt.Errorf("decoding fingerprint #%d: %s", i, err.Error())
		}
		out[i] = r
	}
	return out, nil
}

func NewDialer(cfg SecretProviderConfig, tlsConfig *tls.Config) *Dialer {
	return &Dialer{
		dialer: &tls.Dialer{
			NetDialer: &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			},
			Config: tlsConfig,
		},
		fingerprints: cfg.Fingerprints,
	}
}

type Dialer struct {
	dialer       *tls.Dialer
	fingerprints [][]byte
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.NetDialer.DialContext(ctx, network, address)
}

func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	c, ok := conn.(*tls.Conn)
	if !ok {
		return conn, errors.New("wrong connection type")
	}
	connstate := c.ConnectionState()
	keyPinValid := false
	for _, peercert := range connstate.PeerCertificates {
		der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		hash := sha256.Sum256(der)
		if err != nil {
			log.Fatal(err)
		}
		for _, fingerprint := range d.fingerprints {
			if bytes.Equal(hash[0:], fingerprint) {
				keyPinValid = true
				break
			}
		}
	}
	if !keyPinValid {
		return nil, ErrPinnedKeyNotFound
	}
	return c, nil
}

// DefaultEnabledCipherSuites is a collection of secure cipher suites to use
var DefaultEnabledCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	// TLS 1.3 cipher suites.
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}
