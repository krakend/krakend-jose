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
	"time"

	jose "github.com/go-jose/go-jose/v3"
	auth0 "github.com/krakend/go-auth0/v2"
	"github.com/luraproject/lura/v3/core"

	"github.com/krakend/krakend-jose/v3/secrets"
)

// SecretProviderConfig holds the settings required to build a SecretProvider.
type SecretProviderConfig struct {
	// URI is the URL of the JWK endpoint
	URI string
	// CacheEnabled enables the shared in-memory cache of keys
	CacheEnabled bool
	// CacheDuration is the max age of the cached keys, in seconds (defaults to 15 minutes)
	CacheDuration uint32
	// Fingerprints are the SHA-256 fingerprints of the public keys accepted when
	// connecting to the JWK endpoint (certificate pinning)
	Fingerprints [][]byte
	// Cs are the TLS cipher suites to use (defaults to DefaultEnabledCipherSuites)
	Cs []uint16
	// LocalCA is the path of a PEM file with extra root CAs to trust
	LocalCA string
	// AllowInsecure skips the verification of the TLS certificate of the JWK endpoint
	AllowInsecure bool
	// LocalPath is the path of a local file with the JWK set, used instead of URI
	LocalPath string
	// SecretURL is the URL of the secret keeper used to decrypt the file at LocalPath
	SecretURL string
	// CipherKey is the encrypted key used to decrypt the file at LocalPath
	CipherKey []byte
	// KeyIdentifyStrategy selects how keys are matched with tokens
	KeyIdentifyStrategy string
	// UnknownKeysTTL is the cooldown for keys not found in the JWK (see JWKClientOptions)
	UnknownKeysTTL string
}

var (
	// ErrInsecureJWKSource is returned when the JWK URL does not use https and the
	// JWK security has not been disabled
	ErrInsecureJWKSource = errors.New("JWK client is using an insecure connection to the JWK service")
	// ErrPinnedKeyNotFound is returned when none of the certificates presented by the
	// JWK endpoint match the configured fingerprints
	ErrPinnedKeyNotFound = errors.New("JWK client did not find a pinned key")
	cacheOnce            = make(map[string]struct{})
)

// SecretProvider returns a JWKClient for the given config, using te to extract the
// tokens from the requests.
//
// Without cache, keys are either fetched from the remote JWK on demand or, if LocalPath is
// set, loaded once from that file (decrypted with the secret keeper at SecretURL, if any).
// With cache, keys are stored in a GMemoryKeyCacher for CacheDuration seconds (15 minutes
// by default) and the first client created for each URI warms it up in the background.
// Enabling the cache with a LocalPath is an error.
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

	client := NewJWKClientWithCache(
		opts,
		te,
		NewGlobalMemoryKeyCacher(cacheDuration, auth0.MaxCacheSizeNoCheck, opts.KeyIdentifyStrategy),
	)

	if _, ok := cacheOnce[cfg.URI]; !ok {
		go client.GetKey("unknown")
		cacheOnce[cfg.URI] = struct{}{}
	}

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

// NewFileKeyCacher returns a FileKeyCacher with the keys of the JSON-encoded JWK set in
// data, indexed with the given key identify strategy.
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

// FileKeyCacher is a KeyCacher backed by a static set of keys, loaded from a local file.
type FileKeyCacher struct {
	keys map[string]*jose.JSONWebKey
}

// Get returns the key with the given id or an error if it is not in the set.
func (f *FileKeyCacher) Get(keyID string) (*jose.JSONWebKey, error) {
	v, ok := f.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key '%s' not found in the key set", keyID)
	}
	return v, nil
}

// Add returns the key with the given id, ignoring the received keys since the set is
// static. It returns a nil key and no error if the key is not in the set.
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
		UnknownKeysTTL:      cfg.UnknownKeysTTL,
	}, nil
}

type krakendTransport struct {
	*http.Transport
}

func (k krakendTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", core.KrakendUserAgent)
	return k.Transport.RoundTrip(req)
}

// DecodeFingerprints decodes a list of base64 (URL encoding) SHA-256 fingerprints of
// public keys, as used for certificate pinning.
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

// NewDialer returns a Dialer using the given TLS config and the fingerprints in cfg.
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

// Dialer opens the connections to the JWK endpoint, optionally checking that the
// server presents a certificate with one of the pinned public keys.
type Dialer struct {
	dialer       *tls.Dialer
	fingerprints [][]byte
}

// DialContext opens a plain network connection to the address.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.NetDialer.DialContext(ctx, network, address)
}

// DialTLSContext opens a TLS connection to the address and returns ErrPinnedKeyNotFound
// if none of the peer certificates has a public key matching the configured fingerprints.
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
