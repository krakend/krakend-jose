//go:generate go run $GOROOT/src/crypto/tls/generate_cert.go --rsa-bits 1024 --host 127.0.0.1,::1,localhost --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
package jose

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krakend/krakend-jose/v2/secrets"
	"github.com/luraproject/lura/v2/core"
)

func TestJWK(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		t.Error(err)
		return
	}

	for _, tc := range []struct {
		Name string
		Alg  string
		ID   []string
	}{
		{
			Name: "public",
			ID:   []string{"2011-04-29"},
			Alg:  "RS256",
		},
		{
			Name: "public",
			ID:   []string{"1"},
		},
		{
			Name: "private",
			ID:   []string{"2011-04-29"},
			Alg:  "RS256",
		},
		{
			Name: "private",
			ID:   []string{"1"},
		},
		{
			Name: "symmetric",
			ID:   []string{"sim2"},
			Alg:  "HS256",
		},
	} {
		server := httptest.NewUnstartedServer(jwkEndpoint(tc.Name))
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		server.StartTLS()

		secretProvidr, err := SecretProvider(SecretProviderConfig{URI: server.URL, LocalCA: "cert.pem"}, nil)
		if err != nil {
			t.Error(err)
		}
		for _, k := range tc.ID {
			key, err := secretProvidr.GetKey(k)
			if err != nil {
				t.Errorf("[%s] extracting the key %s: %s", tc.Name, k, err.Error())
			}
			if key.Algorithm != tc.Alg {
				t.Errorf("wrong alg. have: %s, want: %s", key.Algorithm, tc.Alg)
			}
		}
		server.Close()
	}
}

func TestJWK_file(t *testing.T) {
	for _, tc := range []struct {
		Name string
		Alg  string
		ID   string
	}{
		{
			Name: "public",
			ID:   "2011-04-29",
			Alg:  "RS256",
		},
		{
			Name: "public",
			ID:   "1",
		},
		{
			Name: "private",
			ID:   "2011-04-29",
			Alg:  "RS256",
		},
		{
			Name: "private",
			ID:   "1",
		},
		{
			Name: "symmetric",
			ID:   "sim2",
			Alg:  "HS256",
		},
	} {
		secretProvidr, err := SecretProvider(
			SecretProviderConfig{
				URI:           "",
				AllowInsecure: true,
				LocalPath:     "./fixtures/" + tc.Name + ".json",
			},
			nil,
		)
		if err != nil {
			t.Error(err)
		}
		key, err := secretProvidr.GetKey(tc.ID)
		if err != nil {
			t.Errorf("[%s] extracting the key %s: %s", tc.Name, tc.ID, err.Error())
		}
		if key.Algorithm != tc.Alg {
			t.Errorf("wrong alg. have: %s, want: %s", key.Algorithm, tc.Alg)
		}
	}
}

func TestJWK_cyperfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	url := "base64key://smGbjm71Nxd1Ig5FS0wj9SlbzAIrnolCz9bQQ6uAhl4="

	cypher, err := secrets.New(ctx, url)
	if err != nil {
		t.Error(err)
		return
	}
	defer cypher.Close()

	plainKey := make([]byte, 32)
	rand.Read(plainKey)

	cypherKey, err := cypher.EncryptKey(ctx, plainKey)
	if err != nil {
		t.Error(err)
		return
	}

	b, _ := os.ReadFile("./fixtures/private.json")
	cypherText, err := cypher.Encrypt(ctx, b, cypherKey)
	if err != nil {
		t.Error(err)
		return
	}
	os.WriteFile("./fixtures/private.txt", cypherText, 0600)
	defer os.Remove("./fixtures/private.txt")

	for k, tc := range []struct {
		Alg string
		ID  string
	}{
		{
			ID:  "2011-04-29",
			Alg: "RS256",
		},
		{
			ID: "1",
		},
	} {
		secretProvidr, err := SecretProvider(
			SecretProviderConfig{
				URI:           "",
				AllowInsecure: true,
				LocalPath:     "./fixtures/private.txt",
				CipherKey:     cypherKey,
				SecretURL:     url,
			},
			nil,
		)
		if err != nil {
			t.Error(err)
		}
		key, err := secretProvidr.GetKey(tc.ID)
		if err != nil {
			t.Errorf("[%d] extracting the key %s: %s", k, tc.ID, err.Error())
		}
		if key.Algorithm != tc.Alg {
			t.Errorf("wrong alg. have: %s, want: %s", key.Algorithm, tc.Alg)
		}
	}
}

func TestJWK_cache(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		t.Error(err)
		return
	}

	for _, tc := range []struct {
		Name string
		Alg  string
		ID   []string
	}{
		{
			Name: "public",
			ID:   []string{"2011-04-29"},
			Alg:  "RS256",
		},
		{
			Name: "public",
			ID:   []string{"1"},
		},
		{
			Name: "private",
			ID:   []string{"2011-04-29"},
			Alg:  "RS256",
		},
		{
			Name: "private",
			ID:   []string{"1"},
		},
		{
			Name: "symmetric",
			ID:   []string{"sim2"},
			Alg:  "HS256",
		},
	} {
		var hits uint32
		server := httptest.NewUnstartedServer(jwkEndpointWithCounter(tc.Name, &hits))
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		server.StartTLS()

		cfg := SecretProviderConfig{
			URI:          server.URL,
			LocalCA:      "cert.pem",
			CacheEnabled: true,
		}

		secretProvidr, err := SecretProvider(cfg, nil)
		if err != nil {
			t.Error(err)
		}

		// give some time to the concurrent cache warm up to complete
		<-time.After(100 * time.Millisecond)

		if hits != 1 {
			t.Errorf("wrong initial number of hits to the jwk endpoint: %d", hits)
		}

		for i := 0; i < 10; i++ {
			for _, k := range tc.ID {
				key, err := secretProvidr.GetKey(k)
				if err != nil {
					t.Errorf("[%s] extracting the key %s: %s", tc.Name, k, err.Error())
				}
				if key.Algorithm != tc.Alg {
					t.Errorf("wrong alg. have: %s, want: %s", key.Algorithm, tc.Alg)
				}
			}
		}
		server.Close()

		if hits != 1 {
			t.Errorf("wrong number of hits to the jwk endpoint: %d", hits)
		}
	}
}

func TestDialer_DialTLS_ko(t *testing.T) {
	d := NewDialer(SecretProviderConfig{}, nil)
	c, err := d.DialTLSContext(context.Background(), "\t", "addr")
	if err == nil {
		t.Error(err)
	}
	if c != nil {
		t.Errorf("unexpected connection: %v", c)
	}
}

func Test_decodeFingerprints(t *testing.T) {
	_, err := DecodeFingerprints([]string{"not_encoded_message"})
	if err == nil {
		t.Error(err)
	}
}

func TestNewFileKeyCacher(t *testing.T) {
	for _, tc := range []struct {
		Name string
		Alg  string
		ID   string
	}{
		{
			Name: "public",
			ID:   "2011-04-29",
			Alg:  "RS256",
		},
		{
			Name: "public",
			ID:   "1",
		},
		{
			Name: "private",
			ID:   "2011-04-29",
			Alg:  "RS256",
		},
		{
			Name: "private",
			ID:   "1",
		},
		{
			Name: "symmetric",
			ID:   "sim2",
			Alg:  "HS256",
		},
	} {
		b, err := os.ReadFile("./fixtures/" + tc.Name + ".json")
		if err != nil {
			t.Error(err)
		}
		kc, err := NewFileKeyCacher(b, "")
		if err != nil {
			t.Error(err)
		}
		if _, err := kc.Get(tc.ID); err != nil {
			t.Error(err)
		}
	}
}

func TestNewFileKeyCacher_unknownKey(t *testing.T) {
	b, err := os.ReadFile("./fixtures/symmetric.json")
	if err != nil {
		t.Error(err)
	}
	kc, err := NewFileKeyCacher(b, "")
	if err != nil {
		t.Error(err)
	}
	v, err := kc.Get("unknown")
	if err == nil {
		t.Error("error expected")
	} else if e := err.Error(); e != "key 'unknown' not found in the key set" {
		t.Error("unexpected error:", e)
	}
	if v != nil {
		t.Error("nil value expected")
	}
}

func jwkEndpoint(name string) http.HandlerFunc {
	data, err := os.ReadFile("./fixtures/" + name + ".json")
	return func(rw http.ResponseWriter, req *http.Request) {
		if err != nil {
			rw.WriteHeader(500)
			return
		}
		if ua := req.Header.Get("User-Agent"); ua != core.KrakendUserAgent {
			rw.WriteHeader(500)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(data)
	}
}

func jwkEndpointWithCounter(name string, hits *uint32) http.HandlerFunc {
	data, err := os.ReadFile("./fixtures/" + name + ".json")
	return func(rw http.ResponseWriter, _ *http.Request) {
		if err != nil {
			rw.WriteHeader(500)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(data)
		atomic.AddUint32(hits, 1)
	}
}
