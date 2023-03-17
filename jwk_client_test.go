package jose

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/auth0-community/go-auth0"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
)

func TestJWKClient_globalCache(t *testing.T) {
	jwk := []byte(`{ "keys": [{
		"kty": "RSA",
		"e": "AQAB",
		"use": "sig",
		"kid": "8-2-2PBmlHKMo5tizxp-uw9pFrQQamfa1M1ZYMrAFZI",
		"alg": "RS256",
		"n": "n6p2fLU7PLwMvJ-xeukn-f5wrAdyZ0ZaFa6kanQzVBofacLs2l4FVe6_bcjw4VGWM2Ct3WgelZQUYVkFbqePODpMnV0lV8U4hxbIpMEJOJqY3tK48_PBIdEkl02DN8LaucK1Y7GpOlUZFrWAOM68TyWJTjkyc-yx0ibu2MFaGQoXacV7239Yei_x68iGBpQa2f9SYv8U5nJINdI1CuyccQp991qeskJATgn-UVqQfOfHDsUA2qud2yNOf5QKkvqqPEH_IXuTtPcf_yzVuco9rhhUW8q5bC4R0BxjCv9w4b-Q_UKjKEXQK5UlAuiWqWgmQbQO9Ne94EDFpjlkCtil2Q"
	}]}`)

	var count uint64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		atomic.AddUint64(&count, 1)
		w.Write(jwk)
	}))

	defer backend.Close()
	opts := JWKClientOptions{
		JWKClientOptions: auth0.JWKClientOptions{
			URI: backend.URL,
		},
	}
	te := auth0.FromMultiple(
		auth0.RequestTokenExtractorFunc(auth0.FromHeader),
	)
	cfg := config.ExtraConfig{
		ValidatorNamespace: map[string]interface{}{
			"shared_cache_duration": 3,
		},
	}
	if err := SetGlobalCacher(logging.NoOp, cfg); err != nil {
		t.Error(err)
		return
	}
	for i := 0; i < 10; i++ {
		client := NewJWKClientWithCache(
			opts,
			te,
			NewGlobalMemoryKeyCacher(1*time.Second, auth0.MaxCacheSizeNoCheck, opts.KeyIdentifyStrategy),
		)
		if _, err := client.GetKey("8-2-2PBmlHKMo5tizxp-uw9pFrQQamfa1M1ZYMrAFZI"); err != nil {
			t.Error(err)
			return
		}
	}
	if count != 1 {
		t.Errorf("invalid count %d", count)
		return
	}
	<-time.After(4 * time.Second)
	for i := 0; i < 10; i++ {
		client := NewJWKClientWithCache(
			opts,
			te,
			NewGlobalMemoryKeyCacher(1*time.Second, auth0.MaxCacheSizeNoCheck, opts.KeyIdentifyStrategy),
		)
		if _, err := client.GetKey("8-2-2PBmlHKMo5tizxp-uw9pFrQQamfa1M1ZYMrAFZI"); err != nil {
			t.Error(err)
			return
		}
	}
	if count != 2 {
		t.Errorf("invalid count %d", count)
	}
}
