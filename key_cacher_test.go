package jose

import (
	"bytes"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// TestGMemoryKeyCacher_providerScoping ensures that two JWK providers sharing the global
// cache and publishing different keys under the same key id never read each other's keys,
// even after the local caches expire and lookups fall back to the shared global cache.
func TestGMemoryKeyCacher_providerScoping(t *testing.T) {
	const kid = "shared"
	keyA := jose.JSONWebKey{KeyID: kid, Algorithm: "HS256", Key: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
	keyB := jose.JSONWebKey{KeyID: kid, Algorithm: "HS256", Key: []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")}

	// one shared global cache, long lived so the test exercises only the scoping.
	global := GlobalCacher{
		kc: NewMemoryKeyCacher(time.Minute, -1, defaultStrategy),
		mu: new(sync.RWMutex),
	}
	// two providers backed by that global cache, with a short local TTL so lookups quickly
	// fall back to the global cache.
	newProvider := func(uri string) *GMemoryKeyCacher {
		return &GMemoryKeyCacher{
			MemoryKeyCacher: NewMemoryKeyCacher(time.Second, -1, defaultStrategy),
			Global:          global,
			uri:             uri,
		}
	}
	providerA := newProvider("https://provider-a/jwks")
	providerB := newProvider("https://provider-b/jwks")

	// provider A caches its key in both its local and the shared global cache.
	if _, err := providerA.Add(kid, []jose.JSONWebKey{keyA}); err != nil {
		t.Fatalf("provider A failed to add its key: %v", err)
	}

	// provider B has a cold local cache and must not pick up provider A's key from the
	// global cache.
	if k, err := providerB.Get(kid); err == nil {
		t.Fatalf("provider B read a cross-provider key %q from the global cache", k.KeyID)
	}

	// expire the local caches so every lookup is served from the global cache.
	time.Sleep(1200 * time.Millisecond)

	// provider A still resolves its own key from the global cache after local expiry.
	k, err := providerA.Get(kid)
	if err != nil {
		t.Fatalf("provider A failed to read its own key after expiry: %v", err)
	}
	if got := k.Key.([]byte); !bytes.Equal(got, keyA.Key.([]byte)) {
		t.Fatalf("provider A read the wrong key after expiry")
	}

	// provider B still does not get provider A's key from the global cache.
	if _, err := providerB.Get(kid); err == nil {
		t.Fatal("provider B read a cross-provider key from the global cache after expiry")
	}

	// once provider B caches its own key under the same id, each provider keeps its own.
	if _, err := providerB.Add(kid, []jose.JSONWebKey{keyB}); err != nil {
		t.Fatalf("provider B failed to add its key: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)

	ka, err := providerA.Get(kid)
	if err != nil {
		t.Fatalf("provider A failed to read its key: %v", err)
	}
	kb, err := providerB.Get(kid)
	if err != nil {
		t.Fatalf("provider B failed to read its key: %v", err)
	}
	if bytes.Equal(ka.Key.([]byte), kb.Key.([]byte)) {
		t.Fatal("providers resolved to the same key despite distinct secrets under the same id")
	}
}
