package jose

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/luraproject/lura/v3/config"
	"github.com/luraproject/lura/v3/logging"
)

var (
	// ErrNoKeyFound is returned when the requested key is not available
	ErrNoKeyFound = errors.New("no Keys have been found")
	// ErrKeyExpired is returned when the requested key is cached but older than the max key age
	ErrKeyExpired                   = errors.New("key exists but is expired")
	defaultGlobalCacheMaxAge uint32 = 900
	defaultStrategy                 = "kid"

	// MaxKeyAgeNoCheck disables the expiration of the cached keys when used as max key age
	MaxKeyAgeNoCheck    = time.Duration(-1)
	globalKeyCacher     = map[string]GlobalCacher{}
	globalKeyCacherOnce = new(sync.Once)
)

// GlobalCacher is a KeyCacher shared by all the validators using the same key identify
// strategy, guarded by a mutex.
type GlobalCacher struct {
	kc KeyCacher
	mu *sync.RWMutex
}

// SetGlobalCacher initializes the shared key caches, one per key identify strategy, with
// the shared_cache_duration (in seconds, 900 by default) declared under the
// ValidatorNamespace of the service extra config. Only the first successful call has any
// effect. It returns ErrNoValidatorCfg if the namespace is missing.
func SetGlobalCacher(l logging.Logger, cfg config.ExtraConfig) error {
	scfg, err := configGetter(l, cfg)
	if err != nil {
		return err
	}
	duration := time.Duration(scfg.CacheDuration) * time.Second
	globalKeyCacherOnce.Do(func() {
		globalKeyCacher = map[string]GlobalCacher{
			"kid":      {kc: NewMemoryKeyCacher(duration, -1, "kid"), mu: new(sync.RWMutex)},
			"x5t":      {kc: NewMemoryKeyCacher(duration, -1, "x5t"), mu: new(sync.RWMutex)},
			"x5t#S256": {kc: NewMemoryKeyCacher(duration, -1, "x5t#S256"), mu: new(sync.RWMutex)},
			"kid_x5t":  {kc: NewMemoryKeyCacher(duration, -1, "kid_x5t"), mu: new(sync.RWMutex)},
		}
	})
	return nil
}

type serviceConfig struct {
	CacheDuration uint32 `json:"shared_cache_duration"`
}

func configGetter(l logging.Logger, cfg config.ExtraConfig) (serviceConfig, error) {
	scfg := serviceConfig{}
	e, ok := cfg[ValidatorNamespace].(map[string]interface{})
	if !ok {
		return scfg, ErrNoValidatorCfg
	}
	tmp, err := json.Marshal(e)
	if err != nil {
		return scfg, err
	}
	if err := json.Unmarshal(tmp, &scfg); err != nil {
		return scfg, err
	}
	if scfg.CacheDuration == 0 {
		scfg.CacheDuration = defaultGlobalCacheMaxAge
		l.Info("[SERVICE: JOSE] Empty shared_cache_duration, using default (15m)")
	}
	return scfg, nil
}

// KeyIDGetter extracts a key id from a JSONWebKey
type KeyIDGetter interface {
	Get(*jose.JSONWebKey) string
}

// KeyIDGetterFunc function conforming to the KeyIDGetter interface.
type KeyIDGetterFunc func(*jose.JSONWebKey) string

// Get calls f(r)
func (f KeyIDGetterFunc) Get(key *jose.JSONWebKey) string {
	return f(key)
}

// DefaultKeyIDGetter returns the default kid as JSONWebKey key id
func DefaultKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID
}

// X5TKeyIDGetter extracts the key id from the jSONWebKey as the x5t
func X5TKeyIDGetter(key *jose.JSONWebKey) string {
	return b64.RawURLEncoding.EncodeToString(key.CertificateThumbprintSHA1)
}

// X5TS256KeyIDGetter extracts the key id from the jSONWebKey as the x5t#S256
func X5TS256KeyIDGetter(key *jose.JSONWebKey) string {
	return b64.RawURLEncoding.EncodeToString(key.CertificateThumbprintSHA256)
}

// CompoundX5TKeyIDGetter extracts the key id from the jSONWebKey as the a compound string of the kid and the x5t
func CompoundX5TKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID + X5TKeyIDGetter(key)
}

// KeyIDGetterFactory returns the KeyIDGetter for the given key identify strategy:
// "kid", "x5t", "x5t#S256" or "kid_x5t". Unknown strategies fall back to "kid".
func KeyIDGetterFactory(keyIdentifyStrategy string) KeyIDGetter {
	supportedKeyIdentifyStrategy := map[string]KeyIDGetterFunc{
		"kid":      DefaultKeyIDGetter,
		"x5t":      X5TKeyIDGetter,
		"x5t#S256": X5TS256KeyIDGetter,
		"kid_x5t":  CompoundX5TKeyIDGetter,
	}

	if keyGetter, ok := supportedKeyIdentifyStrategy[keyIdentifyStrategy]; ok {
		return keyGetter
	}
	return KeyIDGetterFunc(DefaultKeyIDGetter)
}

// KeyCacher stores the keys downloaded from a JWK.
type KeyCacher interface {
	Get(keyID string) (*jose.JSONWebKey, error)
	Add(keyID string, webKeys []jose.JSONWebKey) (*jose.JSONWebKey, error)
}

// MemoryKeyCacher is an in-memory KeyCacher with optional limits on the age of the keys
// and on the number of keys stored.
type MemoryKeyCacher struct {
	entries      map[string]keyCacherEntry
	maxKeyAge    time.Duration
	maxCacheSize int
	keyIDGetter  KeyIDGetter
	mu           *sync.RWMutex
}

type keyCacherEntry struct {
	addedAt time.Time
	jose.JSONWebKey
}

// GMemoryKeyCacher is a MemoryKeyCacher backed by a GlobalCacher. Keys are stored in
// both, and the keys missing in the local cache are looked up in the global one.
type GMemoryKeyCacher struct {
	*MemoryKeyCacher
	Global GlobalCacher
}

// Add adds the keys to the global cache, if any, and to the local one.
func (gkc *GMemoryKeyCacher) Add(keyID string, downloadedKeys []jose.JSONWebKey) (*jose.JSONWebKey, error) {
	if gkc.Global.kc != nil {
		gkc.Global.mu.Lock()
		gkc.Global.kc.Add(keyID, downloadedKeys)
		gkc.Global.mu.Unlock()
	}

	return gkc.MemoryKeyCacher.Add(keyID, downloadedKeys)
}

// Get obtains a key from the local cache, falling back to the global one, if any. Keys
// found in the global cache are copied to the local one.
func (gkc *GMemoryKeyCacher) Get(keyID string) (*jose.JSONWebKey, error) {
	k, err := gkc.MemoryKeyCacher.Get(keyID)
	if err == nil || gkc.Global.kc == nil {
		return k, err
	}

	gkc.Global.mu.RLock()
	v, err := gkc.Global.kc.Get(keyID)
	gkc.Global.mu.RUnlock()
	if err == nil {
		gkc.MemoryKeyCacher.Add(keyID, []jose.JSONWebKey{*v})
	}
	return v, err
}

// NewMemoryKeyCacher creates a new MemoryKeyCacher with the max age of the cached keys
// (MaxKeyAgeNoCheck disables the expiration) and the max size of the cache. A max size of
// -1 stores every downloaded key without limits; otherwise, only the requested key is
// stored and the oldest entry is evicted when the size is exceeded.
func NewMemoryKeyCacher(maxKeyAge time.Duration, maxCacheSize int, keyIdentifyStrategy string) *MemoryKeyCacher {
	return &MemoryKeyCacher{
		entries:      map[string]keyCacherEntry{},
		maxKeyAge:    maxKeyAge,
		maxCacheSize: maxCacheSize,
		keyIDGetter:  KeyIDGetterFactory(keyIdentifyStrategy),
		mu:           new(sync.RWMutex),
	}
}

// NewGlobalMemoryKeyCacher creates a GMemoryKeyCacher backed by the global cache of the
// key identify strategy, if SetGlobalCacher was called. Otherwise, it behaves as a
// MemoryKeyCacher.
func NewGlobalMemoryKeyCacher(maxKeyAge time.Duration, maxCacheSize int, keyIdentifyStrategy string) *GMemoryKeyCacher {
	kc := &GMemoryKeyCacher{
		MemoryKeyCacher: NewMemoryKeyCacher(maxKeyAge, maxCacheSize, keyIdentifyStrategy),
		Global:          GlobalCacher{},
	}
	if keyIdentifyStrategy == "" {
		keyIdentifyStrategy = defaultStrategy
	}
	if len(globalKeyCacher) > 0 {
		g := globalKeyCacher[keyIdentifyStrategy]
		kc.Global = g
	}
	return kc
}

// Get obtains a key from the cache, and checks if the key is expired
func (mkc *MemoryKeyCacher) Get(keyID string) (*jose.JSONWebKey, error) {
	mkc.mu.RLock()
	searchKey, ok := mkc.entries[keyID]
	mkc.mu.RUnlock()
	if ok {
		if mkc.maxKeyAge == MaxKeyAgeNoCheck || !mkc.keyIsExpired(keyID) {
			return &searchKey.JSONWebKey, nil
		}
		return nil, ErrKeyExpired
	}
	return nil, ErrNoKeyFound
}

// Add adds the downloaded keys into the cache, handles the overflow and returns the key
// with the given id, or ErrNoKeyFound if it is not among the downloaded keys.
func (mkc *MemoryKeyCacher) Add(keyID string, downloadedKeys []jose.JSONWebKey) (*jose.JSONWebKey, error) {
	var addingKey jose.JSONWebKey
	var addingKeyID string
	for i := range downloadedKeys {
		cacheKey := mkc.keyIDGetter.Get(&downloadedKeys[i])
		if cacheKey == keyID {
			addingKey = downloadedKeys[i]
			addingKeyID = cacheKey
		}
		if mkc.maxCacheSize == -1 {
			mkc.mu.Lock()
			mkc.entries[cacheKey] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: downloadedKeys[i],
			}
			mkc.mu.Unlock()
		}
	}
	if addingKey.Key != nil {
		if mkc.maxCacheSize != -1 {
			mkc.mu.Lock()
			mkc.entries[addingKeyID] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: addingKey,
			}
			mkc.mu.Unlock()
			mkc.handleOverflow()
		}
		return &addingKey, nil
	}
	return nil, ErrNoKeyFound
}

// keyIsExpired deletes the key from cache if it is expired
func (mkc *MemoryKeyCacher) keyIsExpired(keyID string) bool {
	mkc.mu.RLock()
	entry := mkc.entries[keyID].addedAt.Add(mkc.maxKeyAge)
	mkc.mu.RUnlock()

	if time.Now().After(entry) {
		mkc.mu.Lock()
		delete(mkc.entries, keyID)
		mkc.mu.Unlock()
		return true
	}
	return false
}

// handleOverflow deletes the oldest key from the cache if overflowed
func (mkc *MemoryKeyCacher) handleOverflow() {
	if mkc.maxCacheSize < len(mkc.entries) {
		mkc.mu.RLock()
		var oldestEntryKeyID string
		latestAddedTime := time.Now()
		for entryKeyID := range mkc.entries {
			if mkc.entries[entryKeyID].addedAt.Before(latestAddedTime) {
				latestAddedTime = mkc.entries[entryKeyID].addedAt
				oldestEntryKeyID = entryKeyID
			}
		}
		mkc.mu.RUnlock()

		mkc.mu.Lock()
		delete(mkc.entries, oldestEntryKeyID)
		mkc.mu.Unlock()
	}
}
