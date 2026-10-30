package jose

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
)

var (
	ErrNoKeyFound                   = errors.New("no Keys have been found")
	ErrKeyExpired                   = errors.New("key exists but is expired")
	defaultGlobalCacheMaxAge uint32 = 900
	defaultStrategy                 = "kid"

	// globalCacheScopeSep separates the JWK provider uri from the key id in the shared
	// global cache keys. The NUL byte does not appear in uris nor in key ids, so it keeps
	// the scope unambiguous.
	globalCacheScopeSep = "\x00"

	// Configuring with MaxKeyAgeNoCheck will skip key expiry check
	MaxKeyAgeNoCheck    = time.Duration(-1)
	globalKeyCacher     = map[string]GlobalCacher{}
	globalKeyCacherOnce = new(sync.Once)
)

type GlobalCacher struct {
	kc *MemoryKeyCacher
	mu *sync.RWMutex
}

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

type KeyCacher interface {
	Get(keyID string) (*jose.JSONWebKey, error)
	Add(keyID string, webKeys []jose.JSONWebKey) (*jose.JSONWebKey, error)
}

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

type GMemoryKeyCacher struct {
	*MemoryKeyCacher
	Global GlobalCacher
	// uri of the JWK provider, used to scope the entries in the shared global cache so
	// that providers publishing different keys under the same id cannot read each other's.
	uri string
}

// globalScope returns the prefix that namespaces this provider's entries in the shared
// global cache.
func (gkc *GMemoryKeyCacher) globalScope() string {
	return gkc.uri + globalCacheScopeSep
}

func (gkc *GMemoryKeyCacher) Add(keyID string, downloadedKeys []jose.JSONWebKey) (*jose.JSONWebKey, error) {
	if gkc.Global.kc != nil {
		gkc.Global.mu.Lock()
		gkc.Global.kc.addScoped(gkc.globalScope(), downloadedKeys)
		gkc.Global.mu.Unlock()
	}

	return gkc.MemoryKeyCacher.Add(keyID, downloadedKeys)
}

// Get obtains a key from the cache, and checks if the key is expired
func (gkc *GMemoryKeyCacher) Get(keyID string) (*jose.JSONWebKey, error) {
	k, err := gkc.MemoryKeyCacher.Get(keyID)
	if err == nil || gkc.Global.kc == nil {
		return k, err
	}

	gkc.Global.mu.RLock()
	v, err := gkc.Global.kc.Get(gkc.globalScope() + keyID)
	gkc.Global.mu.RUnlock()
	if err == nil {
		gkc.MemoryKeyCacher.Add(keyID, []jose.JSONWebKey{*v})
	}
	return v, err
}

// NewMemoryKeyCacher creates a new Keycacher interface with option
// to set max age of cached keys and max size of the cache.
func NewMemoryKeyCacher(maxKeyAge time.Duration, maxCacheSize int, keyIdentifyStrategy string) *MemoryKeyCacher {
	return &MemoryKeyCacher{
		entries:      map[string]keyCacherEntry{},
		maxKeyAge:    maxKeyAge,
		maxCacheSize: maxCacheSize,
		keyIDGetter:  KeyIDGetterFactory(keyIdentifyStrategy),
		mu:           new(sync.RWMutex),
	}
}

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

// NewGlobalMemoryKeyCacherWithURI is like NewGlobalMemoryKeyCacher but scopes this provider's
// entries in the shared global cache by uri, so that providers publishing different keys under
// the same key id cannot read each other's.
func NewGlobalMemoryKeyCacherWithURI(maxKeyAge time.Duration, maxCacheSize int, keyIdentifyStrategy, uri string) *GMemoryKeyCacher {
	kc := NewGlobalMemoryKeyCacher(maxKeyAge, maxCacheSize, keyIdentifyStrategy)
	kc.uri = uri
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

// Add adds a key into the cache and handles overflow
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

// addScoped stores every downloaded key in the cache under a composite key that prepends
// scope to the key id, so entries from different JWK providers do not collide even when
// they share the same key id. It is used for the shared global cache, which keeps every
// downloaded key.
func (mkc *MemoryKeyCacher) addScoped(scope string, downloadedKeys []jose.JSONWebKey) {
	mkc.mu.Lock()
	defer mkc.mu.Unlock()
	for i := range downloadedKeys {
		cacheKey := scope + mkc.keyIDGetter.Get(&downloadedKeys[i])
		mkc.entries[cacheKey] = keyCacherEntry{
			addedAt:    time.Now(),
			JSONWebKey: downloadedKeys[i],
		}
	}
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
