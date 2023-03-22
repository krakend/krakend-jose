package jose

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"gopkg.in/square/go-jose.v2"
)

var (
	ErrNoKeyFound                   = errors.New("no Keys have been found")
	ErrKeyExpired                   = errors.New("key exists but is expired")
	defaultGlobalCacheMaxAge uint32 = 900
	defaultStrategy                 = "kid"

	// Configuring with MaxKeyAgeNoCheck will skip key expiry check
	MaxKeyAgeNoCheck    = time.Duration(-1)
	globalKeyCacher     = map[string]GlobalCacher{}
	globalKeyCacherOnce = new(sync.Once)
)

type GlobalCacher struct {
	kc KeyCacher
	mu *sync.RWMutex
}

func SetGlobalCacher(l logging.Logger, cfg config.ExtraConfig) error {
	scfg, err := configGetter(l, cfg)
	if err != nil {
		if err != ErrNoValidatorCfg {
			l.Error("[SERVICE: JOSE]", err.Error())
		}
		return err
	}
	duration := time.Duration(scfg.CacheDuration) * time.Second
	globalKeyCacherOnce.Do(func() {
		globalKeyCacher = map[string]GlobalCacher{
			"kid":     {kc: NewMemoryKeyCacher(duration, -1, "kid"), mu: new(sync.RWMutex)},
			"x5t":     {kc: NewMemoryKeyCacher(duration, -1, "x5t"), mu: new(sync.RWMutex)},
			"kid_x5t": {kc: NewMemoryKeyCacher(duration, -1, "kid_x5t"), mu: new(sync.RWMutex)},
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
		return scfg, fmt.Errorf("no config")
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
		l.Error("[SERVICE: JOSE] Empty shared_cache_duration, using default (15m)")
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

// CompoundX5TKeyIDGetter extracts the key id from the jSONWebKey as the a compound string of the kid and the x5t
func CompoundX5TKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID + X5TKeyIDGetter(key)
}

func KeyIDGetterFactory(keyIdentifyStrategy string) KeyIDGetter {
	supportedKeyIdentifyStrategy := map[string]KeyIDGetterFunc{
		"kid":     DefaultKeyIDGetter,
		"x5t":     X5TKeyIDGetter,
		"kid_x5t": CompoundX5TKeyIDGetter,
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
}

type keyCacherEntry struct {
	addedAt time.Time
	jose.JSONWebKey
}

type GMemoryKeyCacher struct {
	*MemoryKeyCacher
	Global GlobalCacher
}

func (gkc *GMemoryKeyCacher) Add(keyID string, downloadedKeys []jose.JSONWebKey) (*jose.JSONWebKey, error) {
	if gkc.Global.kc != nil {
		gkc.Global.mu.Lock()
		gkc.Global.kc.Add(keyID, downloadedKeys)
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
	v, err := gkc.Global.kc.Get(keyID)
	gkc.Global.mu.RUnlock()
	if err == nil {
		gkc.MemoryKeyCacher.Add(keyID, []jose.JSONWebKey{*v})
	}
	return v, err
}

// NewMemoryKeyCacher creates a new Keycacher interface with option
// to set max age of cached keys and max size of the cache.
func NewMemoryKeyCacher(maxKeyAge time.Duration, maxCacheSize int, keyIdentifyStrategy string) KeyCacher {
	return &MemoryKeyCacher{
		entries:      map[string]keyCacherEntry{},
		maxKeyAge:    maxKeyAge,
		maxCacheSize: maxCacheSize,
		keyIDGetter:  KeyIDGetterFactory(keyIdentifyStrategy),
	}
}

func NewGlobalMemoryKeyCacher(maxKeyAge time.Duration, maxCacheSize int, keyIdentifyStrategy string) KeyCacher {
	kc := &GMemoryKeyCacher{
		MemoryKeyCacher: &MemoryKeyCacher{
			entries:      map[string]keyCacherEntry{},
			maxKeyAge:    maxKeyAge,
			maxCacheSize: maxCacheSize,
			keyIDGetter:  KeyIDGetterFactory(keyIdentifyStrategy),
		},
		Global: GlobalCacher{},
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
	searchKey, ok := mkc.entries[keyID]
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
			mkc.entries[cacheKey] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: downloadedKeys[i],
			}
		}
	}
	if addingKey.Key != nil {
		if mkc.maxCacheSize != -1 {
			mkc.entries[addingKeyID] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: addingKey,
			}
			mkc.handleOverflow()
		}
		return &addingKey, nil
	}
	return nil, ErrNoKeyFound
}

// keyIsExpired deletes the key from cache if it is expired
func (mkc *MemoryKeyCacher) keyIsExpired(keyID string) bool {
	if time.Now().After(mkc.entries[keyID].addedAt.Add(mkc.maxKeyAge)) {
		delete(mkc.entries, keyID)
		return true
	}
	return false
}

// handleOverflow deletes the oldest key from the cache if overflowed
func (mkc *MemoryKeyCacher) handleOverflow() {
	if mkc.maxCacheSize < len(mkc.entries) {
		var oldestEntryKeyID string
		latestAddedTime := time.Now()
		for entryKeyID := range mkc.entries {
			if mkc.entries[entryKeyID].addedAt.Before(latestAddedTime) {
				latestAddedTime = mkc.entries[entryKeyID].addedAt
				oldestEntryKeyID = entryKeyID
			}
		}
		delete(mkc.entries, oldestEntryKeyID)
	}
}
