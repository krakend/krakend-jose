package jose

import (
	b64 "encoding/base64"
	"errors"
	"time"

	"gopkg.in/square/go-jose.v2"
)

var (
	ErrNoKeyFound = errors.New("no Keys have been found")
	ErrKeyExpired = errors.New("key exists but is expired")

	// Configuring with MaxKeyAgeNoCheck will skip key expiry check
	MaxKeyAgeNoCheck = time.Duration(-1)
)

//KeyIDGetter extracts a key id from a JSONWebKey
type KeyIDGetter interface {
	Get(*jose.JSONWebKey) string
}

//KeyIDGetterFunc function conforming to the KeyIDGetter interface.
type KeyIDGetterFunc func(*jose.JSONWebKey) string

// Get calls f(r)
func (f KeyIDGetterFunc) Get(key *jose.JSONWebKey) string {
	return f(key)
}

//DefaultKeyIDGetter returns the default kid as JSONWebKey key id
func DefaultKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID
}

//X5TKeyIDGetter extracts the key id from the jSONWebKey as the x5t
func X5TKeyIDGetter(key *jose.JSONWebKey) string {
	return b64.RawURLEncoding.EncodeToString(key.CertificateThumbprintSHA1)
}

//CompoundX5TKeyIDGetter extracts the key id from the jSONWebKey as the a compound string of the kid and the x5t
func CompoundX5TKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID + X5TKeyIDGetter(key)
}

func KeyIDGetterFactory(keyIdentifyStrategy string) KeyIDGetter {

	var supportedKeyIdentifyStrategy = map[string]KeyIDGetterFunc{
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
	for _, key := range downloadedKeys {
		cacheKey := mkc.keyIDGetter.Get(&key)
		if cacheKey == keyID {
			addingKey = key
			addingKeyID = cacheKey
		}
		if mkc.maxCacheSize == -1 {
			mkc.entries[cacheKey] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: key,
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
		var latestAddedTime = time.Now()
		for entryKeyID, entry := range mkc.entries {
			if entry.addedAt.Before(latestAddedTime) {
				latestAddedTime = entry.addedAt
				oldestEntryKeyID = entryKeyID
			}
		}
		delete(mkc.entries, oldestEntryKeyID)
	}
}
