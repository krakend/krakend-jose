package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"

	"gocloud.dev/secrets"
	_ "gocloud.dev/secrets/awskms"
	_ "gocloud.dev/secrets/azurekeyvault"
	_ "gocloud.dev/secrets/gcpkms"
	_ "gocloud.dev/secrets/hashivault"
	_ "gocloud.dev/secrets/localsecrets"
)

// OpenCensusViews are predefined views for OpenCensus metrics.
// The views include counts and latency distributions for API method calls.
var OpenCensusViews = secrets.OpenCensusViews

// New returns a Cypher wrapping a secrets.Keeper accesing the secret stored at the given
// url. The url depends on the secrets driver required (awskms, azurekeyvault, gcpkms,
// hashivault and localsecrets).
// See the URLOpener documentation in gocloud.dev/secrets driver subpackages for
// details on supported URL formats, and https://gocloud.dev/concepts/urls
// for more information.
func New(ctx context.Context, url string) (*Cypher, error) {
	k, err := secrets.OpenKeeper(ctx, url)
	if err != nil {
		return nil, err
	}
	return &Cypher{keeper: k}, nil
}

// Cypher is a structure able to encrypt and decrypt messages with an encrypted key.
// Before encrypting or decrypting the message, the encrypted key is decrypted with the
// help of the wrapped secrets.Keeper
type Cypher struct {
	keeper *secrets.Keeper
}

// Encrypt encrypts a plain text using a encrypted key, returning a cipher message. Before using the given key,
// it decrypts the key with the secrets.Keeper
func (c *Cypher) Encrypt(ctx context.Context, plainText, cipheredKey []byte) ([]byte, error) {
	plainKey, err := c.keeper.Decrypt(ctx, cipheredKey)
	if err != nil {
		return []byte{}, err
	}
	return Encrypt(plainText, plainKey)
}

// Decrypt decrypts an encrypted text using a encrypted key, returning a plain message. Before using the given
// key, it decrypts the key with the secrets.Keeper
func (c *Cypher) Decrypt(ctx context.Context, cipherText, cipheredKey []byte) ([]byte, error) {
	plainKey, err := c.keeper.Decrypt(ctx, cipheredKey)
	if err != nil {
		return []byte{}, err
	}
	return Decrypt(cipherText, plainKey)
}

// EncryptKey encrypts the given plain key with the secrets.Keeper
func (c *Cypher) EncryptKey(ctx context.Context, plainKey []byte) ([]byte, error) {
	return c.keeper.Encrypt(ctx, plainKey)
}

// Close releases any resources used for the Cypher
func (c *Cypher) Close() {
	c.keeper.Close()
}

func createHash(key []byte) string {
	hasher := md5.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

// Encrypt encrypts the received data with a passphrase using AES GCM
func Encrypt(data, passphrase []byte) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts the received data with a passphrase using AES GCM
func Decrypt(data, passphrase []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return []byte{}, err
	}
	return plaintext, nil
}
