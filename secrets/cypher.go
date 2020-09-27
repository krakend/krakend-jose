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

func New(ctx context.Context, url string) (*Cypher, error) {
	k, err := secrets.OpenKeeper(ctx, url)
	if err != nil {
		return nil, err
	}
	return &Cypher{keeper: k}, nil
}

type Cypher struct {
	keeper *secrets.Keeper
}

func (c *Cypher) Encrypt(ctx context.Context, plainText, cipheredKey []byte) ([]byte, error) {
	plainKey, err := c.keeper.Decrypt(ctx, cipheredKey)
	if err != nil {
		return []byte{}, err
	}
	return Encrypt(plainText, plainKey)
}

func (c *Cypher) Decrypt(ctx context.Context, cipherText, cipheredKey []byte) ([]byte, error) {
	plainKey, err := c.keeper.Decrypt(ctx, cipheredKey)
	if err != nil {
		return []byte{}, err
	}
	return Decrypt(cipherText, plainKey)
}

func (c *Cypher) EncryptKey(ctx context.Context, plainKey []byte) ([]byte, error) {
	return c.keeper.Encrypt(ctx, plainKey)
}

func (c *Cypher) Close() {
	c.keeper.Close()
}

func createHash(key []byte) string {
	hasher := md5.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

func Encrypt(data []byte, passphrase []byte) ([]byte, error) {
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

func Decrypt(data []byte, passphrase []byte) ([]byte, error) {
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
