package jose

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/devopsfaith/krakend/config"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	ValidatorNamespace = "github.com/devopsfaith/krakend-jose/validator"
	SignerNamespace    = "github.com/devopsfaith/krakend-jose/signer"
	defaultRolesKey    = "roles"
)

type signatureConfig struct {
	Alg          string   `json:"alg"`
	URI          string   `json:"jwk-url"`
	CacheEnabled bool     `json:"cache,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	Audience     []string `json:"audience,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	RolesKey     string   `json:"roles_key,omitempty"`
	CookieKey    string   `json:"cookie_key,omitempty"`
}

type signerConfig struct {
	Alg               string   `json:"alg"`
	KeyID             string   `json:"kid"`
	URI               string   `json:"jwk-url"`
	FullSerialization bool     `json:"full,omitempty"`
	KeysToSign        []string `json:"keys-to-sign,omitempty"`
}

func getSignatureConfig(cfg *config.EndpointConfig) (*signatureConfig, error) {
	tmp, ok := cfg.ExtraConfig[ValidatorNamespace]
	if !ok {
		return nil, errors.New("JOSE: no validator config")
	}
	data, _ := json.Marshal(tmp)
	res := new(signatureConfig)
	err := json.Unmarshal(data, res)

	if res.RolesKey == "" {
		res.RolesKey = defaultRolesKey
	}
	return res, err
}

func getSignerConfig(cfg *config.EndpointConfig) (*signerConfig, error) {
	tmp, ok := cfg.ExtraConfig[SignerNamespace]
	if !ok {
		return nil, errors.New("JOSE: no signer config")
	}
	data, _ := json.Marshal(tmp)
	res := new(signerConfig)
	err := json.Unmarshal(data, res)
	return res, err
}

func newSigner(cfg *config.EndpointConfig) (*signerConfig, Signer, error) {
	signerCfg, err := getSignerConfig(cfg)
	if err != nil {
		return signerCfg, nopSigner, err
	}

	sp := secretProvider(signerCfg.URI, false)
	key, err := sp.GetKey(signerCfg.KeyID)
	if err != nil {
		return signerCfg, nopSigner, err
	}
	if key.IsPublic() {
		// TODO: we should not sign with a public key
	}
	signingKey := jose.SigningKey{
		Key:       key.Key,
		Algorithm: jose.SignatureAlgorithm(signerCfg.Alg),
	}
	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): key.KeyID,
		},
	}
	s, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return signerCfg, nopSigner, err
	}

	if signerCfg.FullSerialization {
		return signerCfg, fullSerializeSigner{signer{s}}.Sign, nil
	}
	return signerCfg, compactSerializeSigner{signer{s}}.Sign, nil
}

type Signer func(interface{}) (string, error)

func nopSigner(_ interface{}) (string, error) { return "", nil }

type signer struct {
	signer jose.Signer
}

func (s signer) sign(v interface{}) (*jose.JSONWebSignature, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize payload: %s", err.Error())
	}
	return s.signer.Sign(data)
}

type fullSerializeSigner struct {
	signer
}

func (f fullSerializeSigner) Sign(v interface{}) (string, error) {
	obj, err := f.sign(v)
	if err != nil {
		return "", fmt.Errorf("unable to sign payload: %s", err.Error())
	}
	return obj.FullSerialize(), nil
}

type compactSerializeSigner struct {
	signer
}

func (c compactSerializeSigner) Sign(v interface{}) (string, error) {
	obj, err := c.sign(v)
	if err != nil {
		return "", fmt.Errorf("unable to sign payload: %s", err.Error())
	}
	return obj.CompactSerialize()
}
