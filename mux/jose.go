package mux

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/auth0-community/go-auth0"
	krakendjose "github.com/devopsfaith/krakend-jose"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	muxkrakend "github.com/devopsfaith/krakend/router/mux"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func HandlerFactory(hf muxkrakend.HandlerFactory, paramExtractor muxkrakend.ParamExtractor, logger logging.Logger, rejecter krakendjose.Rejecter) muxkrakend.HandlerFactory {
	return TokenSigner(TokenSignatureValidator(hf, logger, rejecter), paramExtractor, logger)
}

func TokenSigner(hf muxkrakend.HandlerFactory, paramExtractor muxkrakend.ParamExtractor, logger logging.Logger) muxkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) http.HandlerFunc {
		signerCfg, signer, err := krakendjose.NewSigner(cfg, nil)
		if err != nil {
			logger.Error(err.Error(), cfg.Endpoint)
			return hf(cfg, prxy)
		}

		return func(w http.ResponseWriter, r *http.Request) {
			proxyReq := muxkrakend.NewRequestBuilder(paramExtractor)(r, cfg.QueryString, cfg.HeadersToPass)
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()

			response, err := prxy(ctx, proxyReq)
			if err != nil {
				logger.Error("proxy response error:", err.Error())
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			if response == nil {
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			for _, key := range signerCfg.KeysToSign {
				tmp, ok := response.Data[key]
				if !ok {
					continue
				}
				data, ok := tmp.(map[string]interface{})
				if !ok {
					continue
				}
				token, err := signer(data)
				if err != nil {
					logger.Error(err.Error())
					http.Error(w, "", http.StatusBadRequest)
					return
				}
				response.Data[key] = token
			}

			for k, v := range response.Metadata.Headers {
				w.Header().Set(k, v[0])
			}

			err = jsonRender(w, response)
			if err != nil {
				logger.Error("render answer error:", err.Error())
			}
		}
	}
}

var emptyResponse = []byte("{}")

func jsonRender(w http.ResponseWriter, response *proxy.Response) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.Metadata.StatusCode)

	if response == nil {
		_, err := w.Write(emptyResponse)
		return err
	}

	js, err := json.Marshal(response.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	_, err = w.Write(js)
	return err
}

func TokenSignatureValidator(hf muxkrakend.HandlerFactory, _ logging.Logger, rejecter krakendjose.Rejecter) muxkrakend.HandlerFactory {
	if rejecter == nil {
		rejecter = krakendjose.FixedRejecter(false)
	}
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) http.HandlerFunc {
		handler := hf(cfg, prxy)
		signatureConfig, err := krakendjose.GetSignatureConfig(cfg)
		if err != nil {
			return handler
		}

		validator, err := newValidator(signatureConfig)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		return func(w http.ResponseWriter, r *http.Request) {
			token, err := validator.ValidateRequest(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			claims := map[string]interface{}{}
			err = validator.Claims(r, token, &claims)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if rejecter.Reject(claims) {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			if !canAccess(signatureConfig.RolesKey, claims, signatureConfig.Roles) {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			handler(w, r)
		}
	}
}

func newValidator(signatureConfig *krakendjose.SignatureConfig) (*auth0.JWTValidator, error) {
	sa, ok := supportedAlgorithms[signatureConfig.Alg]
	if !ok {
		return nil, fmt.Errorf("JOSE: unknown algorithm %s", signatureConfig.Alg)
	}
	te := auth0.FromMultiple(
		auth0.RequestTokenExtractorFunc(auth0.FromHeader),
		auth0.RequestTokenExtractorFunc(FromCookie(signatureConfig.CookieKey)),
	)

	decodedFs, err := krakendjose.DecodeFingerprints(signatureConfig.Fingerprints)
	if err != nil {
		return nil, err
	}

	cfg := krakendjose.SecretProviderConfig{
		URI:          signatureConfig.URI,
		CacheEnabled: signatureConfig.CacheEnabled,
		Cs:           signatureConfig.CipherSuites,
		Fingerprints: decodedFs,
	}

	return auth0.NewValidator(
		auth0.NewConfiguration(
			krakendjose.SecretProvider(cfg, te),
			signatureConfig.Audience,
			signatureConfig.Issuer,
			sa,
		),
		te,
	), nil
}

func FromCookie(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if key == "" {
		key = "access_token"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(cookie.Value)
	}
}

func canAccess(roleKey string, claims map[string]interface{}, required []string) bool {
	if len(required) == 0 {
		return true
	}
	var roles []interface{}
	if tmp, ok := claims[roleKey]; ok {
		if v, ok := tmp.([]interface{}); ok {
			roles = v
		}
	}
	for _, role := range required {
		for _, r := range roles {
			if r.(string) == role {
				return true
			}
		}
	}
	return false
}

var supportedAlgorithms = map[string]jose.SignatureAlgorithm{
	"EdDSA": jose.EdDSA,
	"HS256": jose.HS256,
	"HS384": jose.HS384,
	"HS512": jose.HS512,
	"RS256": jose.RS256,
	"RS384": jose.RS384,
	"RS512": jose.RS512,
	"ES256": jose.ES256,
	"ES384": jose.ES384,
	"ES512": jose.ES512,
	"PS256": jose.PS256,
	"PS384": jose.PS384,
	"PS512": jose.PS512,
}
