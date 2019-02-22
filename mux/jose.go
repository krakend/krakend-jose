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
	"gopkg.in/square/go-jose.v2/jwt"
)

func HandlerFactory(hf muxkrakend.HandlerFactory, paramExtractor muxkrakend.ParamExtractor, logger logging.Logger, rejecterF krakendjose.RejecterFactory) muxkrakend.HandlerFactory {
	return TokenSigner(TokenSignatureValidator(hf, logger, rejecterF), paramExtractor, logger)
}

func TokenSigner(hf muxkrakend.HandlerFactory, paramExtractor muxkrakend.ParamExtractor, logger logging.Logger) muxkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) http.HandlerFunc {
		signerCfg, signer, err := krakendjose.NewSigner(cfg, nil)
		if err == krakendjose.ErrNoSignerCfg {
			logger.Info("JOSE: singer disabled for the endpoint", cfg.Endpoint)
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error(err.Error(), cfg.Endpoint)
			return hf(cfg, prxy)
		}

		logger.Info("JOSE: singer enabled for the endpoint", cfg.Endpoint)

		return func(w http.ResponseWriter, r *http.Request) {
			proxyReq := muxkrakend.NewRequestBuilder(paramExtractor)(r, cfg.QueryString, cfg.HeadersToPass)
			ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout)
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

			if err := krakendjose.SignFields(signerCfg.KeysToSign, signer, response); err != nil {
				logger.Error(err.Error())
				http.Error(w, "", http.StatusBadRequest)
				return
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

func TokenSignatureValidator(hf muxkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) muxkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) http.HandlerFunc {
		if rejecterF == nil {
			rejecterF = new(krakendjose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)

		handler := hf(cfg, prxy)
		signatureConfig, err := krakendjose.GetSignatureConfig(cfg)
		if err == krakendjose.ErrNoValidatorCfg {
			logger.Info("JOSE: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: validator for %s: %s", cfg.Endpoint, err.Error()))
			return handler
		}

		validator, err := krakendjose.NewValidator(signatureConfig, FromCookie)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

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

			if !krakendjose.CanAccess(signatureConfig.RolesKey, claims, signatureConfig.Roles) {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			handler(w, r)
		}
	}
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
