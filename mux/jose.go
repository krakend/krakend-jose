package mux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	krakendjose "github.com/krakend/krakend-jose/v3"
	josehttp "github.com/krakend/krakend-jose/v3/http"
	"github.com/luraproject/lura/v3/config"
	"github.com/luraproject/lura/v3/logging"
	"github.com/luraproject/lura/v3/proxy"
	muxlura "github.com/luraproject/lura/v3/router/mux"
)

func HandlerFactory(hf muxlura.HandlerFactory, paramExtractor muxlura.ParamExtractor, logger logging.Logger, rejecterF krakendjose.RejecterFactory) muxlura.HandlerFactory {
	return TokenSignatureValidator(TokenSigner(hf, paramExtractor, logger), logger, rejecterF)
}

func TokenSigner(hf muxlura.HandlerFactory, paramExtractor muxlura.ParamExtractor, logger logging.Logger) muxlura.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) http.HandlerFunc {
		signerCfg, signer, err := krakendjose.NewSigner(cfg, nil)
		if err == krakendjose.ErrNoSignerCfg {
			logger.Info("JOSE: signer disabled for the endpoint", cfg.Endpoint)
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error("JOSE: unable to create the signer for the endpoint", cfg.Endpoint)
			logger.Error(err.Error())
			return hf(cfg, prxy)
		}

		logger.Info("JOSE: signer enabled for the endpoint", cfg.Endpoint)

		return func(w http.ResponseWriter, r *http.Request) {
			proxyReq := muxlura.NewRequestBuilder(paramExtractor)(r, cfg.QueryString, cfg.HeadersToPass)
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

	if response == nil {
		_, err := w.Write(emptyResponse)
		return err
	}

	w.WriteHeader(response.Metadata.StatusCode)

	js, err := json.Marshal(response.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	_, err = w.Write(js)
	return err
}

func TokenSignatureValidator(hf muxlura.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) muxlura.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) http.HandlerFunc {
		logPrefix := fmt.Sprintf("[ENDPOINT: %s %s][JWTValidator]", cfg.Method, cfg.Endpoint)
		handler := hf(cfg, prxy)
		scfg, err := krakendjose.GetSignatureConfig(cfg)
		if err == krakendjose.ErrNoValidatorCfg {
			logger.Info("JOSE: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}
		if err != nil {
			logger.Warning(logPrefix, "Unable to parse the configuration:", err.Error())
			return erroredHandler
		}

		if rejecterF == nil {
			rejecterF = new(krakendjose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)

		jwtChecker, err := krakendjose.NewJWTChecks(scfg, logger, logPrefix, rejecter)
		if err != nil {
			logger.Warning(logPrefix, "Unable to create JWT validator:", err.Error())
			return erroredHandler
		}

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

		strTokenExtractor := josehttp.StrTokenFromHeaderOrCookieFn(scfg.AuthHeaderName, scfg.CookieKey)
		ps, err := krakendjose.NewPropagators(scfg.PropagateClaimsToHeader)
		if err != nil && err != krakendjose.ErrNoHeadersToPropagate {
			logger.Warning(logPrefix, fmt.Sprintf("error preparing header propagators: %s", err.Error()))
		}

		return func(w http.ResponseWriter, r *http.Request) {
			strToken, err := strTokenExtractor(r)
			if err != nil {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Unable to validate the token:", err.Error())
				}
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			claims, err := jwtChecker.Check(strToken)
			if err != nil {
				status := josehttp.CheckErrorToStatusCode(err)
				msg := ""
				if status == http.StatusUnauthorized && !errors.Is(err, krakendjose.ErrTokenRejected) {
					msg = err.Error()
				}
				http.Error(w, msg, status)
				return
			}

			josehttp.PropagateHeaders(r, ps, claims, scfg.PropagateClaimsPreserveArray)

			handler(w, r)
		}
	}
}

func erroredHandler(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "", http.StatusUnauthorized)
}

// FromCookie aliases http.FromCokie. Deprecated: use github.com/krakend/krakend-jose/v3/http.FromCookie
var FromCookie = josehttp.FromCookie

// FromHeader aliases http.FromHeader. Deprecated: use github.com/krakend/krakend-jose/v3/http.FromHeader
var FromHeader = josehttp.FromHeader
