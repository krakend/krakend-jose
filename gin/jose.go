package gin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	auth0 "github.com/auth0-community/go-auth0"
	krakendjose "github.com/devopsfaith/krakend-jose"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	ginkrakend "github.com/devopsfaith/krakend/router/gin"
	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2/jwt"
)

func HandlerFactory(hf ginkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginkrakend.HandlerFactory {
	return TokenSigner(TokenSignatureValidator(hf, logger, rejecterF), logger)
}

func TokenSigner(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
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

		return func(c *gin.Context) {
			proxyReq := ginkrakend.NewRequest(cfg.HeadersToPass)(c, cfg.QueryString)
			ctx, cancel := context.WithTimeout(c, cfg.Timeout)
			defer cancel()

			response, err := prxy(ctx, proxyReq)
			if err != nil {
				logger.Error("proxy response error:", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if response == nil {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if err := krakendjose.SignFields(signerCfg.KeysToSign, signer, response); err != nil {
				logger.Error(err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			for k, v := range response.Metadata.Headers {
				c.Header(k, v[0])
			}
			c.JSON(response.Metadata.StatusCode, response.Data)
		}
	}
}

func TokenSignatureValidator(hf ginkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		if rejecterF == nil {
			rejecterF = new(krakendjose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)

		handler := hf(cfg, prxy)
		scfg, err := krakendjose.GetSignatureConfig(cfg)
		if err == krakendjose.ErrNoValidatorCfg {
			logger.Info("JOSE: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: validator for %s: %s", cfg.Endpoint, err.Error()))
			return handler
		}

		validator, err := krakendjose.NewValidator(scfg, FromCookie)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		var aclCheck func(string, map[string]interface{}, []string) bool

		if strings.Contains(scfg.RolesKey, ".") {
			aclCheck = krakendjose.CanAccessNested
		} else {
			aclCheck = krakendjose.CanAccess
		}

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			token, err := validator.ValidateRequest(c.Request)
			if err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}

			claims := map[string]interface{}{}
			err = validator.Claims(c.Request, token, &claims)
			if err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}

			if rejecter.Reject(claims) {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if !aclCheck(scfg.RolesKey, claims, scfg.Roles) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			handler(c)
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
