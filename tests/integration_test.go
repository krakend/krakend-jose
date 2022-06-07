package tests

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	krakendjose "github.com/krakendio/krakend-jose/v2"
	jose "github.com/krakendio/krakend-jose/v2/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	ginlura "github.com/luraproject/lura/v2/router/gin"
)

func TestJoseMw(t *testing.T) {
	hf := ginlura.HandlerFactory(func(_ *config.EndpointConfig, _ proxy.Proxy) gin.HandlerFunc {
		return func(c *gin.Context) {
			t.Error("this handler should not be executed")
		}
	})

	buf := bytes.NewBuffer([]byte{})
	logger, _ := logging.NewLogger("DEBUG", buf, "")

	hf = jose.HandlerFactory(hf, logger, new(krakendjose.NopRejecterFactory))

	signerProxy := func(_ context.Context, _ *proxy.Request) (*proxy.Response, error) {
		return &proxy.Response{
			IsComplete: true,
			Data: map[string]interface{}{
				"access_token": map[string]interface{}{
					"aud":   "http://api.example.com",
					"iss":   "https://krakend.io",
					"sub":   "1234567890qwertyuio",
					"jti":   "mnb23vcsrt756yuiomnbvcx98ertyuiop",
					"roles": []interface{}{"role_a", "role_b"},
					"exp":   1735689600,
				},
				"refresh_token": map[string]interface{}{
					"aud": "http://api.example.com",
					"iss": "https://krakend.io",
					"sub": "1234567890qwertyuio",
					"jti": "mnb23vcsrt756yuiomn12876bvcx98ertyuiop",
					"exp": 1735689600,
				},
				"exp": 1735689600,
			},
		}, nil
	}

	signerCfg := &config.EndpointConfig{
		Endpoint: "/token/asymmetric/file",
		Backend: []*config.Backend{
			{
				URLPattern: "/token.json",
			},
		},
		ExtraConfig: map[string]interface{}{
			"github.com/devopsfaith/krakend-jose/signer": map[string]interface{}{
				"alg":                  "RS256",
				"kid":                  "2011-04-29",
				"keys-to-sign":         []interface{}{"access_token", "refresh_token"},
				"jwk_local_path":       "../fixtures/private.json",
				"disable_jwk_security": true,
			},
		},
	}

	gin.SetMode(gin.TestMode)
	e := gin.New()
	e.GET(signerCfg.Endpoint, hf(signerCfg, signerProxy))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", signerCfg.Endpoint, nil)

	e.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != 200 {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Println(string(body))
	fmt.Println(buf.String())
}
