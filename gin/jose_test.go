package gin

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	jose "github.com/krakendio/krakend-jose/v2"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	ginlura "github.com/luraproject/lura/v2/router/gin"
)

func TestTokenSignatureValidator(t *testing.T) {
	server := httptest.NewServer(jwkEndpoint("public"))
	defer server.Close()

	validatorEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_a"}, false)

	forbidenEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_c"}, false)
	forbidenEndpointCfg.Endpoint = "/forbiden"

	registeredEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{}, false)
	registeredEndpointCfg.Endpoint = "/registered"
	registeredEndpointCfg.Backend[0].URLPattern = "/{{.JWT.sub}}/{{.JWT.jti}}?foo={{.JWT.iss}}"

	propagateHeadersEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{}, false)
	propagateHeadersEndpointCfg.Endpoint = "/propagateheaders"

	optionalEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{}, true)
	optionalEndpointCfg.Endpoint = "/optional"

	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.NrLwxZK8UhS6CV2ijdJLUfAinpjBn5_uliZCdzQ7v-Dc8lcv1AQA9cYsG63RseKWH9u6-TqPKMZQ56WfhqL028BLDdQCiaeuBoLzYU1tQLakA1V0YmouuEVixWLzueVaQhyGx-iKuiuFhzHWZSqFqSehiyzI9fb5O6Gcc2L6rMEoxQMaJomVS93h-t013MNq3ADLWTXRaO-negydqax_WmzlVWp_RDroR0s5J2L2klgmBXVwh6SYy5vg7RrnuN3S8g4oSicJIi9NgnG-dDikuaOg2DeFUt-mYq_j_PbNXf9TUl5hl4kEy7E0JauJ17d1BUuTl3ChY4BOmhQYRN0dYg"
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	dummyProxy := func(ctx context.Context, req *proxy.Request) (*proxy.Response, error) {
		return &proxy.Response{
			Data: map[string]interface{}{
				"aaaa": map[string]interface{}{
					"foo": "a",
					"bar": "b",
				},
				"bbbb": true,
				"cccc": 1234567890,
			},
			IsComplete: true,
			Metadata: proxy.Metadata{
				StatusCode: 200,
			},
		}, nil
	}

	buf := new(bytes.Buffer)
	logger, _ := logging.NewLogger("DEBUG", buf, "")
	hf := HandlerFactory(ginlura.EndpointHandler, logger, nil)

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	assertProxy := func(ctx context.Context, r *proxy.Request) (*proxy.Response, error) {
		if v, ok := r.Params["JWT.sub"]; !ok {
			t.Errorf("JWT param not injected: %v", r.Params)
		} else if v != "1234567890qwertyuio" {
			t.Errorf("wrong JWT param injected (sub): %v", v)
		}

		if v, ok := r.Params["JWT.jti"]; !ok {
			t.Errorf("JWT param not injected: %v", r.Params)
		} else if v != "mnb23vcsrt756yuiomnbvcx98ertyuiop" {
			t.Errorf("wrong JWT param injected (jti): %v", v)
		}

		if v, ok := r.Params["JWT.iss"]; !ok {
			t.Errorf("JWT param not injected: %v", r.Params)
		} else if v != "http://example.com" {
			t.Errorf("wrong JWT param injected (iss): %v", v)
		}

		return dummyProxy(ctx, r)
	}

	engine.GET(validatorEndpointCfg.Endpoint, hf(validatorEndpointCfg, dummyProxy))
	engine.GET(forbidenEndpointCfg.Endpoint, hf(forbidenEndpointCfg, dummyProxy))
	engine.GET(registeredEndpointCfg.Endpoint, hf(registeredEndpointCfg, assertProxy))
	engine.GET(propagateHeadersEndpointCfg.Endpoint, hf(propagateHeadersEndpointCfg, dummyProxy))
	engine.GET(optionalEndpointCfg.Endpoint, hf(optionalEndpointCfg, dummyProxy))

	if log := buf.String(); !strings.Contains(log, "DEBUG: [ENDPOINT: /propagateheaders][JWTSigner] Signer disabled") {
		t.Error(log)
		t.Fail()
		return
	}

	t.Run("unathorized without token", func(t *testing.T) {
		req := httptest.NewRequest("GET", forbidenEndpointCfg.Endpoint, new(bytes.Buffer))

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assertStatus(t, w.Code, http.StatusUnauthorized)
		assertBody(t, w.Body.String(), "")
	})

	t.Run("ok with correct token", func(t *testing.T) {
		req := httptest.NewRequest("GET", validatorEndpointCfg.Endpoint, new(bytes.Buffer))
		req.Header.Set("Authorization", "BEARER "+token)

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assertStatus(t, w.Code, http.StatusOK)
		assertBody(t, w.Body.String(), "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}")
	})

	t.Run("forbidden with incorrect roles", func(t *testing.T) {
		req := httptest.NewRequest("GET", forbidenEndpointCfg.Endpoint, new(bytes.Buffer))
		req.Header.Set("Authorization", "BEARER "+token)

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assertStatus(t, w.Code, http.StatusForbidden)
		assertBody(t, w.Body.String(), "")
	})

	t.Run("ok with param extractor", func(t *testing.T) {
		req := httptest.NewRequest("GET", registeredEndpointCfg.Endpoint, new(bytes.Buffer))
		req.Header.Set("Authorization", "BEARER "+token)

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assertStatus(t, w.Code, http.StatusOK)
		assertBody(t, w.Body.String(), "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}")
	})

	t.Run("ok with propagate headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", propagateHeadersEndpointCfg.Endpoint, new(bytes.Buffer))
		req.Header.Set("Authorization", "BEARER "+token)
		// Check header-overwrite: it must be overwritten by a claim in the JWT!
		req.Header.Set("x-krakend-replace", "abc")

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assertStatus(t, w.Code, http.StatusOK)
		assertBody(t, w.Body.String(), "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}")
		assertPropagationHeaders(t, req)
	})

	t.Run("ok without token at optional endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", optionalEndpointCfg.Endpoint, new(bytes.Buffer))

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assertStatus(t, w.Code, http.StatusOK)
		assertBody(t, w.Body.String(), "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}")
	})

	t.Run("unauthorized with invalid token at optional endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", optionalEndpointCfg.Endpoint, new(bytes.Buffer))
		req.Header.Set("Authorization", "BEARER "+invalidToken)

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assertStatus(t, w.Code, http.StatusUnauthorized)
		assertBody(t, w.Body.String(), "")
	})

	t.Run("ok with valid token at optional endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", optionalEndpointCfg.Endpoint, new(bytes.Buffer))
		req.Header.Set("Authorization", "BEARER "+token)

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assertStatus(t, w.Code, http.StatusOK)
		assertBody(t, w.Body.String(), "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}")
	})
}

func TestTokenSigner_error(t *testing.T) {
	ts := TokenSigner(
		func(_ *config.EndpointConfig, _ proxy.Proxy) gin.HandlerFunc {
			return func(c *gin.Context) {
				t.Error("the injected handler should not be called")
			}
		},
		logging.NoOp,
	)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", ts(&config.EndpointConfig{ExtraConfig: config.ExtraConfig{jose.SignerNamespace: config.ExtraConfig{}}}, proxy.NoopProxy))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", w.Code)
	}
}

func TestTokenSignatureValidator_error(t *testing.T) {
	ts := TokenSignatureValidator(
		func(_ *config.EndpointConfig, _ proxy.Proxy) gin.HandlerFunc {
			return func(c *gin.Context) {
				t.Error("the injected handler should not be called")
			}
		},
		logging.NoOp,
		nil,
	)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", ts(&config.EndpointConfig{ExtraConfig: config.ExtraConfig{jose.ValidatorNamespace: config.ExtraConfig{}}}, proxy.NoopProxy))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", w.Code)
	}
}

func jwkEndpoint(name string) http.HandlerFunc {
	data, err := os.ReadFile("../fixtures/" + name + ".json")
	return func(rw http.ResponseWriter, _ *http.Request) {
		if err != nil {
			rw.WriteHeader(500)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(data)
	}
}

func assertStatus(t testing.TB, got, want int) {
	t.Helper()

	if got != want {
		t.Errorf("unexpected status code: %d", got)
	}
}

func assertBody(t testing.TB, got, want string) {
	t.Helper()

	if got != want {
		t.Errorf("unexpected body: %s", got)
	}
}

func assertPropagationHeaders(t testing.TB, req *http.Request) {
	if req.Header.Get("x-krakend-jti") == "" {
		t.Error("JWT claim not propagated to header: jti")
	} else if req.Header.Get("x-krakend-jti") != "mnb23vcsrt756yuiomnbvcx98ertyuiop" {
		t.Errorf("wrong JWT claim propagated for 'jti': %v", req.Header.Get("x-krakend-jti"))
	}

	// Check that existing header values are overwritten
	if req.Header.Get("x-krakend-replace") == "abc" {
		t.Error("JWT claim not propagated to x-krakend-replace header: sub")
	} else if req.Header.Get("x-krakend-replace") != "1234567890qwertyuio" {
		t.Errorf("wrong JWT claim propagated for 'sub': %v", req.Header.Get("x-krakend-replace"))
	}

	if req.Header.Get("x-krakend-sub") == "" {
		t.Error("JWT claim not propagated to header: sub")
	} else if req.Header.Get("x-krakend-sub") != "1234567890qwertyuio" {
		t.Errorf("wrong JWT claim propagated for 'sub': %v", req.Header.Get("x-krakend-sub"))
	}

	if req.Header.Get("x-krakend-ne") != "" {
		t.Error("JWT claim propagated, although it shouldn't: nonexistent")
	}
}
