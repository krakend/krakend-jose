package gin

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
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

	propagateHeadersEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_a", "role_b"}, false)
	propagateHeadersEndpointCfg.Endpoint = "/propagateheaders"

	propagateArrayHeadersEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_a", "role_b"}, true)
	propagateArrayHeadersEndpointCfg.Endpoint = "/propagatearrayheaders"

	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoyMDUxODgyNzU1LCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.u1fK05FpXctB-VkhhT3xu2WSIkEr1_VM71ald-yeKTesxhxg68TsHFEOBCgoXPuCviOP8QnUKNuVSeyMJh9z3nnrfQIjo9VZ2yicZu6ImYptSQ2DJbR80GDSPp-H7KnjaR9AAY0HZ0M-KUTaHdLABZFr307nkOeaJn_5jMpav7pqa7nrU3sI1CLX5pYVTggG6t7Zoqj2ebzzqdRxQEtdmZkD_NfH-3w3t-H0ylVdeBnPh-RvlspxC_mJzyUIJ0BwPlZpabppHm1ISySa4kwnwxEYnux0oZcb3PSoOZZZA467JySZ69PRlenNPdfGPL6E3uL1nqPHcxhte7ikSG4Q6Q"

	dummyProxy := func(_ context.Context, _ *proxy.Request) (*proxy.Response, error) {
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
	engine.GET(propagateArrayHeadersEndpointCfg.Endpoint, hf(propagateArrayHeadersEndpointCfg, dummyProxy))

	req := httptest.NewRequest("GET", forbidenEndpointCfg.Endpoint, new(bytes.Buffer))

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", validatorEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}" {
		t.Errorf("unexpected body: %s", body)
	}

	if log := buf.String(); !strings.Contains(log, "DEBUG: [ENDPOINT: /propagateheaders][JWTSigner] Signer disabled") {
		t.Error(log)
		t.Fail()
		return
	}

	req = httptest.NewRequest("GET", forbidenEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", registeredEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}" {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", propagateHeadersEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)
	// Check header-overwrite: it must be overwritten by a claim in the JWT!
	req.Header.Set("x-krakend-replace", "abc")
	req.Header.Set("x-krakend-ne", "fake_non_existing")

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

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

	if req.Header.Get("x-krakend-roles") == "" {
		t.Error("JWT claim not propagated to header: roles")
	} else if req.Header.Get("x-krakend-roles") != "role_a,role_b" {
		t.Errorf("wrong JWT claim propagated for 'roles': %v", req.Header.Get("x-krakend-roles"))
	}

	if req.Header.Get("x-krakend-ne") != "" {
		t.Error("JWT claim propagated, although it shouldn't: nonexistent")
	}

	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}" {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", propagateArrayHeadersEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)
	// Check header-overwrite: it must be overwritten by a claim in the JWT!
	req.Header.Set("x-krakend-replace", "abc")
	req.Header.Set("x-krakend-ne", "fake_non_existing")

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

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

	if req.Header.Get("x-krakend-roles") == "" {
		t.Error("JWT claim not propagated to header: roles")
	} else if !reflect.DeepEqual(req.Header.Values("x-krakend-roles"), []string{"role_a", "role_b"}) {
		t.Errorf("wrong JWT claim propagated for 'roles': %v", req.Header.Get("x-krakend-roles"))
	}

	if req.Header.Get("x-krakend-ne") != "" {
		t.Error("JWT claim propagated, although it shouldn't: nonexistent")
	}

	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}" {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestCustomHeaderName(t *testing.T) {
	server := httptest.NewServer(jwkEndpoint("public"))
	defer server.Close()

	nonDefaultAuthHeaderEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{}, false)
	nonDefaultAuthHeaderEndpointCfg.Endpoint = "/custom-header"
	nonDefaultAuthHeaderEndpointCfg.ExtraConfig[jose.ValidatorNamespace].(map[string]interface{})["auth_header_name"] = "X-Custom-Auth"

	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoyMDUxODgyNzU1LCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.u1fK05FpXctB-VkhhT3xu2WSIkEr1_VM71ald-yeKTesxhxg68TsHFEOBCgoXPuCviOP8QnUKNuVSeyMJh9z3nnrfQIjo9VZ2yicZu6ImYptSQ2DJbR80GDSPp-H7KnjaR9AAY0HZ0M-KUTaHdLABZFr307nkOeaJn_5jMpav7pqa7nrU3sI1CLX5pYVTggG6t7Zoqj2ebzzqdRxQEtdmZkD_NfH-3w3t-H0ylVdeBnPh-RvlspxC_mJzyUIJ0BwPlZpabppHm1ISySa4kwnwxEYnux0oZcb3PSoOZZZA467JySZ69PRlenNPdfGPL6E3uL1nqPHcxhte7ikSG4Q6Q"

	dummyProxy := func(_ context.Context, _ *proxy.Request) (*proxy.Response, error) {
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

	engine.GET(nonDefaultAuthHeaderEndpointCfg.Endpoint, hf(nonDefaultAuthHeaderEndpointCfg, dummyProxy))

	req := httptest.NewRequest("GET", nonDefaultAuthHeaderEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("X-Custom-Auth", "BEARER "+token)

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "{\"aaaa\":{\"bar\":\"b\",\"foo\":\"a\"},\"bbbb\":true,\"cccc\":1234567890}" {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", nonDefaultAuthHeaderEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", nonDefaultAuthHeaderEndpointCfg.Endpoint, new(bytes.Buffer))

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestTokenSigner_error(t *testing.T) {
	ts := TokenSigner(
		func(_ *config.EndpointConfig, _ proxy.Proxy) gin.HandlerFunc {
			return func(_ *gin.Context) {
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
			return func(_ *gin.Context) {
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
