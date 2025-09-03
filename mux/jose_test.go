package mux

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	jose "github.com/krakend/krakend-jose/v2"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	muxlura "github.com/luraproject/lura/v2/router/mux"
)

func TestTokenSignatureValidator(t *testing.T) { // skipcq: GO-R1005
	server := httptest.NewServer(jwkEndpoint("public"))
	defer server.Close()

	validatorEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_a"}, false)

	forbidenEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_c"}, false)
	forbidenEndpointCfg.Endpoint = "/forbiden"

	registeredEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{}, false)
	registeredEndpointCfg.Endpoint = "/registered"

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
	hf := HandlerFactory(muxlura.EndpointHandler, dummyParamsExtractor, logger, nil)

	engine := muxlura.DefaultEngine()

	engine.Handle(validatorEndpointCfg.Endpoint, "GET", hf(validatorEndpointCfg, dummyProxy))
	engine.Handle(forbidenEndpointCfg.Endpoint, "GET", hf(forbidenEndpointCfg, dummyProxy))
	engine.Handle(registeredEndpointCfg.Endpoint, "GET", hf(registeredEndpointCfg, dummyProxy))
	engine.Handle(propagateHeadersEndpointCfg.Endpoint, "GET", hf(propagateHeadersEndpointCfg, dummyProxy))
	engine.Handle(propagateArrayHeadersEndpointCfg.Endpoint, "GET", hf(propagateArrayHeadersEndpointCfg, dummyProxy))

	req := httptest.NewRequest("GET", forbidenEndpointCfg.Endpoint, new(bytes.Buffer))

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "Token not found\n" {
		t.Errorf("unexpected body: '%s'", body)
	}

	req = httptest.NewRequest("GET", validatorEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != `{"aaaa":{"bar":"b","foo":"a"},"bbbb":true,"cccc":1234567890}` {
		t.Errorf("unexpected body: %s", body)
	}

	if log := buf.String(); !strings.Contains(log, "INFO: JOSE: signer disabled for the endpoint /private") {
		t.Error(log)
	}

	req = httptest.NewRequest("GET", forbidenEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != "\n" {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", registeredEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != `{"aaaa":{"bar":"b","foo":"a"},"bbbb":true,"cccc":1234567890}` {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", propagateHeadersEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)
	// Check header-overwrite: it must be overwritten by a claim in the JWT!
	req.Header.Set("x-krakend-replace", "abc")

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
	if body := w.Body.String(); body != `{"aaaa":{"bar":"b","foo":"a"},"bbbb":true,"cccc":1234567890}` {
		t.Errorf("unexpected body: %s", body)
	}

	req = httptest.NewRequest("GET", propagateArrayHeadersEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)
	// Check header-overwrite: it must be overwritten by a claim in the JWT!
	req.Header.Set("x-krakend-replace", "abc")

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
	if body := w.Body.String(); body != `{"aaaa":{"bar":"b","foo":"a"},"bbbb":true,"cccc":1234567890}` {
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
	hf := HandlerFactory(muxlura.EndpointHandler, dummyParamsExtractor, logger, nil)

	engine := muxlura.DefaultEngine()

	engine.Handle(nonDefaultAuthHeaderEndpointCfg.Endpoint, "GET", hf(nonDefaultAuthHeaderEndpointCfg, dummyProxy))

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

	req = httptest.NewRequest("GET", nonDefaultAuthHeaderEndpointCfg.Endpoint, new(bytes.Buffer))

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", w.Code)
	}
}

func jwkEndpoint(name string) http.HandlerFunc {
	data, err := ioutil.ReadFile("../fixtures/" + name + ".json")
	return func(rw http.ResponseWriter, _ *http.Request) {
		if err != nil {
			rw.WriteHeader(500)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(data)
	}
}

func dummyParamsExtractor(_ *http.Request) map[string]string {
	return map[string]string{}
}
