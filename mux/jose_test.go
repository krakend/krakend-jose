package mux

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	krakendjose "github.com/devopsfaith/krakend-jose"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	muxkrakend "github.com/devopsfaith/krakend/router/mux"
)

func TestTokenSignatureValidator(t *testing.T) {
	server := httptest.NewServer(jwkEndpoint("public"))
	defer server.Close()

	validatorEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_a"})

	forbidenEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_c"})
	forbidenEndpointCfg.Endpoint = "/forbiden"

	registeredEndpointCfg := newVerifierEndpointCfg("RS256", server.URL, []string{})
	registeredEndpointCfg.Endpoint = "/registered"

	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.NrLwxZK8UhS6CV2ijdJLUfAinpjBn5_uliZCdzQ7v-Dc8lcv1AQA9cYsG63RseKWH9u6-TqPKMZQ56WfhqL028BLDdQCiaeuBoLzYU1tQLakA1V0YmouuEVixWLzueVaQhyGx-iKuiuFhzHWZSqFqSehiyzI9fb5O6Gcc2L6rMEoxQMaJomVS93h-t013MNq3ADLWTXRaO-negydqax_WmzlVWp_RDroR0s5J2L2klgmBXVwh6SYy5vg7RrnuN3S8g4oSicJIi9NgnG-dDikuaOg2DeFUt-mYq_j_PbNXf9TUl5hl4kEy7E0JauJ17d1BUuTl3ChY4BOmhQYRN0dYg"

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
	hf := HandlerFactory(muxkrakend.EndpointHandler, dummyParamsExtractor, logger, nil)

	engine := muxkrakend.DefaultEngine()

	engine.Handle(validatorEndpointCfg.Endpoint, hf(validatorEndpointCfg, dummyProxy))
	engine.Handle(forbidenEndpointCfg.Endpoint, hf(forbidenEndpointCfg, dummyProxy))
	engine.Handle(registeredEndpointCfg.Endpoint, hf(registeredEndpointCfg, dummyProxy))

	req := httptest.NewRequest("GET", validatorEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("unexpected status code: %d", w.Code)
	}
	if body := w.Body.String(); body != `{"aaaa":{"bar":"b","foo":"a"},"bbbb":true,"cccc":1234567890}` {
		t.Errorf("unexpected body: %s", body)
	}

	if log := buf.String(); !strings.Contains(log, "ERROR: JOSE: no signer config /private") {
		t.Error(log)
	}

	req = httptest.NewRequest("GET", forbidenEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+token)

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
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
}

func Test_newValidator_unkownAlg(t *testing.T) {
	_, err := newValidator(&krakendjose.SignatureConfig{
		Alg: "random",
	})
	if err == nil || err.Error() != "JOSE: unknown algorithm random" {
		t.Errorf("unexpected error: %v", err)
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