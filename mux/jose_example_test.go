package mux

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	krakendjose "github.com/krakendio/krakend-jose/v2"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	muxlura "github.com/luraproject/lura/v2/router/mux"
)

func Example_RS256() {
	privateServer := httptest.NewServer(jwkEndpoint("private"))
	defer privateServer.Close()
	publicServer := httptest.NewServer(jwkEndpoint("public"))
	defer publicServer.Close()

	runValidationCycle(
		newSignerEndpointCfg("RS256", "2011-04-29", privateServer.URL),
		newVerifierEndpointCfg("RS256", publicServer.URL, []string{"role_a"}, false),
	)

	// output:
	// token request
	// 201
	// {"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.NrLwxZK8UhS6CV2ijdJLUfAinpjBn5_uliZCdzQ7v-Dc8lcv1AQA9cYsG63RseKWH9u6-TqPKMZQ56WfhqL028BLDdQCiaeuBoLzYU1tQLakA1V0YmouuEVixWLzueVaQhyGx-iKuiuFhzHWZSqFqSehiyzI9fb5O6Gcc2L6rMEoxQMaJomVS93h-t013MNq3ADLWTXRaO-negydqax_WmzlVWp_RDroR0s5J2L2klgmBXVwh6SYy5vg7RrnuN3S8g4oSicJIi9NgnG-dDikuaOg2DeFUt-mYq_j_PbNXf9TUl5hl4kEy7E0JauJ17d1BUuTl3ChY4BOmhQYRN0dYg","exp":1735689600,"refresh_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uMTI4NzZidmN4OThlcnR5dWlvcCIsInN1YiI6IjEyMzQ1Njc4OTBxd2VydHl1aW8ifQ.v5dzeXlcYGOCwlhJ05tQ7JXgNw_KO49YvAtURxUOlWqF-OMExzjbevNPSZ2tdWrf8FO5VByoLW6b4cD_6-4PS5XAvTcip2GHOLsvfBokCaxRcMc-tSF-wfPQ4Z2B2GM3_0ErmXC5bSTuBeGaYQ76dONKFUDn7t2lxuABD9oEsLfQYJDnzhCkOzBo8Gg_AY1Vyx-MEYIcatqHI52QGi2_6EBbpJ2ienOaoeGgMfrOMWKFAmBABLkxjnNCzEjAR2lT04NWdB4NnXNa3-m8WedF2TZzmcWzp3mtI9uJhMjpnu8rNi1Uy8LAm6qCjVZABtgfLs-YZekQ2JXx_b0Zojg7og"}
	// map[Content-Type:[application/json]]
	// unauthorized request
	// 401
	// authorized request
	// 200
	// {}
	// application/json
	// dummy request
	// 200
	// {}
	// application/json
}

func Example_HS256() {
	server := httptest.NewServer(jwkEndpoint("symmetric"))
	defer server.Close()

	runValidationCycle(
		newSignerEndpointCfg("HS256", "sim2", server.URL),
		newVerifierEndpointCfg("HS256", server.URL, []string{"role_a"}, false),
	)

	// output:
	// token request
	// 201
	// {"access_token":"eyJhbGciOiJIUzI1NiIsImtpZCI6InNpbTIifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.vTdN1Nm6Eeb3oJWC5yOpmvwTrwuXFYkqy2131u3G0Hk","exp":1735689600,"refresh_token":"eyJhbGciOiJIUzI1NiIsImtpZCI6InNpbTIifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uMTI4NzZidmN4OThlcnR5dWlvcCIsInN1YiI6IjEyMzQ1Njc4OTBxd2VydHl1aW8ifQ.F7KWdUacMQX9g2SGk-UMAU0kfC4xUFsuB-QTFdg9P-M"}
	// map[Content-Type:[application/json]]
	// unauthorized request
	// 401
	// authorized request
	// 200
	// {}
	// application/json
	// dummy request
	// 200
	// {}
	// application/json
}

func Example_HS256_cookie() {
	server := httptest.NewServer(jwkEndpoint("symmetric"))
	defer server.Close()

	sCfg := newSignerEndpointCfg("HS256", "sim2", server.URL)
	_, signer, _ := krakendjose.NewSigner(sCfg, nil)
	verifierCfg := newVerifierEndpointCfg("HS256", server.URL, []string{"role_a"}, false)

	externalTokenIssuer := func(rw http.ResponseWriter, req *http.Request) {
		resp, _ := tokenIssuer(context.Background(), new(proxy.Request))
		data, ok := resp.Data["access_token"]
		if !ok {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		token, _ := signer(data)
		cookie := &http.Cookie{
			Name:    "access_token",
			Value:   token,
			Expires: time.Now().Add(time.Hour),
		}
		http.SetCookie(rw, cookie)
	}

	loginRequest, _ := http.NewRequest("GET", "/", new(bytes.Buffer))
	w := httptest.NewRecorder()
	externalTokenIssuer(w, loginRequest)

	buf := new(bytes.Buffer)
	logger, _ := logging.NewLogger("DEBUG", os.Stderr, "")
	hf := HandlerFactory(muxlura.EndpointHandler, dummyParamsExtractor, logger, nil)

	engine := http.ServeMux{}

	engine.Handle(verifierCfg.Endpoint, hf(verifierCfg, proxy.NoopProxy))

	request, _ := http.NewRequest("GET", verifierCfg.Endpoint, new(bytes.Buffer))
	if len(w.Result().Cookies()) == 0 {
		fmt.Println("unexpected number of cookies")
		return
	}
	request.AddCookie(w.Result().Cookies()[0])

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, request)

	fmt.Println(w.Result().StatusCode)
	fmt.Println(w.Body.String())
	fmt.Println(w.Result().Header.Get("Content-Type"))

	fmt.Println(buf.String())

	// output:
	// 200
	// {}
	// application/json
}

func runValidationCycle(signerEndpointCfg, validatorEndpointCfg *config.EndpointConfig) {
	buf := new(bytes.Buffer)
	logger, _ := logging.NewLogger("DEBUG", os.Stderr, "")
	hf := HandlerFactory(muxlura.EndpointHandler, dummyParamsExtractor, logger, nil)

	engine := http.ServeMux{}

	engine.Handle(validatorEndpointCfg.Endpoint, hf(validatorEndpointCfg, proxy.NoopProxy))
	engine.Handle(signerEndpointCfg.Endpoint, hf(signerEndpointCfg, tokenIssuer))
	engine.Handle("/", hf(&config.EndpointConfig{
		Timeout:  time.Second,
		Endpoint: "/private",
		Method:   "GET",
		Backend: []*config.Backend{
			{
				URLPattern: "/",
				Host:       []string{"http://example.com/"},
				Timeout:    time.Second,
			},
		},
	}, proxy.NoopProxy))

	fmt.Println("token request")
	req := httptest.NewRequest("POST", signerEndpointCfg.Endpoint, new(bytes.Buffer))

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	fmt.Println(w.Result().StatusCode)
	fmt.Println(w.Body.String())
	fmt.Println(w.Result().Header)

	responseData := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Expiration   int    `json:"exp"`
	}{}
	json.Unmarshal(w.Body.Bytes(), &responseData)

	fmt.Println("unauthorized request")
	req = httptest.NewRequest("GET", validatorEndpointCfg.Endpoint, new(bytes.Buffer))
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	fmt.Println(w.Result().StatusCode)

	fmt.Println("authorized request")
	req = httptest.NewRequest("GET", validatorEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+responseData.AccessToken)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	fmt.Println(w.Result().StatusCode)
	fmt.Println(w.Body.String())
	fmt.Println(w.Result().Header.Get("Content-Type"))

	fmt.Println("dummy request")
	req = httptest.NewRequest("GET", "/", new(bytes.Buffer))
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	fmt.Println(w.Result().StatusCode)
	fmt.Println(w.Body.String())
	fmt.Println(w.Result().Header.Get("Content-Type"))

	fmt.Println(buf.String())
}

func tokenIssuer(_ context.Context, _ *proxy.Request) (*proxy.Response, error) {
	return &proxy.Response{
		Data: map[string]interface{}{
			"access_token": map[string]interface{}{
				"aud":   "http://api.example.com",
				"iss":   "http://example.com",
				"sub":   "1234567890qwertyuio",
				"jti":   "mnb23vcsrt756yuiomnbvcx98ertyuiop",
				"roles": []string{"role_a", "role_b"},
				"exp":   1735689600,
			},
			"refresh_token": map[string]interface{}{
				"aud": "http://api.example.com",
				"iss": "http://example.com",
				"sub": "1234567890qwertyuio",
				"jti": "mnb23vcsrt756yuiomn12876bvcx98ertyuiop",
				"exp": 1735689600,
			},
			"exp": 1735689600,
		},
		Metadata: proxy.Metadata{
			StatusCode: 201,
		},
		IsComplete: true,
	}, nil
}

func newSignerEndpointCfg(alg, ID, URL string) *config.EndpointConfig {
	return &config.EndpointConfig{
		Timeout:  time.Second,
		Endpoint: "/token",
		Method:   "POST",
		Backend: []*config.Backend{
			{
				URLPattern: "/token",
				Host:       []string{"http://example.com/"},
				Timeout:    time.Second,
			},
		},
		ExtraConfig: config.ExtraConfig{
			krakendjose.SignerNamespace: map[string]interface{}{
				"alg":                  alg,
				"kid":                  ID,
				"jwk_url":              URL,
				"keys_to_sign":         []string{"access_token", "refresh_token"},
				"disable_jwk_security": true,
				"cache":                true,
			},
		},
	}
}

func newVerifierEndpointCfg(alg, URL string, roles []string, optional bool) *config.EndpointConfig {
	return &config.EndpointConfig{
		Timeout:  time.Second,
		Endpoint: "/private",
		Method:   "GET",
		Backend: []*config.Backend{
			{
				URLPattern: "/",
				Host:       []string{"http://example.com/"},
				Timeout:    time.Second,
			},
		},
		ExtraConfig: config.ExtraConfig{
			krakendjose.ValidatorNamespace: map[string]interface{}{
				"alg":                  alg,
				"jwk_url":              URL,
				"audience":             []string{"http://api.example.com"},
				"issuer":               "http://example.com",
				"roles":                roles,
				"propagate_claims":     [][]string{{"jti", "x-krakend-jti"}, {"sub", "x-krakend-sub"}, {"nonexistent", "x-krakend-ne"}, {"sub", "x-krakend-replace"}},
				"disable_jwk_security": true,
				"cache":                true,
				"optional":             optional,
			},
		},
	}
}
