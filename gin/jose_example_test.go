package gin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	krakendjose "github.com/krakendio/krakend-jose/v2"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	ginlura "github.com/luraproject/lura/v2/router/gin"
)

func Example_RS256() {
	privateServer := httptest.NewServer(jwkEndpoint("private"))
	defer privateServer.Close()
	publicServer := httptest.NewServer(jwkEndpoint("public"))
	defer publicServer.Close()

	verifierCfg := newVerifierEndpointCfg("RS256", publicServer.URL, []string{"role_a"})
	verifierCfg.ExtraConfig[krakendjose.ValidatorNamespace].(map[string]interface{})["operation_debug"] = true

	runValidationCycle(
		newSignerEndpointCfg("RS256", "2011-04-29", privateServer.URL),
		verifierCfg,
	)

	// output:
	// token request
	// 201
	// {"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.SFy8lloEcTMGb7twtxOPMZE1zPccGDVylsrjyvMj_DTZbKacq5WZsyvtG_InjKvRTn_xSC3JQkeCRFTCXFyQEJMyjhWgCAZ4QHXXDHyXSHnvIh1_hDQW5BrIDslWsftg3KYPFAXB2i78p1kioqQSa9NmikgRChjx-InqUM599yRaOB4Z_Xjg7DCIkgIO01JfsXU6IxEskGVuXcIV1EY44CT84I5w-Mr0fwGOyqKMmUodji2raI_SIYRb2EBTtoDBlabB19Dulv8puq4LacjQaRIuWQbA40hGOiepchJMApBaiX6QdYXTnc0f6RFE5GiX1-oYWgOQNi3OA2gJ61PLLA","exp":1735689600,"refresh_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uMTI4NzZidmN4OThlcnR5dWlvcCIsInN1YiI6IjEyMzQ1Njc4OTBxd2VydHl1aW8ifQ.d-2M5oC2H29qZQdEd5LE221fQZwl2L1ibMF_EeG5uOyBVlay705_aU6XRnZ4Y7Ns77C7RPz215is7aDOVydrq48cBbztoezxUvc2r5aT84quvT_QImyiDpWYrErthr9a_UpAEthIwh8AfcizW0fXrhEYifaZp2hxG24x5bQqWssFZo4UCzMzfp90NJuIQ970bl_Q0mJbOv4ao8X14MMb6j4MuqRGKPAt8rQDpcfSkbxgKofC4GrrcaaCa7Y-wrrMjurRJiYKe_y2OKSyKx5T8PsbXxrWzmRhL1nBF3Kq1wHFcz3M0yemyN2q9Af9BY-kyh5cnv_OgcSlb5RmW0O2Xg"}
	// map[Content-Type:[application/json; charset=utf-8]]
	// unauthorized request
	// 401
	// authorized request
	// 200
	// {}
	// application/json; charset=utf-8
	// dummy request
	// 200
	// {}
	// application/json; charset=utf-8
	// refresh token request
	// 201
	// {"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.SFy8lloEcTMGb7twtxOPMZE1zPccGDVylsrjyvMj_DTZbKacq5WZsyvtG_InjKvRTn_xSC3JQkeCRFTCXFyQEJMyjhWgCAZ4QHXXDHyXSHnvIh1_hDQW5BrIDslWsftg3KYPFAXB2i78p1kioqQSa9NmikgRChjx-InqUM599yRaOB4Z_Xjg7DCIkgIO01JfsXU6IxEskGVuXcIV1EY44CT84I5w-Mr0fwGOyqKMmUodji2raI_SIYRb2EBTtoDBlabB19Dulv8puq4LacjQaRIuWQbA40hGOiepchJMApBaiX6QdYXTnc0f6RFE5GiX1-oYWgOQNi3OA2gJ61PLLA","exp":1735689600,"refresh_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uMTI4NzZidmN4OThlcnR5dWlvcCIsInN1YiI6IjEyMzQ1Njc4OTBxd2VydHl1aW8ifQ.d-2M5oC2H29qZQdEd5LE221fQZwl2L1ibMF_EeG5uOyBVlay705_aU6XRnZ4Y7Ns77C7RPz215is7aDOVydrq48cBbztoezxUvc2r5aT84quvT_QImyiDpWYrErthr9a_UpAEthIwh8AfcizW0fXrhEYifaZp2hxG24x5bQqWssFZo4UCzMzfp90NJuIQ970bl_Q0mJbOv4ao8X14MMb6j4MuqRGKPAt8rQDpcfSkbxgKofC4GrrcaaCa7Y-wrrMjurRJiYKe_y2OKSyKx5T8PsbXxrWzmRhL1nBF3Kq1wHFcz3M0yemyN2q9Af9BY-kyh5cnv_OgcSlb5RmW0O2Xg"}
	// application/json; charset=utf-8
	//  DEBUG: [ENDPOINT: /private][JWTSigner] Signer disabled
	//  DEBUG: [ENDPOINT: /private][JWTValidator] Roles will be matched against the key: 'roles'
	//  DEBUG: [ENDPOINT: /private][JWTValidator] No scope validation required
	//  DEBUG: [ENDPOINT: /private][JWTValidator] Validator enabled for this endpoint. Operation debug is enabled
	//  DEBUG: [ENDPOINT: /token][JWTSigner] Signer enabled
	//  INFO: [ENDPOINT: /token][JWTValidator] Validator disabled for this endpoint
	//  DEBUG: [ENDPOINT: /refresh_token][JWTSigner] Signer enabled
	//  DEBUG: [ENDPOINT: /refresh_token][JWTValidator] Roles will be matched against the key: 'roles'
	//  DEBUG: [ENDPOINT: /refresh_token][JWTValidator] No scope validation required
	//  DEBUG: [ENDPOINT: /refresh_token][JWTValidator] Validator enabled for this endpoint. Operation debug is enabled
	//  DEBUG: [ENDPOINT: /private][JWTSigner] Signer disabled
	//  INFO: [ENDPOINT: /private][JWTValidator] Validator disabled for this endpoint
	//  ERROR: [ENDPOINT: /private][JWTValidator] Unable to validate the token: Token not found
}

func Example_HS256() {
	server := httptest.NewServer(jwkEndpoint("symmetric"))
	defer server.Close()

	runValidationCycle(
		newSignerEndpointCfg("HS256", "sim2", server.URL),
		newVerifierEndpointCfg("HS256", server.URL, []string{"role_a"}),
	)

	// output:
	// token request
	// 201
	// {"access_token":"eyJhbGciOiJIUzI1NiIsImtpZCI6InNpbTIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.89zdRo4LCHpT93JX3_Yn2LoAOUvEAiFj6X7vnCgOd5Q","exp":1735689600,"refresh_token":"eyJhbGciOiJIUzI1NiIsImtpZCI6InNpbTIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uMTI4NzZidmN4OThlcnR5dWlvcCIsInN1YiI6IjEyMzQ1Njc4OTBxd2VydHl1aW8ifQ.lJuO1xyI8QOTWNGxBQe2hH90Jdp5y0DEbPd44I728dA"}
	// map[Content-Type:[application/json; charset=utf-8]]
	// unauthorized request
	// 401
	// authorized request
	// 200
	// {}
	// application/json; charset=utf-8
	// dummy request
	// 200
	// {}
	// application/json; charset=utf-8
	// refresh token request
	// 201
	// {"access_token":"eyJhbGciOiJIUzI1NiIsImtpZCI6InNpbTIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.89zdRo4LCHpT93JX3_Yn2LoAOUvEAiFj6X7vnCgOd5Q","exp":1735689600,"refresh_token":"eyJhbGciOiJIUzI1NiIsImtpZCI6InNpbTIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uMTI4NzZidmN4OThlcnR5dWlvcCIsInN1YiI6IjEyMzQ1Njc4OTBxd2VydHl1aW8ifQ.lJuO1xyI8QOTWNGxBQe2hH90Jdp5y0DEbPd44I728dA"}
	// application/json; charset=utf-8
	//  DEBUG: [ENDPOINT: /private][JWTSigner] Signer disabled
	//  DEBUG: [ENDPOINT: /private][JWTValidator] Roles will be matched against the key: 'roles'
	//  DEBUG: [ENDPOINT: /private][JWTValidator] No scope validation required
	//  DEBUG: [ENDPOINT: /private][JWTValidator] Validator enabled for this endpoint
	//  DEBUG: [ENDPOINT: /token][JWTSigner] Signer enabled
	//  INFO: [ENDPOINT: /token][JWTValidator] Validator disabled for this endpoint
	//  DEBUG: [ENDPOINT: /refresh_token][JWTSigner] Signer enabled
	//  DEBUG: [ENDPOINT: /refresh_token][JWTValidator] Roles will be matched against the key: 'roles'
	//  DEBUG: [ENDPOINT: /refresh_token][JWTValidator] No scope validation required
	//  DEBUG: [ENDPOINT: /refresh_token][JWTValidator] Validator enabled for this endpoint
	//  DEBUG: [ENDPOINT: /private][JWTSigner] Signer disabled
	//  INFO: [ENDPOINT: /private][JWTValidator] Validator disabled for this endpoint
}

func Example_HS256_cookie() {
	server := httptest.NewServer(jwkEndpoint("symmetric"))
	defer server.Close()

	sCfg := newSignerEndpointCfg("HS256", "sim2", server.URL)
	_, signer, _ := krakendjose.NewSigner(sCfg, nil)
	verifierCfg := newVerifierEndpointCfg("HS256", server.URL, []string{"role_a"})

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
	logger, _ := logging.NewLogger("DEBUG", buf, "")
	hf := HandlerFactory(ginlura.EndpointHandler, logger, nil)

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	engine.GET(verifierCfg.Endpoint, hf(verifierCfg, proxy.NoopProxy))

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

	printLog(buf)

	// output:
	// 200
	// {}
	// application/json; charset=utf-8
	//  DEBUG: [ENDPOINT: /private][JWTSigner] Signer disabled
	//  DEBUG: [ENDPOINT: /private][JWTValidator] Roles will be matched against the key: 'roles'
	//  DEBUG: [ENDPOINT: /private][JWTValidator] No scope validation required
	//  DEBUG: [ENDPOINT: /private][JWTValidator] Validator enabled for this endpoint
}

func runValidationCycle(signerEndpointCfg, validatorEndpointCfg *config.EndpointConfig) {
	buf := new(bytes.Buffer)
	logger, _ := logging.NewLogger("DEBUG", buf, "")
	hf := HandlerFactory(ginlura.EndpointHandler, logger, nil)

	mixedCfg := &config.EndpointConfig{
		Timeout:  time.Second,
		Endpoint: "/refresh_token",
		Method:   signerEndpointCfg.Method,
		Backend:  signerEndpointCfg.Backend,
		ExtraConfig: config.ExtraConfig{
			krakendjose.SignerNamespace:    signerEndpointCfg.ExtraConfig[krakendjose.SignerNamespace],
			krakendjose.ValidatorNamespace: validatorEndpointCfg.ExtraConfig[krakendjose.ValidatorNamespace],
		},
	}

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	engine.GET(validatorEndpointCfg.Endpoint, hf(validatorEndpointCfg, proxy.NoopProxy))
	engine.POST(signerEndpointCfg.Endpoint, hf(signerEndpointCfg, tokenIssuer))
	engine.POST(mixedCfg.Endpoint, hf(mixedCfg, tokenIssuer))
	engine.GET("/", hf(&config.EndpointConfig{
		Timeout:  time.Second,
		Endpoint: "/private",
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

	fmt.Println(w.Code)

	fmt.Println("authorized request")
	req = httptest.NewRequest("GET", validatorEndpointCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+responseData.AccessToken)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	fmt.Println(w.Code)
	fmt.Println(w.Body.String())
	fmt.Println(w.Result().Header.Get("Content-Type"))

	fmt.Println("dummy request")
	req = httptest.NewRequest("GET", "/", new(bytes.Buffer))
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	fmt.Println(w.Code)
	fmt.Println(w.Body.String())
	fmt.Println(w.Result().Header.Get("Content-Type"))

	fmt.Println("refresh token request")
	req = httptest.NewRequest("POST", mixedCfg.Endpoint, new(bytes.Buffer))
	req.Header.Set("Authorization", "BEARER "+responseData.AccessToken)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	fmt.Println(w.Code)
	fmt.Println(w.Body.String())
	fmt.Println(w.Result().Header.Get("Content-Type"))

	printLog(buf)
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

func newVerifierEndpointCfg(alg, URL string, roles []string) *config.EndpointConfig {
	return &config.EndpointConfig{
		Timeout:  time.Second,
		Endpoint: "/private",
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
			},
		},
	}
}

func printLog(buf *bytes.Buffer) {
	for _, l := range strings.Split(buf.String(), "\n") {
		if len(l) <= 20 {
			fmt.Println(l)
			continue
		}
		fmt.Println(l[20:])
	}
}
