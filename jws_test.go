package jose

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devopsfaith/krakend/config"
	jose "gopkg.in/square/go-jose.v2"
)

func Test_getSignatureConfig(t *testing.T) {
	server := httptest.NewServer(jwkEndpoint("private"))
	defer server.Close()

	scfg, err := getSignatureConfig(newVerifierEndpointCfg("RS256", server.URL, []string{}))
	if err != nil {
		t.Error(err.Error())
		return
	}

	if scfg.Issuer != "http://example.com" {
		t.Errorf("unexpected issuer: %s", scfg.Issuer)
	}

	if scfg.Audience[0] != "http://api.example.com" {
		t.Errorf("unexpected audience: %v", scfg.Audience)
	}
}

func Test_getSignatureConfig_unsecure(t *testing.T) {
	cfg := &config.EndpointConfig{
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
			ValidatorNamespace: map[string]interface{}{
				"alg":      "RS256",
				"jwk-url":  "http://jwk.example.com",
				"audience": []string{"http://api.example.com"},
				"issuer":   "http://example.com",
				"roles":    []string{},
				"cache":    false,
			},
		},
	}

	_, err := getSignatureConfig(cfg)
	if err != ErrInsecureJWKSource {
		t.Errorf("unexpected error: %v", err)
	}
}

func Test_getSignatureConfig_wrongStruct(t *testing.T) {
	cfg := &config.EndpointConfig{
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
			ValidatorNamespace: true,
		},
	}

	_, err := getSignatureConfig(cfg)
	if err == nil || err.Error() != "json: cannot unmarshal bool into Go value of type jose.signatureConfig" {
		t.Errorf("unexpected error: %v", err)
	}
}

func Test_newSigner(t *testing.T) {
	server := httptest.NewServer(jwkEndpoint("private"))
	defer server.Close()

	_, signer, err := newSigner(newSignerEndpointCfg("RS256", "2011-04-29", server.URL), nil)
	if err != nil {
		t.Error(err.Error())
		return
	}

	msg, err := signer(map[string]interface{}{
		"aud": "http://api.example.com",
		"iss": "http://example.com",
		"sub": "1234567890qwertyuio",
		"jti": "mnb23vcsrt756yuiomnbvcx98ertyuiop",
	})
	if err != nil {
		t.Error(err.Error())
		return
	}

	expected := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cDovL2V4YW1wbGUuY29tIiwianRpIjoibW5iMjN2Y3NydDc1Nnl1aW9tbmJ2Y3g5OGVydHl1aW9wIiwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.TWdsBQPqfDV1IFe1iD0KFu-E_wqeFXgNJXIoESl9smg2W_Snh2GwwktwlvHCSAGvUdkKU6Js6LQ594e6HZ3eAdj3mfCdCxerhuodb6GS-rZ2OrMv44VaC_YnzoOjCWUrU3ivzhYjEFBxgDgWc0G9qFdQVaZPOLPohd_mXpeM5jAS-vFzudOlJz8rtK9KfVDPiAWnGxih5fa3MF1b19vnnsfyN1Y8hTeen3j24thQbuh61vkqu8TLoG2NrETyC9zqCuL3IQnPld3IBolYJhqEcka95cCNZ1dQnqsgrP4q325JmRxXsn0GJM3VtFpKbfJCcQgdpixCohQ-_xHmTUpXng"
	if msg != expected {
		t.Errorf("unexpected signed payload: %s", msg)
	}
}

func Test_newSigner_unsecure(t *testing.T) {
	cfg := &config.EndpointConfig{
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
			SignerNamespace: map[string]interface{}{
				"alg":          "RS256",
				"kid":          "2011-04-29",
				"jwk-url":      "http://jwk.example.com",
				"keys-to-sign": []string{"access_token", "refresh_token"},
			},
		},
	}
	_, _, err := newSigner(cfg, nil)
	if err != ErrInsecureJWKSource {
		t.Errorf("unexpected error: %v", err)
	}
}

func Test_newSigner_wrongStruct(t *testing.T) {
	cfg := &config.EndpointConfig{
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
			SignerNamespace: true,
		},
	}
	_, _, err := newSigner(cfg, nil)
	if err == nil || err.Error() != "json: cannot unmarshal bool into Go value of type jose.signerConfig" {
		t.Errorf("unexpected error: %v", err)
	}
}

func Test_newSigner_unknownKey(t *testing.T) {
	server := httptest.NewServer(jwkEndpoint("private"))
	defer server.Close()

	_, _, err := newSigner(newSignerEndpointCfg("RS256", "unknown key", server.URL), nil)
	if err == nil || err.Error() != "no Keys has been found" {
		t.Errorf("unexpected error: %v", err)
	}
}

func Test_RSAPrivateSigner(t *testing.T) {
	testPrivateSigner(
		t,
		"private",
		"2011-04-29",
		`{"payload":"eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cDovL2V4YW1wbGUuY29tIiwianRpIjoibW5iMjN2Y3NydDc1Nnl1aW9tbmJ2Y3g5OGVydHl1aW9wIiwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9","protected":"eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9","signature":"QxDpRQLmMq7umclf8BeT8W_Cwv9NsqBHwhTrepaNZx3ciKrOwVE433BfpA5Zbh_Jj0J2M1ojQqmE7uWC4kB3YFYhbLBclpqko3HHj6D4uvfklCXrLEngPoDhC2oGxID8fJcle2eVoGl3VzkVZBRoXSbT71Z3ZFy6sjsFReiBTMIpqpmSw8d0DRriu6emduaxmyn4MoFnKUD-q7oYcXApqvS4sw0UU2C7f1eIwMx0qLVa2j7lQBB0Lb0w1EejAQlfCbm5mqYHGcFzUDWBpKl7Zwk68bKglfvHEDh4W9bHCd9A3OVUoS6olJxSJiAUBk_FSiNHd-pwifIxu3SqkrEMUQ"}`,
		"eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cDovL2V4YW1wbGUuY29tIiwianRpIjoibW5iMjN2Y3NydDc1Nnl1aW9tbmJ2Y3g5OGVydHl1aW9wIiwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.QxDpRQLmMq7umclf8BeT8W_Cwv9NsqBHwhTrepaNZx3ciKrOwVE433BfpA5Zbh_Jj0J2M1ojQqmE7uWC4kB3YFYhbLBclpqko3HHj6D4uvfklCXrLEngPoDhC2oGxID8fJcle2eVoGl3VzkVZBRoXSbT71Z3ZFy6sjsFReiBTMIpqpmSw8d0DRriu6emduaxmyn4MoFnKUD-q7oYcXApqvS4sw0UU2C7f1eIwMx0qLVa2j7lQBB0Lb0w1EejAQlfCbm5mqYHGcFzUDWBpKl7Zwk68bKglfvHEDh4W9bHCd9A3OVUoS6olJxSJiAUBk_FSiNHd-pwifIxu3SqkrEMUQ",
	)
}

func Test_HSAPrivateSigner(t *testing.T) {
	testPrivateSigner(
		t,
		"symmetric",
		"sim2",
		`{"payload":"eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cDovL2V4YW1wbGUuY29tIiwianRpIjoibW5iMjN2Y3NydDc1Nnl1aW9tbmJ2Y3g5OGVydHl1aW9wIiwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"2eGKzqRiIJE5TJ4WcgnmopwhUczIdTFuQkp9ZVuFyUk"}`,
		"eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cDovL2V4YW1wbGUuY29tIiwianRpIjoibW5iMjN2Y3NydDc1Nnl1aW9tbmJ2Y3g5OGVydHl1aW9wIiwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.2eGKzqRiIJE5TJ4WcgnmopwhUczIdTFuQkp9ZVuFyUk",
	)
}

func testPrivateSigner(t *testing.T, keyType, keyName, full, compact string) {
	server := httptest.NewServer(jwkEndpoint(keyType))
	defer server.Close()

	sp := secretProvider(secretProviderConfig{URI: server.URL}, nil)
	key, err := sp.GetKey(keyName)
	if err != nil {
		t.Errorf("getting the key: %s", err.Error())
		return
	}

	signingKey := jose.SigningKey{
		Key:       key.Key,
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
	}
	s, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		t.Errorf("building the signer: %s", err.Error())
		return
	}

	payload := map[string]interface{}{
		"aud": "http://api.example.com",
		"iss": "http://example.com",
		"sub": "1234567890qwertyuio",
		"jti": "mnb23vcsrt756yuiomnbvcx98ertyuiop",
	}
	for _, tc := range []struct {
		Name     string
		Signer   Signer
		Expected string
	}{
		{
			Name:     keyType + "-full",
			Signer:   fullSerializeSigner{signer{s}}.Sign,
			Expected: full,
		},
		{
			Name:     keyType + "-compact",
			Signer:   compactSerializeSigner{signer{s}}.Sign,
			Expected: compact,
		},
	} {
		data, err := tc.Signer(payload)
		if err != nil {
			t.Errorf("[%s] signing the payload: %s", tc.Name, err.Error())
			return
		}
		if data != tc.Expected {
			t.Errorf("[%s] unexpected signed payload: %s", tc.Name, data)
		}
	}
}
