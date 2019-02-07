package jose

import (
	"net/http"
	"testing"

	"gopkg.in/square/go-jose.v2/jwt"
)

func nopExtractor(_ string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	return func(_ *http.Request) (*jwt.JSONWebToken, error) { return nil, nil }
}

func Test_NewValidator_unkownAlg(t *testing.T) {
	_, err := NewValidator(&SignatureConfig{
		Alg: "random",
	}, nopExtractor)
	if err == nil || err.Error() != "JOSE: unknown algorithm random" {
		t.Errorf("unexpected error: %v", err)
	}
}
