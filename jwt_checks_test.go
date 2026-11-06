package jose

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	auth0 "github.com/krakend/go-auth0/v2"
	"github.com/luraproject/lura/v3/logging"
)

// RS256 token signed with the key in fixtures/private.json: kid 2011-04-29,
// iss http://example.com, aud http://api.example.com, roles [role_a, role_b]
const checksTestToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoyMDUxODgyNzU1LCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.u1fK05FpXctB-VkhhT3xu2WSIkEr1_VM71ald-yeKTesxhxg68TsHFEOBCgoXPuCviOP8QnUKNuVSeyMJh9z3nnrfQIjo9VZ2yicZu6ImYptSQ2DJbR80GDSPp-H7KnjaR9AAY0HZ0M-KUTaHdLABZFr307nkOeaJn_5jMpav7pqa7nrU3sI1CLX5pYVTggG6t7Zoqj2ebzzqdRxQEtdmZkD_NfH-3w3t-H0ylVdeBnPh-RvlspxC_mJzyUIJ0BwPlZpabppHm1ISySa4kwnwxEYnux0oZcb3PSoOZZZA467JySZ69PRlenNPdfGPL6E3uL1nqPHcxhte7ikSG4Q6Q"

func newTestJWTChecks(t *testing.T, scfg *SignatureConfig, buf *bytes.Buffer) *JWTChecks {
	t.Helper()
	if scfg.Alg == "" {
		scfg.Alg = "RS256"
	}
	scfg.LocalPath = "./fixtures/public.json"
	scfg.DisableJWKSecurity = true
	if scfg.Issuer == "" {
		scfg.Issuer = "http://example.com"
	}
	if scfg.Audience == nil {
		scfg.Audience = []string{"http://api.example.com"}
	}
	logger, _ := logging.NewLogger("DEBUG", buf, "")
	j, err := NewJWTChecks(scfg, logger, "[test]", nil)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestNewJWTChecks_unknownAlgReturnsError(t *testing.T) {
	logger, _ := logging.NewLogger("CRITICAL", new(bytes.Buffer), "")
	if _, err := NewJWTChecks(&SignatureConfig{Alg: "nope"}, logger, "", nil); err == nil {
		t.Error("expected an error")
	}
}

func TestJWTChecks_Check(t *testing.T) {
	buf := new(bytes.Buffer)
	j := newTestJWTChecks(t, &SignatureConfig{Roles: []string{"role_a"}, RolesKey: "roles"}, buf)
	claims, err := j.Check("Bearer " + checksTestToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "1234567890qwertyuio" {
		t.Errorf("unexpected claims: %v", claims)
	}
}

type countingSecrets struct {
	auth0.TokenSecretProvider
	calls int
}

func (c *countingSecrets) SecretFromToken(token *jwt.JSONWebToken) (interface{}, error) {
	c.calls++
	return c.TokenSecretProvider.SecretFromToken(token)
}

func TestJWTChecks_Check_singleKeyLookup(t *testing.T) {
	j := newTestJWTChecks(t, &SignatureConfig{}, new(bytes.Buffer))
	c := &countingSecrets{TokenSecretProvider: j.secrets}
	j.secrets = c
	if _, err := j.Check(checksTestToken); err != nil {
		t.Fatal(err)
	}
	if c.calls != 1 {
		t.Errorf("expected a single key lookup, got %d", c.calls)
	}
}

func TestJWTChecks_Check_errors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scfg  SignatureConfig
		token string
		is    error
	}{
		{"empty token", SignatureConfig{}, "", auth0.ErrTokenNotFound},
		{"bearer prefix only", SignatureConfig{}, "Bearer ", auth0.ErrTokenNotFound},
		{"lowercase bearer prefix only", SignatureConfig{}, "bearer ", auth0.ErrTokenNotFound},
		{"wrong issuer", SignatureConfig{Issuer: "http://other.example.com"}, checksTestToken, jwt.ErrInvalidIssuer},
		{"wrong audience", SignatureConfig{Audience: []string{"other"}}, checksTestToken, jwt.ErrInvalidAudience},
		{"missing roles", SignatureConfig{Roles: []string{"role_c"}, RolesKey: "roles"}, checksTestToken, ErrRequiredRoles},
		{"missing scopes", SignatureConfig{Scopes: []string{"read"}, ScopesKey: "scope"}, checksTestToken, ErrRequiredScopes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			scfg := tc.scfg
			scfg.OperationDebug = true
			j := newTestJWTChecks(t, &scfg, buf)
			_, err := j.Check(tc.token)
			if !errors.Is(err, tc.is) {
				t.Fatalf("expected error wrapping %v, got %v", tc.is, err)
			}
			if !strings.Contains(buf.String(), err.Error()) {
				t.Errorf("the error was not logged with operation_debug enabled: %q", buf.String())
			}
		})
	}
}

func TestJWTChecks_Check_malformedTokenNotLoggedWithoutDebug(t *testing.T) {
	buf := new(bytes.Buffer)
	j := newTestJWTChecks(t, &SignatureConfig{}, buf)
	buf.Reset()
	if _, err := j.Check("Bearer not-a-jwt"); err == nil {
		t.Fatal("expected an error")
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected log output: %q", buf.String())
	}
}
