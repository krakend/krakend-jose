package gin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	jose "github.com/krakend/krakend-jose/v3"

	"github.com/luraproject/lura/v3/logging"
	"github.com/luraproject/lura/v3/proxy"
	ginlura "github.com/luraproject/lura/v3/router/gin"
)

func TestTokenSignatureValidator_wwwAuthenticate(t *testing.T) { // skipcq: GO-R1005
	server := httptest.NewServer(jwkEndpoint("public"))
	defer server.Close()

	// valid RS256 token with roles [role_a, role_b]
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoyMDUxODgyNzU1LCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.u1fK05FpXctB-VkhhT3xu2WSIkEr1_VM71ald-yeKTesxhxg68TsHFEOBCgoXPuCviOP8QnUKNuVSeyMJh9z3nnrfQIjo9VZ2yicZu6ImYptSQ2DJbR80GDSPp-H7KnjaR9AAY0HZ0M-KUTaHdLABZFr307nkOeaJn_5jMpav7pqa7nrU3sI1CLX5pYVTggG6t7Zoqj2ebzzqdRxQEtdmZkD_NfH-3w3t-H0ylVdeBnPh-RvlspxC_mJzyUIJ0BwPlZpabppHm1ISySa4kwnwxEYnux0oZcb3PSoOZZZA467JySZ69PRlenNPdfGPL6E3uL1nqPHcxhte7ikSG4Q6Q"

	bearerRealm := map[string]interface{}{
		"auth_scheme": "Bearer",
		"params": []map[string]string{
			{"key": "realm", "value": "example"},
			{"key": "scope", "value": "openid profile"},
		},
	}
	// invalid: token68 and params at the same time. It must warn but keep working.
	invalid := map[string]interface{}{
		"auth_scheme": "Newauth",
		"token68":     "abc==",
		"params":      []map[string]string{{"key": "realm", "value": "example"}},
	}

	for _, tc := range []struct {
		name       string
		www        map[string]interface{}
		extra      map[string]interface{}
		authHeader string
		wantStatus int
		wantHeader string
		wantLog    string
	}{
		{name: "no config, missing token", wantStatus: http.StatusUnauthorized},
		{name: "missing token", www: bearerRealm, wantStatus: http.StatusUnauthorized, wantHeader: `Bearer realm="example", scope="openid profile"`},
		{name: "invalid token", www: bearerRealm, authHeader: "BEARER " + token + "x", wantStatus: http.StatusUnauthorized, wantHeader: `Bearer realm="example", scope="openid profile"`},
		{name: "token68", www: map[string]interface{}{"auth_scheme": "Newauth", "token68": "abc=="}, wantStatus: http.StatusUnauthorized, wantHeader: "Newauth abc=="},
		{name: "scheme only", www: map[string]interface{}{"auth_scheme": "Bearer"}, wantStatus: http.StatusUnauthorized, wantHeader: "Bearer"},
		{name: "empty scheme sends no header", www: map[string]interface{}{"token68": "abc=="}, wantStatus: http.StatusUnauthorized, wantLog: "Invalid www_authenticate config"},
		{name: "invalid config warns and keeps working", www: invalid, wantStatus: http.StatusUnauthorized, wantHeader: `Newauth abc==`, wantLog: "Invalid www_authenticate config"},
		{name: "validator build error uses erroredHandler", www: bearerRealm, extra: map[string]interface{}{"alg": "unknown"}, authHeader: "BEARER " + token, wantStatus: http.StatusUnauthorized},
		{name: "forbidden has no header", www: bearerRealm, extra: map[string]interface{}{"roles": []string{"role_c"}}, authHeader: "BEARER " + token, wantStatus: http.StatusForbidden},
		{name: "valid token has no header", www: bearerRealm, authHeader: "BEARER " + token, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newVerifierEndpointCfg("RS256", server.URL, []string{"role_a"}, false)
			ns := cfg.ExtraConfig[jose.ValidatorNamespace].(map[string]interface{})
			if tc.www != nil {
				ns["www_authenticate"] = tc.www
			}
			for k, v := range tc.extra {
				ns[k] = v
			}

			buf := new(bytes.Buffer)
			logger, _ := logging.NewLogger("DEBUG", buf, "")
			hf := TokenSignatureValidator(ginlura.EndpointHandler, logger, nil)
			gin.SetMode(gin.TestMode)
			engine := gin.New()
			engine.GET(cfg.Endpoint, hf(cfg, proxy.NoopProxy))
			serve := engine.ServeHTTP

			req := httptest.NewRequest(http.MethodGet, cfg.Endpoint, http.NoBody)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			serve(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("unexpected status code: %d, want %d", w.Code, tc.wantStatus)
			}
			if got := w.Header().Get("WWW-Authenticate"); got != tc.wantHeader {
				t.Errorf("unexpected WWW-Authenticate header: %q, want %q", got, tc.wantHeader)
			}
			if tc.wantLog != "" && !strings.Contains(buf.String(), tc.wantLog) {
				t.Errorf("log does not contain %q: %s", tc.wantLog, buf.String())
			}
			if tc.wantLog == "" && strings.Contains(buf.String(), "Invalid www_authenticate config") {
				t.Errorf("unexpected warning: %s", buf.String())
			}
		})
	}
}
