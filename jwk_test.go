package jose

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJWK(t *testing.T) {
	for _, tc := range []struct {
		Name string
		Alg  string
		ID   []string
	}{
		{
			Name: "public",
			ID:   []string{"2011-04-29"},
			Alg:  "RS256",
		},
		{
			Name: "public",
			ID:   []string{"1"},
		},
		{
			Name: "private",
			ID:   []string{"2011-04-29"},
			Alg:  "RS256",
		},
		{
			Name: "private",
			ID:   []string{"1"},
		},
		{
			Name: "symmetric",
			ID:   []string{"sim2"},
			Alg:  "HS256",
		},
	} {
		server := httptest.NewServer(jwkEndpoint(tc.Name))
		defer server.Close()
		secretProvidr := secretProvider(secretProviderConfig{URI: server.URL}, nil)
		for _, k := range tc.ID {
			key, err := secretProvidr.GetKey(k)
			if err != nil {
				t.Errorf("[%s] extracting the key %s: %s", tc.Name, k, err.Error())
			}
			if key.Algorithm != tc.Alg {
				t.Errorf("wrong alg. have: %s, want: %s", key.Algorithm, tc.Alg)
			}
		}
	}
}

func TestDialer_DialTLS_ko(t *testing.T) {
	d := NewDialer(secretProviderConfig{})
	c, err := d.DialTLS("\t", "addr")
	if err == nil {
		t.Error(err)
	}
	if c != nil {
		t.Errorf("unexpected connection: %v", c)
	}
}

func Test_decodeFingerprints(t *testing.T) {
	_, err := decodeFingerprints([]string{"not_encoded_message"})
	if err == nil {
		t.Error(err)
	}
}

func jwkEndpoint(name string) http.HandlerFunc {
	data, err := ioutil.ReadFile("./fixtures/" + name + ".json")
	return func(rw http.ResponseWriter, _ *http.Request) {
		if err != nil {
			rw.WriteHeader(500)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(data)
	}
}
