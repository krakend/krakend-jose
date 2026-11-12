package jose

import "testing"

func BenchmarkWWWAuthenticateHeader_String(b *testing.B) {
	h := &WWWAuthenticateHeader{AuthScheme: "Bearer", Params: []AuthenticateParam{
		{Key: "realm", Val: "example"},
		{Key: "scope", Val: "openid profile"},
		{Key: "error", Val: "invalid_token"},
	}}
	b.ReportAllocs()
	for b.Loop() {
		_ = h.String()
	}
}
