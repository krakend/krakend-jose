package gin

import (
	"net/http"
	"testing"

	krakendjose "github.com/krakendio/krakend-jose/v2"
	"github.com/luraproject/lura/v2/config"
)

func BenchmarkValidation_ES256(b *testing.B) {
	cfg := &config.EndpointConfig{
		Backend: []*config.Backend{},
		ExtraConfig: map[string]interface{}{
			krakendjose.ValidatorNamespace: map[string]interface{}{
				"alg":            "ES256",
				"jwk_local_path": "../fixtures/public.json",
			},
		},
	}
	scfg, _ := krakendjose.GetSignatureConfig(cfg)
	validator, _ := krakendjose.NewValidator(scfg, FromCookie, FromHeader)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER eyJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.1bNeUdXVB1HULFizcd92JuCj9EL_LCdGUMMbsAlxue84I61EWWXJ0SbmJU_Gm8obTyQlXf2UgptynARytgfU0A")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.ValidateRequest(req)
	}
}

func BenchmarkValidation_RS256(b *testing.B) {
	cfg := &config.EndpointConfig{
		Backend: []*config.Backend{},
		ExtraConfig: map[string]interface{}{
			krakendjose.ValidatorNamespace: map[string]interface{}{
				"alg":            "RS256",
				"jwk_local_path": "../fixtures/public.json",
			},
		},
	}
	scfg, _ := krakendjose.GetSignatureConfig(cfg)
	validator, _ := krakendjose.NewValidator(scfg, FromCookie, FromHeader)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.NrLwxZK8UhS6CV2ijdJLUfAinpjBn5_uliZCdzQ7v-Dc8lcv1AQA9cYsG63RseKWH9u6-TqPKMZQ56WfhqL028BLDdQCiaeuBoLzYU1tQLakA1V0YmouuEVixWLzueVaQhyGx-iKuiuFhzHWZSqFqSehiyzI9fb5O6Gcc2L6rMEoxQMaJomVS93h-t013MNq3ADLWTXRaO-negydqax_WmzlVWp_RDroR0s5J2L2klgmBXVwh6SYy5vg7RrnuN3S8g4oSicJIi9NgnG-dDikuaOg2DeFUt-mYq_j_PbNXf9TUl5hl4kEy7E0JauJ17d1BUuTl3ChY4BOmhQYRN0dYg")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.ValidateRequest(req)
	}
}

func BenchmarkValidation_RS384(b *testing.B) {
	cfg := &config.EndpointConfig{
		Backend: []*config.Backend{},
		ExtraConfig: map[string]interface{}{
			krakendjose.ValidatorNamespace: map[string]interface{}{
				"alg":            "RS384",
				"jwk_local_path": "../fixtures/public.json",
			},
		},
	}
	scfg, _ := krakendjose.GetSignatureConfig(cfg)
	validator, _ := krakendjose.NewValidator(scfg, FromCookie, FromHeader)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER eyJhbGciOiJSUzM4NCIsImtpZCI6IjM4NCJ9.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.MnbhVVK-8o-wxSF3p159Ao5gu3cO9cfepOfBJnHaLnl9sEGlZNZchlVsscybFF_oq4Pm3yfG-oXC7zf5W3Mi3SULLwXUPXB28yBk27un6-5431FJTBombFN8njf0dLUFJ1IsDBiGX0CBaQ_cge_p06fc6K7PP97mqnECKyoJRzBzY5V79iXy3eMImhFfwVSYSJC3pnC-UzADspFja3IKYIJDNsmMCKM2hM0HYJI3AlERCNdBPKi5h12BM7zmkVjBlfs90AwL71r22B-b2kA3RlOJ_jnOY1AAGwsbxmRG-HH-Kdy7w87Iib5duOgje905j0I1sf13pPIfWFzJ3pEQZU5Y0ZdBgBbvWtYDjjmhfMo8Y0ZBWdF3WvQd3Z7OaEFWJi2D18JFUIILUPAFjDItrq72r8bPmu6v612ZDH5-A0uxoikdkinTTl7CaFyEt9Fi-juTrcOfvoSvyJ3-LGbpUBXTxevaQyI_vOmWs5xduAZWe3Lk061pRCi1YJXCzyEIlcUADQudSp8h26obLiGtAzs9Ftff34-BWkGHggfSACRDN2S-rm9rOy4vF6efSzt5QjfNMqsqPqohPyIl3d91-5W3-GKUKSgVyryOqRFkSUwLHC6-uK3JWtCqetswOTZoJNEQkk256Muys1LzJucNFtAgMaXg5OVUecYDeMKo7mk")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.ValidateRequest(req)
	}
}

func BenchmarkValidation_RS512(b *testing.B) {
	cfg := &config.EndpointConfig{
		Backend: []*config.Backend{},
		ExtraConfig: map[string]interface{}{
			krakendjose.ValidatorNamespace: map[string]interface{}{
				"alg":            "RS512",
				"jwk_local_path": "../fixtures/public.json",
			},
		},
	}
	scfg, _ := krakendjose.GetSignatureConfig(cfg)
	validator, _ := krakendjose.NewValidator(scfg, FromCookie, FromHeader)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER eyJhbGciOiJSUzUxMiIsImtpZCI6IjRrNTEyIn0.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.hk6pz4ro8dIQN6lQpu5VSfKhnCWg3d0jRN7tKVJavk_WLsXt9FSvSbTMMVBVDo4Ea9oXDEbamelISn_ViNiP9JyIYdMcU1fVoxagpKl2PAvSH_wxzfc-45McSV3NshPeCANMiuq0pjD0-RE31TfEC515sbAKfMNePf1Aw2Zut3bve5Ol2ZReW_T3XeJivAaOpvZK1nZ9UNhevzszJ_l8Y8d1uhzA9IpfiWFLyH0VyYevrgLThMk--OjET2sOje-mA8YhL2yz5c3IEMAKGaly2U76mgukvlpcB8P-N69kC0f_EdyCo1-04tcoyLwBIglhhO4la3s2TyK7lQXma0iE0m5BG42bjCZ-R07vGg-zsnYt0GJlYOutpulfbqC-BXBbbuSqP8LaomzriVukzzaDw5As1coKJy6n9F8eNrQLdUPZHFtYBQoGZGQFlF2IGcUYGm3_Zm3fnIbzMS6nucRIc7nRCaeu0XP3_sErs-nsjc4JT-N2u3IGJtCDLb-op8WbIhef_eV_RPPq141M-rH7PHOzM2uFyO3tGEx1xnHNEYhk9hpq3cmYPEEMYtCgn6FDsq84PGJpmhqy3-4j-k_erIQyP8pGYGzCzkxdHeq_iFWLGE2TAAcpx60aH8GMwNjU5StcBzP8fetqTIrEVSJn4YHYCgIw2J3C9bPQTrmhyvM")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.ValidateRequest(req)
	}
}

func BenchmarkValidation_PS256(b *testing.B) {
	cfg := &config.EndpointConfig{
		Backend: []*config.Backend{},
		ExtraConfig: map[string]interface{}{
			krakendjose.ValidatorNamespace: map[string]interface{}{
				"alg":            "PS256",
				"jwk_local_path": "../fixtures/public.json",
			},
		},
	}
	scfg, _ := krakendjose.GetSignatureConfig(cfg)
	validator, _ := krakendjose.NewValidator(scfg, FromCookie, FromHeader)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER eyJhbGciOiJQUzI1NiIsImtpZCI6InAyNTYifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.hnDYFvoQElI7PtAPXB-pYfFWAv2Ceg7Z-Xk76MFExi-57hCh0ivKGoaGjyCKBi_xznmzuZ4SPRtF5ARRH1B_3YKg2-ImetOEt9jdXbrwc77zSDzh78q_JiLYNoMv1at6TuAEFFJqoaE0XkJdyPbiCgwwb2FREVhob9zeXPaz90MzcKHHBJsEtxWdLFrXbXDmfkzdQEzwnk1kSi80xNRYdqYxWSus8PvWR0-boJ7OGfURXXKUSvwRhKUhglqpzxMltlJEeIykvzLzSXsgPnpubcu_ug5TJD0tW-7739V3_3zerqbE7xsHj1Hw1jPHiZhmSmoKFjI4OOKg-Ij-9RvqrIImW_mAWUUW3n40BMvt8WgV2qJCR64C8t13n006ev71MO4S1wqs-vzEPNPofSGaPL4n3zZEBn5cDMt5NjgHZNq-eVQT4izACELQf-zBdAnqE9yhCgC_6zBc1bBIFdOlq6kF7YNJdLdD9tOSAQN8hWutFDNLFHSrC3rP7j4HShm8eI1m4FarsHzTxrmDZLjeya0U5iStC0r5PwA2csdy1WfxServv-WH3ZhVvaRcyyBcLHaFvqCIc68h3Q6Y6m1W6X_LNzBqE9WMIsfdp9aqQn8cgUPIEA5xM2kerD5S0zU_LJFO1e0fq3gG1NtV0NDT-dGW8VX_szYG6dYBWwd35BE")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.ValidateRequest(req)
	}
}

func BenchmarkValidation_PS384(b *testing.B) {
	cfg := &config.EndpointConfig{
		Backend: []*config.Backend{},
		ExtraConfig: map[string]interface{}{
			krakendjose.ValidatorNamespace: map[string]interface{}{
				"alg":            "PS384",
				"jwk_local_path": "../fixtures/public.json",
			},
		},
	}
	scfg, _ := krakendjose.GetSignatureConfig(cfg)
	validator, _ := krakendjose.NewValidator(scfg, FromCookie, FromHeader)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER eyJhbGciOiJQUzM4NCIsImtpZCI6InAzODQifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.Uf1vLmFcYNPGG8PC-Ej3cTcCdLXKVFAbwguCmkvsnmibOgzYD6gPX675QOkh0XKZWUId80-AVHylDOuR8bx-5QEYLX1crYXfTumW9CQ2_iKaOeMfhpELxQAk5N59qkLIDQRhPZL3DkG78kVBv3dKTHkrc7UvsHuJp9Yupdx6Ik0BHGBu8p6XgRBrBbF81Nh1mxbQhgoclNe1k_SLaDYwIhXBsjHzeT6SoNp--nxP9RJ0R85EVtgtVm7cX1fP6JEqWX4UPESlmR_9Ze2K7kft4GAywuZNIIW2Y6kSTEJhNnRkMUnux22O1wk2GPmJEvJmzkZ4o9b9d_oGChETod5KHzvIIbOZRhOkeJZ1EGK-y40X-N1uhKe1TM48Qf4CVCj-sIz3udmg17NC6zB-z70M0YtnI5xvhxuoMlQR2A4EP-gW9NFao4EYsLo5QM56GNj4r_3EvF7DC-KbBwg51ixT8m5fIT0SZjbDW-Znzjo4Xz_1LpeXzHxi1K-b_JUOn9TiZyZy9LVEQppzLX4S6XSpCze3gEwc7Fm9nda8xMGwr8nVebHFXDlTXXZvBOGMiQDosiS1Cl7u0ysrJJ0DguUTVogKirCS0gEPElpXkc9FGwjIrGLNuSSWt3bxKEaHUicSW9K5vRSJDowtDpM932wKOfe3S3EM0LdveaHZXvqljLg")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.ValidateRequest(req)
	}
}

func BenchmarkValidation_PS512(b *testing.B) {
	cfg := &config.EndpointConfig{
		Backend: []*config.Backend{},
		ExtraConfig: map[string]interface{}{
			krakendjose.ValidatorNamespace: map[string]interface{}{
				"alg":            "PS512",
				"jwk_local_path": "../fixtures/public.json",
			},
		},
	}
	scfg, _ := krakendjose.GetSignatureConfig(cfg)
	validator, _ := krakendjose.NewValidator(scfg, FromCookie, FromHeader)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER eyJhbGciOiJQUzUxMiIsImtpZCI6InA1MTIifQ.eyJhdWQiOiJodHRwOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzM1Njg5NjAwLCJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJtbmIyM3Zjc3J0NzU2eXVpb21uYnZjeDk4ZXJ0eXVpb3AiLCJyb2xlcyI6WyJyb2xlX2EiLCJyb2xlX2IiXSwic3ViIjoiMTIzNDU2Nzg5MHF3ZXJ0eXVpbyJ9.YIcRqRMGRRaeP7ImWKOpRJhveYK8TFHs4YlO3_YMFOBrJB4QSVYs_Z54EniNcBfrUwgu1EoqbEgh1mtpexUmwkgc6oWc69QhdEgWeITFRzxKhC9TF9V7l7HW713vCXfYgdFJ3-8hr0yNfoMz69tKHhwJnEMCnM6INj_jgFzuvgw3V2mlgWHCItx-J5MUY32d4E6AIHcgXAtQbBnVeke9y9JVlP2a27eZE6njW-d5zZxpHrRvwv_z1V2qWxZUpPxjZJV8n24vVi68saM9dF5OcDBX5xU8ntMOyb6AH_Jw2oE6fIsu1GyRfTmcCQJVmn-rh-A0gzvrT14WOPV9tYvNol8HGsSBDI8S86C0aD8b1VpjJufhqvgZZDUUFIcVLv0rFOSa4_vYwR_MjxxYeXqk7f9wVygK9SpD9QtYP_EdRzB7wZynX2jnyW6QGTcwuuP7OvbG_2Lpp20--1TBqCWeDpeyFv5uJT7iLKyFUXFyvC3tjBqobo-HBZOYiUInzfRCyofsRTqaoca1w-DsNdQCoAF4T1We7JECZIae2yn5owDf7qWl8S6qLk8BnfSeKZX540ppDbVy0EntN4ufT19GnMMl4-6ZTvl1TtNykOMoDF4ARU-yBbSmQlnG_47vfZ6NqWTEWFw-kcpuHiMEOKBjGTKFD6WwVGksxds6-oYOU0o")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.ValidateRequest(req)
	}
}
