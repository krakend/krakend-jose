package jose

import (
	"net/http"
	"reflect"
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

func TestCanAccess(t *testing.T) {
	for _, v := range []struct {
		name         string
		roleKey      string
		claims       map[string]interface{}
		requirements []string
		expected     bool
	}{
		{
			name:         "simple_success",
			roleKey:      "role",
			claims:       map[string]interface{}{"role": []interface{}{"a", "b"}},
			requirements: []string{"a"},
			expected:     true,
		},
		{
			name:         "simple_space_success",
			roleKey:      "role",
			claims:       map[string]interface{}{"role": "a b"},
			requirements: []string{"a"},
			expected:     true,
		},
		{
			name:         "single_success",
			roleKey:      "role",
			claims:       map[string]interface{}{"role": "a"},
			requirements: []string{"a"},
			expected:     true,
		},
		{
			name:         "simple_sfail",
			roleKey:      "role",
			claims:       map[string]interface{}{"role": []interface{}{"c", "b"}},
			requirements: []string{"a"},
			expected:     false,
		},
		{
			name:         "multiple_success",
			roleKey:      "role",
			claims:       map[string]interface{}{"role": []interface{}{"c"}},
			requirements: []string{"a", "b", "c"},
			expected:     true,
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			if res := CanAccess(v.roleKey, v.claims, v.requirements); res != v.expected {
				t.Errorf("'%s' have %v, want %v", v.name, res, v.expected)
			}
		})
	}
}

func TestCanAccessNested(t *testing.T) {
	for _, v := range []struct {
		name         string
		roleKey      string
		claims       map[string]interface{}
		requirements []string
		expected     bool
	}{
		{
			name:         "simple_success",
			roleKey:      "role",
			claims:       map[string]interface{}{"role": []interface{}{"a", "b"}},
			requirements: []string{"a"},
			expected:     true,
		},
		{
			name:         "simple_sfail",
			roleKey:      "role",
			claims:       map[string]interface{}{"role": []interface{}{"c", "b"}},
			requirements: []string{"a"},
			expected:     false,
		},
		{
			name:         "multiple_success",
			roleKey:      "role",
			claims:       map[string]interface{}{"role": []interface{}{"c"}},
			requirements: []string{"a", "b", "c"},
			expected:     true,
		},
		{
			name:         "struct_success",
			roleKey:      "data.role",
			claims:       map[string]interface{}{"data": map[string]interface{}{"role": []interface{}{"c"}}},
			requirements: []string{"a", "b", "c"},
			expected:     true,
		},
		{
			name:    "complex_struct_success",
			roleKey: "data.data.data.data.data.data.data.role",
			claims: map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"data": map[string]interface{}{
							"data": map[string]interface{}{
								"data": map[string]interface{}{
									"data": map[string]interface{}{
										"data": map[string]interface{}{
											"role": []interface{}{"c"},
										},
									},
								},
							},
						},
					},
				},
			},
			requirements: []string{"a", "b", "c"},
			expected:     true,
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			if res := CanAccessNested(v.roleKey, v.claims, v.requirements); res != v.expected {
				t.Errorf("'%s' have %v, want %v", v.name, res, v.expected)
			}
		})
	}
}

func TestScopesAllMatcher(t *testing.T) {
	for _, v := range []struct {
		name           string
		scopesKey      string
		claims         map[string]interface{}
		requiredScopes []string
		expected       bool
	}{
		{
			name:           "all_simple_success_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:           "all_simple_fail_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{"c"},
			expected:       false,
		},
		{
			name:           "all_missingone_fail_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{"a", "b", "c"},
			expected:       false,
		},
		{
			name:           "all_one_simple_success_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{"b"},
			expected:       true,
		},
		{
			name:           "all_no_req_scopes_success_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{},
			expected:       true,
		},
		{
			name:           "all_struct_success_for_scope_slice",
			scopesKey:      "data.scope",
			claims:         map[string]interface{}{"data": map[string]interface{}{"scope": []interface{}{"a", "b"}}},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:      "all_deep_struct_success_for_scope_slice",
			scopesKey: "data.data.data.data.data.data.data.scope",
			claims: map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"data": map[string]interface{}{
							"data": map[string]interface{}{
								"data": map[string]interface{}{
									"data": map[string]interface{}{
										"data": map[string]interface{}{
											"scope": []interface{}{"a", "b"},
										},
									},
								},
							},
						},
					},
				},
			},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:           "all_simple_success",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:           "all_simple_fail",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{"c"},
			expected:       false,
		},
		{
			name:           "all_missingone_fail",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{"a", "b", "c"},
			expected:       false,
		},
		{
			name:           "all_one_simple_success",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{"b"},
			expected:       true,
		},
		{
			name:           "all_no_req_scopes_success",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{},
			expected:       true,
		},
		{
			name:           "all_struct_success",
			scopesKey:      "data.scope",
			claims:         map[string]interface{}{"data": map[string]interface{}{"scope": "a b"}},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:      "all_deep_struct_success",
			scopesKey: "data.data.data.data.data.data.data.scope",
			claims: map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"data": map[string]interface{}{
							"data": map[string]interface{}{
								"data": map[string]interface{}{
									"data": map[string]interface{}{
										"data": map[string]interface{}{
											"scope": "a b",
										},
									},
								},
							},
						},
					},
				},
			},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			if res := ScopesAllMatcher(v.scopesKey, v.claims, v.requiredScopes); res != v.expected {
				t.Errorf("'%s' have %v, want %v", v.name, res, v.expected)
			}
		})
	}
}
func TestScopesAnyMatcher(t *testing.T) {
	for _, v := range []struct {
		name           string
		scopesKey      string
		claims         map[string]interface{}
		requiredScopes []string
		expected       bool
	}{
		{
			name:           "any_simple_success_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:           "any_simple_fail_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{"c"},
			expected:       false,
		},
		{
			name:           "any_missingone_success_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a"}},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:           "any_one_simple_success_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{"b"},
			expected:       true,
		},
		{
			name:           "any_no_req_scopes_success_for_scope_slice",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": []interface{}{"a", "b"}},
			requiredScopes: []string{},
			expected:       true,
		},
		{
			name:           "any_struct_success_for_scope_slice",
			scopesKey:      "data.scope",
			claims:         map[string]interface{}{"data": map[string]interface{}{"scope": []interface{}{"a"}}},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:      "any_deep_struct_success_for_scope_slice",
			scopesKey: "data.data.data.data.data.data.data.scope",
			claims: map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"data": map[string]interface{}{
							"data": map[string]interface{}{
								"data": map[string]interface{}{
									"data": map[string]interface{}{
										"data": map[string]interface{}{
											"scope": []interface{}{"a"},
										},
									},
								},
							},
						},
					},
				},
			},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:           "any_simple_success",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:           "any_simple_fail",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{"c"},
			expected:       false,
		},
		{
			name:           "any_missingone_success",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a"},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:           "any_one_simple_success",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{"b"},
			expected:       true,
		},
		{
			name:           "any_no_req_scopes_success",
			scopesKey:      "scope",
			claims:         map[string]interface{}{"scope": "a b"},
			requiredScopes: []string{},
			expected:       true,
		},
		{
			name:           "any_struct_success",
			scopesKey:      "data.scope",
			claims:         map[string]interface{}{"data": map[string]interface{}{"scope": "a"}},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
		{
			name:      "any_deep_struct_success",
			scopesKey: "data.data.data.data.data.data.data.scope",
			claims: map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"data": map[string]interface{}{
							"data": map[string]interface{}{
								"data": map[string]interface{}{
									"data": map[string]interface{}{
										"data": map[string]interface{}{
											"scope": "a",
										},
									},
								},
							},
						},
					},
				},
			},
			requiredScopes: []string{"a", "b"},
			expected:       true,
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			if res := ScopesAnyMatcher(v.scopesKey, v.claims, v.requiredScopes); res != v.expected {
				t.Errorf("'%s' have %v, want %v", v.name, res, v.expected)
			}
		})
	}
}

func TestCalculateHeadersToPropagate(t *testing.T) {
	for i, tc := range []struct {
		cfg      [][]string
		claims   map[string]interface{}
		expected map[string]string
	}{
		{
			cfg: [][]string{{"a", "x-a"}, {"b", "x-b"}, {"c", "x-c"}, {"d", "x-d"}},
			claims: map[string]interface{}{
				"a": 1,
				"b": "foo",
				"c": []interface{}{"one", "two"},
				"d": map[string]interface{}{
					"a": 1,
					"b": "foo",
					"c": []interface{}{"one", "two"},
				},
			},
			expected: map[string]string{"x-a": "1", "x-b": "foo", "x-c": "one,two", "x-d": `{"a":1,"b":"foo","c":["one","two"]}`},
		},
	} {
		res, err := CalculateHeadersToPropagate(tc.cfg, tc.claims)
		if err != nil {
			t.Errorf("tc-%d: unexpected error: %v", i, err)
			continue
		}

		if !reflect.DeepEqual(tc.expected, res) {
			t.Errorf("tc-%d: unexpected response: %v", i, res)
		}
	}
}
