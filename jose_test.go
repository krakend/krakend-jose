package jose

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
)

func nopExtractor(_ string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	return func(_ *http.Request) (*jwt.JSONWebToken, error) { return nil, nil }
}

func Test_NewValidator_unkownAlg(t *testing.T) {
	_, err := NewValidator(&SignatureConfig{
		Alg: "random",
	}, nopExtractor, nopExtractor)
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
			cfg: [][]string{
				{"a", "x-a"},
				{"b", "x-b"},
				{"c", "x-c"},
				{"d.d", "x-d"},
				{"d.d.c", "x-e"},
				{"d.f", "x-f"},
				{"g", "x-g"},
			},
			claims: map[string]interface{}{
				"a": 1,
				"b": "foo",
				"c": []interface{}{"one", "two"},
				"d": map[string]interface{}{
					"a": 1,
					"b": "foo",
					"c": []interface{}{"one", "two"},
					"d": map[string]interface{}{
						"a": 1,
						"b": "foo",
						"c": []interface{}{"one", "two"},
					},
				},
				"g": []interface{}{},
			},
			expected: map[string]string{
				"x-a": "1",
				"x-b": "foo",
				"x-c": "one,two",
				"x-d": `{"a":1,"b":"foo","c":["one","two"]}`,
				"x-e": "one,two",
				"x-f": "",
				"x-g": "",
			},
		},
	} {
		res, err := CalculateHeadersToPropagate(tc.cfg, tc.claims)
		if err != nil {
			t.Errorf("tc-%d: unexpected error: %v", i, err)
			continue
		}

		if !reflect.DeepEqual(tc.expected, res) {
			t.Errorf("tc-%d: got: %v want: %v", i, res, tc.expected)
		}
	}
}

func TestUnmarshalDataTypesGetClaim(t *testing.T) {
	var c Claims
	json.Unmarshal([]byte(`{
		"t0_int": 42,
		"t1_int": 0,
		"t2_int": -42,
		"t3_float": -42.42,
		"t4_string": "string val",
		"t5_string": "d0052a8b-6b35-4cb4-af69-b95e241e7208",
		"t6_array": ["item 1", "item-2", 1, -2, 2.99, -3.01],
		"t7_big_int": 1000001,
		"t8_float_round": 4.000001,
		"t9_float_round": 4.0000001,
		"t10_timestamp": 1651529725,
		"t11_array": []
	}`), &c)

	for i, tc := range []struct {
		key      string
		expected string
	}{
		{
			key:      "t0_int",
			expected: "42",
		},
		{
			key:      "t1_int",
			expected: "0",
		},
		{
			key:      "t2_int",
			expected: "-42",
		},
		{
			key:      "t3_float",
			expected: "-42.420000",
		},
		{
			key:      "t4_string",
			expected: "string val",
		},
		{
			key:      "t5_string",
			expected: "d0052a8b-6b35-4cb4-af69-b95e241e7208",
		},
		{
			key:      "t6_array",
			expected: "item 1,item-2,1,-2,2.99,-3.01",
		},
		{
			key:      "t7_big_int",
			expected: "1000001",
		},
		{
			key:      "t8_float_round",
			expected: "4.000001",
		},
		{
			key:      "t9_float_round",
			expected: "4",
		},
		{
			key:      "t10_timestamp",
			expected: "1651529725",
		},
		{
			key:      "t11_array",
			expected: "",
		},
	} {
		t.Run(tc.key, func(t *testing.T) {
			res, ok := c.Get(tc.key)
			if !ok || !reflect.DeepEqual(tc.expected, res) {
				t.Errorf("Test %d - Claim %s: unexpected value: %v", i, tc.key, res)
			}
		})
	}
}
