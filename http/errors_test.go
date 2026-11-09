package http

import (
	"errors"
	"net/http"
	"testing"

	krakendjose "github.com/krakend/krakend-jose/v3"
)

func TestCheckErrorToStatusCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{krakendjose.ErrRequiredRoles, http.StatusForbidden},
		{krakendjose.ErrRequiredScopes, http.StatusForbidden},
		{krakendjose.ErrTokenRejected, http.StatusUnauthorized},
		{errors.New("anything else"), http.StatusUnauthorized},
	} {
		if got := CheckErrorToStatusCode(tc.err); got != tc.want {
			t.Errorf("%v: got %d, want %d", tc.err, got, tc.want)
		}
	}
}
