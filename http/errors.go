package http

import (
	"errors"
	"net/http"

	krakendjose "github.com/krakend/krakend-jose/v3"
)

func CheckErrorToStatusCode(err error) int {
	if errors.Is(err, krakendjose.ErrRequiredRoles) || errors.Is(err, krakendjose.ErrRequiredScopes) {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}
