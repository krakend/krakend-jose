package http

import (
	"net/http"

	krakendjose "github.com/krakend/krakend-jose/v3"
)

func CheckErrorToStatusCode(err error) int {
	if err == krakendjose.ErrRequiredRoles || err == krakendjose.ErrRequiredScopes {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}
