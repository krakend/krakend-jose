// Package http contains the functions that depends on the "net/http"
// package to be reused in all routers.
package http

import (
	"net/http"

	"github.com/go-jose/go-jose/v4/jwt"
	auth0 "github.com/krakend/go-auth0/v2"
	krakendjose "github.com/krakend/krakend-jose/v3"
)

func FromCookie(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if key == "" {
		key = "access_token"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return nil, auth0.ErrTokenNotFound
		}
		return krakendjose.ParseSigned(cookie.Value)
	}
}

func FromHeader(header string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if header == "" {
		header = "Authorization"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		return krakendjose.StripBearerAndParse(r.Header.Get(header))
	}
}

func StrTokenFromHeaderOrCookieFn(header, cookie string) func(r *http.Request) (string, error) {
	if header == "" {
		header = "Authorization"
	}
	if cookie == "" {
		cookie = "access_token"
	}

	return func(r *http.Request) (string, error) {
		if v := r.Header.Get(header); v != "" {
			return v, nil
		}
		c, err := r.Cookie(cookie)
		if err != nil {
			return "", auth0.ErrTokenNotFound
		}
		return c.Value, nil
	}
}
