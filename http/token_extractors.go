// Package http contains the functions that depends on the "net/http"
// package to be reused in all routers.
package http

import (
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"
	auth0 "github.com/krakend/go-auth0/v2"
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
		return jwt.ParseSigned(cookie.Value)
	}
}

func FromHeader(header string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if header == "" {
		header = "Authorization"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		raw := r.Header.Get(header)
		if len(raw) > 7 && strings.EqualFold(raw[0:7], "BEARER ") {
			raw = raw[7:]
		}
		if raw == "" {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(raw)
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
