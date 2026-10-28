package http

import (
	"net/http"
	"net/textproto"

	krakendjose "github.com/krakend/krakend-jose/v3"
)

func PropagateHeaders(r *http.Request, ps []krakendjose.Propagator, claims map[string]interface{}, preserveArrays bool) {
	if len(ps) == 0 {
		return
	}
	if !preserveArrays {
		headersToPropagate := krakendjose.HeadersToPropagate(ps, claims)
		for k, v := range headersToPropagate {
			// Set header value - replaces existing one
			r.Header.Set(k, v)
		}
		return
	}

	headersToPropagate := krakendjose.ArrayHeadersToPropagate(ps, claims)
	for k, v := range headersToPropagate {
		r.Header[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
}
