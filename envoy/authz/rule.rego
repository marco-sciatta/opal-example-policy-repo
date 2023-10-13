package envoy.authz

import future.keywords
import input.attributes.request.http as http_request

default allow := false

allow if {
  coming_from_gw
  has_valid_passport
}

coming_from_gw if {
    svc_spiffe_id := input.attributes.source.principal
	svc_spiffe_id == "spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account_FAKE"
}

has_valid_passport if {
	passport_tkn := http_request.headers["x-passport-jwt"]
    [_, payload, _] := io.jwt.decode(passport_tkn)
    now := time.now_ns() / 1000000000
    now < payload.exp 
}

