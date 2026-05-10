// Package cboxidjwksauth is the Go counterpart of the PHP
// cboxdk/cbox-id-jwks-auth package — JWKS-only validator + HTTP
// middleware for resource servers consuming Cbox id-issued JWTs.
//
// High-volume gateways (vault, OTel ingest, future managed
// services) install this so they don't have to roundtrip to id on
// every request. JWKS is cached aggressively; last-good JWKS keeps
// serving up to a configurable grace window after id becomes
// unreachable.
//
// Revocation is NOT honoured by JWKS-only validation. The 10-min
// access-token TTL is the v1 mitigation; a distributed revocation
// feed is on the roadmap (see cbox-infra/docs/SERVICE_AUTH.md).
package cboxidjwksauth

import "time"

// Claims is the validated JWT payload returned by Validator.Validate.
// Standard OIDC fields are typed; the Custom map carries the rest
// (e.g. platform_roles, oid, roles, seats) so callers can read
// anything id ships in the access token.
type Claims struct {
	Subject   string         `json:"sub"`
	Issuer    string         `json:"iss"`
	Audience  []string       `json:"aud"`
	IssuedAt  time.Time      `json:"iat"`
	ExpiresAt time.Time      `json:"exp"`
	JTI       string         `json:"jti,omitempty"`
	ClientID  string         `json:"client_id,omitempty"`
	Scopes    []string       `json:"scopes,omitempty"`
	Custom    map[string]any `json:"-"`
}

// HasScope reports whether scope is in c.Scopes.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope reports whether c.Scopes contains at least one of
// the given scopes.
func (c *Claims) HasAnyScope(scopes ...string) bool {
	for _, want := range scopes {
		if c.HasScope(want) {
			return true
		}
	}
	return false
}

// HasAllScopes reports whether c.Scopes contains every given scope.
func (c *Claims) HasAllScopes(scopes ...string) bool {
	for _, want := range scopes {
		if !c.HasScope(want) {
			return false
		}
	}
	return true
}
