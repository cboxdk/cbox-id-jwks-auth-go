package cboxidjwksauth

import "fmt"

// InvalidTokenError is returned when a presented JWT fails
// validation — bad signature, wrong issuer, wrong audience,
// expired, malformed structure, or unknown signing key.
//
// Maps to HTTP 401 (`invalid_token`) at the middleware layer.
type InvalidTokenError struct {
	// Reason is a stable token-failure code (malformed,
	// missing_kid, unknown_kid, bad_signature, missing_iss,
	// wrong_issuer, wrong_audience, expired, not_yet_valid,
	// jwks_unavailable). Useful for log filtering / alerting.
	Reason string

	// Message is a human-readable summary.
	Message string

	// Err is the underlying cause, if any.
	Err error
}

func (e *InvalidTokenError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cbox-id-jwks-auth: invalid token (%s): %s: %v", e.Reason, e.Message, e.Err)
	}
	return fmt.Sprintf("cbox-id-jwks-auth: invalid token (%s): %s", e.Reason, e.Message)
}

func (e *InvalidTokenError) Unwrap() error { return e.Err }

// InsufficientScopeError is returned when a token validates
// correctly but lacks a scope the endpoint requires.
//
// Maps to HTTP 403 (`insufficient_scope`) at the middleware layer.
type InsufficientScopeError struct {
	RequiredScope string
}

func (e *InsufficientScopeError) Error() string {
	return fmt.Sprintf("cbox-id-jwks-auth: required scope `%s` is not present in the token", e.RequiredScope)
}
