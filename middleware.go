package cboxidjwksauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type ctxKey int

const (
	// ctxKeyClaims stashes *Claims on the request context for
	// downstream handlers.
	ctxKeyClaims ctxKey = iota
)

// ClaimsFromContext returns the validated claims attached to the
// request context by the middleware. Returns (nil, false) if the
// request didn't pass through the middleware.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKeyClaims).(*Claims)
	return c, ok
}

// MiddlewareOption configures the middleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	requiredScope string
}

// WithRequiredScope makes the middleware reject requests whose
// token lacks the given scope. Returns 403 insufficient_scope.
// Multiple wrappings stack — apply per-route.
func WithRequiredScope(scope string) MiddlewareOption {
	return func(c *middlewareConfig) { c.requiredScope = scope }
}

// Middleware returns an http.Handler middleware that:
//
//  1. Extracts the Bearer token from Authorization header
//  2. Validates it via the Validator (signature, iss, aud, exp, nbf)
//  3. Optionally checks for a required scope
//  4. Attaches the validated claims to the request context
//
// Failure modes follow OAuth 2.0:
//
//	401 invalid_token       — missing / bad token
//	403 insufficient_scope  — token valid, scope missing
//
// WWW-Authenticate challenges are populated per RFC 6750.
//
// Usage:
//
//	mux.Handle("/api/v1/audit",
//	    cboxidjwksauth.Middleware(validator)(auditHandler))
//
//	// Per-route required scope:
//	mux.Handle("/api/v1/audit/events",
//	    cboxidjwksauth.Middleware(validator,
//	        cboxidjwksauth.WithRequiredScope("id.audit.write"))(auditHandler))
func Middleware(v *Validator, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	cfg := &middlewareConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer := extractBearer(r)
			if bearer == "" {
				writeUnauthorized(w, "missing_token", "Missing Bearer token.")
				return
			}

			claims, err := v.Validate(r.Context(), bearer)
			if err != nil {
				var ite *InvalidTokenError
				if errAs(err, &ite) {
					writeUnauthorized(w, ite.Reason, ite.Message)
				} else {
					writeUnauthorized(w, "validation_failed", err.Error())
				}
				return
			}

			if cfg.requiredScope != "" && !claims.HasScope(cfg.requiredScope) {
				writeForbidden(w, cfg.requiredScope)
				return
			}

			ctx := context.WithValue(r.Context(), ctxKeyClaims, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractBearer(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

func writeUnauthorized(w http.ResponseWriter, reason, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="`+description+`"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_token",
		"error_description": description,
		"reason":            reason,
	})
}

func writeForbidden(w http.ResponseWriter, requiredScope string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate",
		`Bearer error="insufficient_scope", scope="`+requiredScope+`"`)
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "insufficient_scope",
		"error_description": "Required scope `" + requiredScope + "` is not present in the token.",
		"required_scope":    requiredScope,
	})
}

// errAs is a thin wrapper around errors.As that keeps the package
// import surface small (no errors import in middleware.go).
func errAs(err error, target any) bool {
	if err == nil {
		return false
	}
	if t, ok := target.(**InvalidTokenError); ok {
		var ite *InvalidTokenError
		for cur := err; cur != nil; {
			if v, isType := cur.(*InvalidTokenError); isType {
				ite = v
				break
			}
			type unwrapper interface{ Unwrap() error }
			if u, ok := cur.(unwrapper); ok {
				cur = u.Unwrap()
				continue
			}
			break
		}
		if ite != nil {
			*t = ite
			return true
		}
	}
	return false
}
