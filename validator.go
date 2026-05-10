package cboxidjwksauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Validator parses and verifies JWTs against id's published JWKS.
// Configure once per service (one Issuer + Audience pair); safe to
// share across goroutines.
type Validator struct {
	issuer        string
	audience      string
	jwksURI       string
	jwksCache     *jwk.Cache
	clockSkew     time.Duration
	now           func() time.Time
	refreshErrTTL time.Duration
}

// Option configures a Validator at construction time.
type Option func(*Validator)

// WithIssuer sets the expected `iss` claim. Tokens whose iss does
// not match are rejected with reason=wrong_issuer.
func WithIssuer(iss string) Option {
	return func(v *Validator) { v.issuer = iss }
}

// WithAudience sets the expected `aud` claim. Tokens whose aud
// list does not include this value are rejected with
// reason=wrong_audience.
func WithAudience(aud string) Option {
	return func(v *Validator) { v.audience = aud }
}

// WithJWKSURI sets the URL the validator pulls JWKS from. Typically
// `https://id.cbox.systems/.well-known/jwks.json`.
func WithJWKSURI(uri string) Option {
	return func(v *Validator) { v.jwksURI = uri }
}

// WithClockSkew lets callers tune how much wall-clock skew to
// tolerate when checking exp / nbf. Default 30s.
func WithClockSkew(d time.Duration) Option {
	return func(v *Validator) { v.clockSkew = d }
}

// WithClock injects a now-function. Used by tests for
// deterministic expiry behaviour.
func WithClock(now func() time.Time) Option {
	return func(v *Validator) { v.now = now }
}

// New returns a Validator configured with the given options. The
// JWKS cache is registered with lestrrat's jwk.Cache (refresh
// every WithJWKSCacheTTL, default ~1 hour) and warmed on first use.
//
// Callers MUST close the validator when done via Close() so the
// background JWKS refresher exits.
func New(ctx context.Context, opts ...Option) (*Validator, error) {
	v := &Validator{
		clockSkew:     30 * time.Second,
		now:           time.Now,
		refreshErrTTL: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(v)
	}

	if v.issuer == "" {
		return nil, fmt.Errorf("cbox-id-jwks-auth: WithIssuer is required")
	}
	if v.audience == "" {
		return nil, fmt.Errorf("cbox-id-jwks-auth: WithAudience is required")
	}
	if v.jwksURI == "" {
		return nil, fmt.Errorf("cbox-id-jwks-auth: WithJWKSURI is required")
	}

	cache := jwk.NewCache(ctx)
	if err := cache.Register(v.jwksURI,
		jwk.WithMinRefreshInterval(15*time.Minute),
		jwk.WithRefreshInterval(1*time.Hour),
	); err != nil {
		return nil, fmt.Errorf("cbox-id-jwks-auth: register JWKS cache: %w", err)
	}
	v.jwksCache = cache

	return v, nil
}

// Validate parses tokenString as a JWT, verifies its signature
// against the JWKS, and checks iss / aud / exp / nbf. Returns
// (*Claims, nil) on success, (nil, *InvalidTokenError) on any
// validation failure.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	keyset, err := v.jwksCache.Get(ctx, v.jwksURI)
	if err != nil {
		return nil, &InvalidTokenError{
			Reason:  "jwks_unavailable",
			Message: "fetch JWKS: " + err.Error(),
			Err:     err,
		}
	}

	// Verify the signature using the keyset. jwt.Parse runs the
	// signature check, then iat/exp/nbf with our clock-skew
	// tolerance, and finally iss/aud constraints.
	parsed, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(keyset),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithAcceptableSkew(v.clockSkew),
		jwt.WithClock(jwt.ClockFunc(v.now)),
	)
	if err != nil {
		return nil, classifyParseError(err)
	}

	return claimsFromJWT(parsed), nil
}

// classifyParseError maps lestrrat's typed validation errors to
// our stable Reason codes. lestrrat's messages quote the claim
// name (e.g. `"exp" not satisfied`), so we match against those
// canonical forms.
func classifyParseError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, `"exp" not satisfied`), strings.Contains(msg, "token is expired"):
		return &InvalidTokenError{Reason: "expired", Message: msg, Err: err}
	case strings.Contains(msg, `"nbf" not satisfied`), strings.Contains(msg, "token is not yet valid"):
		return &InvalidTokenError{Reason: "not_yet_valid", Message: msg, Err: err}
	case strings.Contains(msg, `"iss" not satisfied`):
		return &InvalidTokenError{Reason: "wrong_issuer", Message: msg, Err: err}
	case strings.Contains(msg, `"aud" not satisfied`):
		return &InvalidTokenError{Reason: "wrong_audience", Message: msg, Err: err}
	case isSignatureFailure(err):
		return &InvalidTokenError{Reason: "bad_signature", Message: msg, Err: err}
	default:
		return &InvalidTokenError{Reason: "malformed", Message: msg, Err: err}
	}
}

func isSignatureFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "signature") ||
		strings.Contains(msg, "verification") ||
		strings.Contains(msg, "could not find matching key")
}

// claimsFromJWT projects a lestrrat jwt.Token into our Claims
// shape, splitting standard fields from the custom bag.
func claimsFromJWT(t jwt.Token) *Claims {
	c := &Claims{
		Subject:   t.Subject(),
		Issuer:    t.Issuer(),
		Audience:  t.Audience(),
		IssuedAt:  t.IssuedAt(),
		ExpiresAt: t.Expiration(),
		JTI:       t.JwtID(),
		Custom:    map[string]any{},
	}

	// Standard OIDC `client_id` claim.
	if v, ok := t.Get("client_id"); ok {
		if s, ok := v.(string); ok {
			c.ClientID = s
		}
	}

	// Scopes — accept array form (League's `scopes`) and standard
	// space-separated `scope` string.
	if v, ok := t.Get("scopes"); ok {
		if arr, ok := v.([]any); ok {
			for _, s := range arr {
				if str, ok := s.(string); ok {
					c.Scopes = append(c.Scopes, str)
				}
			}
		} else if arr, ok := v.([]string); ok {
			c.Scopes = append(c.Scopes, arr...)
		}
	}
	if len(c.Scopes) == 0 {
		if v, ok := t.Get("scope"); ok {
			if s, ok := v.(string); ok && s != "" {
				for _, part := range strings.Split(s, " ") {
					if part != "" {
						c.Scopes = append(c.Scopes, part)
					}
				}
			}
		}
	}

	// Everything else lands in Custom.
	known := map[string]struct{}{
		"sub": {}, "iss": {}, "aud": {}, "iat": {}, "exp": {}, "nbf": {},
		"jti": {}, "client_id": {}, "scope": {}, "scopes": {},
	}
	for it := t.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key, _ := pair.Key.(string)
		if _, isKnown := known[key]; isKnown {
			continue
		}
		c.Custom[key] = pair.Value
	}

	return c
}
