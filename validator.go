package cboxidjwksauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// minRSAModulusBytes is the floor we accept for an RSA modulus —
// 256 bytes = 2048 bits. Smaller keys are dropped at parse time so
// a JWKS misconfig can't downgrade our trust boundary. NIST SP
// 800-131A retired 1024-bit RSA in 2014. Mirrors the PHP package.
const minRSAModulusBytes = 256

// Validator parses and verifies JWTs against id's published JWKS.
// Configure once per service (one Issuer + Audience pair); safe to
// share across goroutines.
type Validator struct {
	issuer            string
	audience          string
	jwksURI           string
	jwksCache         *jwk.Cache
	clockSkew         time.Duration
	now               func() time.Time
	refreshErrTTL     time.Duration
	cancel            context.CancelFunc
	staleFallbackPath string
	stalePersistOnce  sync.Mutex
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

// WithStaleFallbackPath persists the most recent good JWKS to a
// local file and consults it when id is unreachable AND the
// in-process cache is cold (e.g. a fresh pod that boots while id
// is down). Pass an absolute path on a writable, non-shared volume
// — typically /var/cache/<service>/jwks.json. Permissions are set
// to 0600 since the file contains public material whose integrity
// matters more than its confidentiality, but we don't want random
// processes appending to it.
//
// Without this option a fresh pod failing its initial JWKS fetch
// returns reason=jwks_unavailable; with it, the pod uses the last-
// known keyset until id recovers, blunting the blast radius of an
// id outage during deploys.
func WithStaleFallbackPath(path string) Option {
	return func(v *Validator) { v.staleFallbackPath = path }
}

// New returns a Validator configured with the given options. The
// JWKS cache is registered with lestrrat's jwk.Cache (refresh
// every WithJWKSCacheTTL, default ~1 hour) and warmed on first use.
//
// Callers should call Close() at shutdown so the background JWKS
// refresher exits cleanly.
func New(ctx context.Context, opts ...Option) (*Validator, error) {
	// Wrap the caller's context so Close() can cancel just the
	// validator's background refresher without canceling the
	// parent context (which usually owns the whole process).
	cacheCtx, cancel := context.WithCancel(ctx)

	v := &Validator{
		clockSkew:     30 * time.Second,
		now:           time.Now,
		refreshErrTTL: 24 * time.Hour,
		cancel:        cancel,
	}
	for _, opt := range opts {
		opt(v)
	}

	if v.issuer == "" {
		cancel()
		return nil, fmt.Errorf("cbox-id-jwks-auth: WithIssuer is required")
	}
	if v.audience == "" {
		cancel()
		return nil, fmt.Errorf("cbox-id-jwks-auth: WithAudience is required")
	}
	if v.jwksURI == "" {
		cancel()
		return nil, fmt.Errorf("cbox-id-jwks-auth: WithJWKSURI is required")
	}

	cache := jwk.NewCache(cacheCtx)
	if err := cache.Register(v.jwksURI,
		jwk.WithMinRefreshInterval(15*time.Minute),
		jwk.WithRefreshInterval(1*time.Hour),
	); err != nil {
		cancel()
		return nil, fmt.Errorf("cbox-id-jwks-auth: register JWKS cache: %w", err)
	}
	v.jwksCache = cache

	return v, nil
}

// Close releases the validator's background JWKS-refresher. Safe
// to call multiple times and from multiple goroutines. After Close
// the validator MUST NOT be used; in-flight Validate calls may
// observe jwks_unavailable errors as the underlying http requests
// abort.
func (v *Validator) Close() {
	if v.cancel != nil {
		v.cancel()
	}
}

// Validate parses tokenString as a JWT, verifies its signature
// against the JWKS, and checks iss / aud / exp / nbf. Returns
// (*Claims, nil) on success, (nil, *InvalidTokenError) on any
// validation failure.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	keyset, err := v.loadKeyset(ctx)
	if err != nil {
		return nil, err
	}

	parsed, parseErr := v.parseAndVerify(tokenString, keyset)
	if parseErr != nil {
		// Kid-miss / signature-failure refresh: id may have rotated
		// keys between the cache's last refresh interval (default
		// 1h) and this token. Force a single refresh and retry —
		// matches the PHP pendant's `loadJwks(forceRefresh: true)`
		// fallback. Avoid infinite refresh storms by retrying
		// exactly once.
		if shouldRefreshOnError(parseErr) {
			if refreshed, refreshErr := v.refreshAndGet(ctx); refreshErr == nil {
				if reparsed, reErr := v.parseAndVerify(tokenString, refreshed); reErr == nil {
					return v.finishParsed(reparsed)
				} else {
					return nil, classifyParseError(reErr)
				}
			}
		}
		return nil, classifyParseError(parseErr)
	}

	return v.finishParsed(parsed)
}

func (v *Validator) parseAndVerify(tokenString string, keyset jwk.Set) (jwt.Token, error) {
	// jwt.Parse runs signature → iat/exp/nbf (skew-tolerant) → iss/aud.
	return jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(keyset),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithAcceptableSkew(v.clockSkew),
		jwt.WithClock(jwt.ClockFunc(v.now)),
	)
}

func (v *Validator) finishParsed(parsed jwt.Token) (*Claims, error) {
	// SECURITY: lestrrat's jwt.Parse silently accepts a token
	// that omits `exp` — the validator runs only when the claim
	// is present. We REQUIRE `exp` so a forged token without an
	// expiry can't be accepted as never-expiring. PHP's pendant
	// (`cbox-id-jwks-auth/src/JwksValidator.php::checkExpiry`)
	// does the same; this keeps the two languages symmetrical.
	if parsed.Expiration().IsZero() {
		return nil, &InvalidTokenError{
			Reason:  "missing_exp",
			Message: "token is missing the exp claim",
		}
	}

	return claimsFromJWT(parsed), nil
}

// loadKeyset returns the live JWKS, with stale-file fallback when
// the live source is unreachable. Also persists the live keyset
// after a good fetch when WithStaleFallbackPath was supplied so the
// next cold start has something to read.
func (v *Validator) loadKeyset(ctx context.Context) (jwk.Set, error) {
	keyset, err := v.jwksCache.Get(ctx, v.jwksURI)
	if err == nil {
		v.persistStale(keyset)
		filtered, fErr := filterWeakRSA(keyset)
		if fErr != nil {
			return nil, &InvalidTokenError{
				Reason:  "jwks_unavailable",
				Message: "JWKS contained no usable keys: " + fErr.Error(),
				Err:     fErr,
			}
		}
		return filtered, nil
	}

	// Live fetch failed — try the on-disk fallback.
	if v.staleFallbackPath != "" {
		if stale, sErr := v.readStale(); sErr == nil {
			filtered, fErr := filterWeakRSA(stale)
			if fErr == nil {
				return filtered, nil
			}
		}
	}

	return nil, &InvalidTokenError{
		Reason:  "jwks_unavailable",
		Message: "fetch JWKS: " + err.Error(),
		Err:     err,
	}
}

// refreshAndGet forces a JWKS refresh and returns the freshly-
// fetched keyset. Used by the kid-miss / signature-failure retry
// path so a token signed with a just-rotated key validates as soon
// as id has published the new JWK, instead of waiting up to one
// jwk.Cache refresh interval.
func (v *Validator) refreshAndGet(ctx context.Context) (jwk.Set, error) {
	if _, err := v.jwksCache.Refresh(ctx, v.jwksURI); err != nil {
		return nil, err
	}
	keyset, err := v.jwksCache.Get(ctx, v.jwksURI)
	if err != nil {
		return nil, err
	}
	v.persistStale(keyset)
	return filterWeakRSA(keyset)
}

// shouldRefreshOnError returns true for parse errors that suggest
// the live keyset is out of date — most importantly key not found
// (post-rotation token) and signature mismatch (key changed under us).
// Other reasons (bad iss, expired) are about the token, not the key,
// so we don't burn an extra refresh on them.
func shouldRefreshOnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "could not find matching key") ||
		strings.Contains(msg, "no matching key") ||
		strings.Contains(msg, "failed to find key") ||
		strings.Contains(msg, "signature") ||
		strings.Contains(msg, "verification")
}

// persistStale writes the current keyset to the on-disk fallback,
// if configured. Best-effort: write failures are logged-and-ignored
// so a missing /var directory or full disk doesn't fail validation.
func (v *Validator) persistStale(keyset jwk.Set) {
	if v.staleFallbackPath == "" {
		return
	}
	v.stalePersistOnce.Lock()
	defer v.stalePersistOnce.Unlock()

	buf, err := json.Marshal(keyset)
	if err != nil {
		return
	}
	dir := filepath.Dir(v.staleFallbackPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp := v.staleFallbackPath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, v.staleFallbackPath)
}

// readStale reads the on-disk fallback keyset, parses it, and
// returns it. Returns an error if the file doesn't exist, can't be
// read, or doesn't parse as a JWKS.
func (v *Validator) readStale() (jwk.Set, error) {
	if v.staleFallbackPath == "" {
		return nil, errors.New("no stale fallback path configured")
	}
	data, err := os.ReadFile(v.staleFallbackPath)
	if err != nil {
		return nil, err
	}
	return jwk.Parse(data)
}

// filterWeakRSA removes RSA keys with a modulus below 2048 bits.
// Returns an error if the resulting set is empty — better to fail
// loud than to silently accept a JWKS that contains only weak keys.
func filterWeakRSA(in jwk.Set) (jwk.Set, error) {
	out := jwk.NewSet()
	ctx := context.Background()
	for it := in.Keys(ctx); it.Next(ctx); {
		pair := it.Pair()
		key, ok := pair.Value.(jwk.Key)
		if !ok {
			continue
		}
		if !isAcceptableKey(key) {
			continue
		}
		_ = out.AddKey(key)
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("JWKS has no keys >= %d bits", minRSAModulusBytes*8)
	}
	return out, nil
}

func isAcceptableKey(key jwk.Key) bool {
	if key.KeyType() != "RSA" {
		// Non-RSA keys (EC, OKP) ride through; their security is
		// governed by the curve, not modulus size.
		return true
	}
	rsaKey, ok := key.(jwk.RSAPublicKey)
	if !ok {
		return false
	}
	if len(rsaKey.N()) < minRSAModulusBytes {
		return false
	}
	return true
}

// classifyParseError maps lestrrat's typed validation errors to
// our stable Reason codes. lestrrat's messages quote the claim
// name (e.g. `"exp" not satisfied`), so we match against those
// canonical forms. Variants surface as either `not satisfied`
// (claim is present but doesn't match) or `not found` (claim is
// absent — same intent on our side, since both mean "won't validate
// against the configured iss/aud").
func classifyParseError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, `"exp" not satisfied`),
		strings.Contains(msg, "token is expired"),
		strings.Contains(msg, "exp not satisfied"):
		return &InvalidTokenError{Reason: "expired", Message: msg, Err: err}
	case strings.Contains(msg, `"nbf" not satisfied`),
		strings.Contains(msg, "token is not yet valid"),
		strings.Contains(msg, "nbf not satisfied"):
		return &InvalidTokenError{Reason: "not_yet_valid", Message: msg, Err: err}
	case strings.Contains(msg, `"iss" not satisfied`),
		strings.Contains(msg, "iss not satisfied"),
		strings.Contains(msg, `"iss" not found`),
		strings.Contains(msg, "iss not found"):
		return &InvalidTokenError{Reason: "wrong_issuer", Message: msg, Err: err}
	case strings.Contains(msg, `"aud" not satisfied`),
		strings.Contains(msg, "aud not satisfied"),
		strings.Contains(msg, `"aud" not found`),
		strings.Contains(msg, "aud not found"):
		return &InvalidTokenError{Reason: "wrong_audience", Message: msg, Err: err}
	case strings.Contains(msg, "could not find matching key"),
		strings.Contains(msg, "no matching key"),
		strings.Contains(msg, "failed to find key"):
		return &InvalidTokenError{Reason: "unknown_kid", Message: msg, Err: err}
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
