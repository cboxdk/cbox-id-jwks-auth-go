package cboxidjwksauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cboxidjwksauth "github.com/cboxdk/cbox-id-jwks-auth-go"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	testIssuer   = "https://id.test"
	testAudience = "vault.cbox.systems"
)

// signer wraps an RSA keypair + kid so tests can mint JWTs that
// match a JWKS doc serving the public half.
type signer struct {
	private *rsa.PrivateKey
	public  jwk.Key
	kid     string
}

func newSigner(t *testing.T, kid string) *signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	return &signer{private: priv, public: pub, kid: kid}
}

func (s *signer) mintToken(t *testing.T, opts ...func(jwt.Token)) string {
	t.Helper()
	now := time.Now()

	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, testIssuer)
	_ = tok.Set(jwt.AudienceKey, []string{testAudience})
	_ = tok.Set(jwt.SubjectKey, "vault-prod")
	_ = tok.Set(jwt.IssuedAtKey, now)
	_ = tok.Set(jwt.NotBeforeKey, now)
	_ = tok.Set(jwt.ExpirationKey, now.Add(10*time.Minute))

	for _, opt := range opts {
		opt(tok)
	}

	signed, err := jwt.Sign(tok,
		jwt.WithKey(jwa.RS256, s.private, jws.WithProtectedHeaders(headerWithKid(s.kid))),
	)
	if err != nil {
		t.Fatalf("jwt.Sign: %v", err)
	}
	return string(signed)
}

func headerWithKid(kid string) jws.Headers {
	h := jws.NewHeaders()
	_ = h.Set(jws.KeyIDKey, kid)
	return h
}

// jwksServer returns an httptest server that serves the given
// signers' public keys at /.well-known/jwks.json.
func jwksServer(t *testing.T, signers ...*signer) *httptest.Server {
	t.Helper()
	set := jwk.NewSet()
	for _, s := range signers {
		_ = set.AddKey(s.public)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/.well-known/jwks.json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newValidator(t *testing.T, jwksURI string, opts ...cboxidjwksauth.Option) *cboxidjwksauth.Validator {
	t.Helper()
	base := []cboxidjwksauth.Option{
		cboxidjwksauth.WithIssuer(testIssuer),
		cboxidjwksauth.WithAudience(testAudience),
		cboxidjwksauth.WithJWKSURI(jwksURI),
	}
	v, err := cboxidjwksauth.New(t.Context(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("cboxidjwksauth.New: %v", err)
	}
	return v
}

func TestValidatesGoodToken(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set("scopes", []any{"id.audit.write"})
	})

	claims, err := v.Validate(t.Context(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if claims.Subject != "vault-prod" {
		t.Errorf("Subject = %q, want vault-prod", claims.Subject)
	}
	if claims.Issuer != testIssuer {
		t.Errorf("Issuer = %q", claims.Issuer)
	}
	if !slicesContains(claims.Audience, testAudience) {
		t.Errorf("Audience = %v, want includes %q", claims.Audience, testAudience)
	}
	if !claims.HasScope("id.audit.write") {
		t.Errorf("HasScope: missing id.audit.write")
	}
}

func TestRejectsTokenSignedByUnknownKey(t *testing.T) {
	publishedSigner := newSigner(t, "published-kid")
	attackerSigner := newSigner(t, "published-kid") // same kid, different key

	srv := jwksServer(t, publishedSigner)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := attackerSigner.mintToken(t)

	_, err := v.Validate(t.Context(), token)
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) {
		t.Fatalf("expected *InvalidTokenError, got %T (%v)", err, err)
	}
	if ite.Reason != "bad_signature" && ite.Reason != "malformed" {
		t.Errorf("Reason = %q, want bad_signature or malformed", ite.Reason)
	}
}

func TestRejectsTokenWithUnknownKid(t *testing.T) {
	s := newSigner(t, "real-kid")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	otherSigner := newSigner(t, "different-kid")
	token := otherSigner.mintToken(t)

	_, err := v.Validate(t.Context(), token)
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) {
		t.Fatalf("expected *InvalidTokenError, got %T", err)
	}
}

func TestRejectsTokenWithWrongIssuer(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set(jwt.IssuerKey, "https://attacker.example")
	})

	_, err := v.Validate(t.Context(), token)
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) || ite.Reason != "wrong_issuer" {
		t.Fatalf("expected wrong_issuer, got %v", err)
	}
}

func TestRejectsTokenWithWrongAudience(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set(jwt.AudienceKey, []string{"some-other-service.cbox.systems"})
	})

	_, err := v.Validate(t.Context(), token)
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) || ite.Reason != "wrong_audience" {
		t.Fatalf("expected wrong_audience, got %v", err)
	}
}

func TestAcceptsArrayAudienceContainingValue(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set(jwt.AudienceKey, []string{"third-party", testAudience, "another"})
	})

	claims, err := v.Validate(t.Context(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !slicesContains(claims.Audience, testAudience) {
		t.Errorf("Audience missing %q: %v", testAudience, claims.Audience)
	}
}

func TestRejectsTokenWithoutExpClaim(t *testing.T) {
	// SECURITY: lestrrat's jwt.Parse skips exp validation when
	// the claim is absent. We require exp so an attacker can't
	// forge a never-expiring token by omitting the claim.
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	// Mint a token with NO exp claim by using jws.Sign directly
	// to avoid jwt.Sign's auto-default behaviours, then assert
	// validation rejects it.
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, testIssuer)
	_ = tok.Set(jwt.AudienceKey, []string{testAudience})
	_ = tok.Set(jwt.SubjectKey, "no-exp-attacker")
	_ = tok.Set(jwt.IssuedAtKey, time.Now())
	_ = tok.Set(jwt.NotBeforeKey, time.Now())
	// no exp set

	signed, err := jwt.Sign(tok,
		jwt.WithKey(jwa.RS256, s.private, jws.WithProtectedHeaders(headerWithKid(s.kid))),
	)
	if err != nil {
		t.Fatalf("jwt.Sign: %v", err)
	}

	_, err = v.Validate(t.Context(), string(signed))
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) {
		t.Fatalf("expected *InvalidTokenError, got %T (%v)", err, err)
	}
	if ite.Reason != "missing_exp" {
		t.Errorf("Reason = %q, want missing_exp", ite.Reason)
	}
}

func TestRejectsExpiredToken(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	now := time.Now()
	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set(jwt.IssuedAtKey, now.Add(-2*time.Hour))
		_ = tok.Set(jwt.NotBeforeKey, now.Add(-2*time.Hour))
		_ = tok.Set(jwt.ExpirationKey, now.Add(-1*time.Hour))
	})

	_, err := v.Validate(t.Context(), token)
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) || ite.Reason != "expired" {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestParsesCustomClaims(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set(jwt.SubjectKey, "42")
		_ = tok.Set("platform_roles", []any{"staff", "super_admin"})
		_ = tok.Set("oid", "org-slug")
	})

	claims, err := v.Validate(t.Context(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if got := claims.Custom["oid"]; got != "org-slug" {
		t.Errorf("Custom[oid] = %v, want org-slug", got)
	}

	roles, ok := claims.Custom["platform_roles"].([]any)
	if !ok {
		t.Fatalf("platform_roles missing or wrong type: %T", claims.Custom["platform_roles"])
	}
	if len(roles) != 2 || roles[0] != "staff" || roles[1] != "super_admin" {
		t.Errorf("platform_roles = %v", roles)
	}
}

func TestRejectsMalformedToken(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	_, err := v.Validate(t.Context(), "not-a-jwt")
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) {
		t.Fatalf("expected *InvalidTokenError, got %T", err)
	}
}

func TestNewRequiresIssuerAudienceJWKSURI(t *testing.T) {
	cases := []struct {
		name string
		opts []cboxidjwksauth.Option
	}{
		{"no issuer", []cboxidjwksauth.Option{
			cboxidjwksauth.WithAudience(testAudience),
			cboxidjwksauth.WithJWKSURI("https://x"),
		}},
		{"no audience", []cboxidjwksauth.Option{
			cboxidjwksauth.WithIssuer(testIssuer),
			cboxidjwksauth.WithJWKSURI("https://x"),
		}},
		{"no jwks uri", []cboxidjwksauth.Option{
			cboxidjwksauth.WithIssuer(testIssuer),
			cboxidjwksauth.WithAudience(testAudience),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cboxidjwksauth.New(t.Context(), tc.opts...)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestMiddlewareLetsGoodTokenThrough(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set("scopes", []any{"id.audit.write"})
	})

	var captured *cboxidjwksauth.Claims
	handler := cboxidjwksauth.Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = cboxidjwksauth.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if captured == nil {
		t.Fatalf("captured claims missing")
	}
	if !captured.HasScope("id.audit.write") {
		t.Errorf("missing scope on context")
	}
}

func TestMiddleware401WhenAuthHeaderMissing(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	handler := cboxidjwksauth.Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("downstream handler must not run")
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), `"invalid_token"`) {
		t.Errorf("body missing invalid_token: %s", body)
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("missing WWW-Authenticate challenge")
	}
}

func TestMiddleware403OnMissingRequiredScope(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set("scopes", []any{"id.audit.write"})
	})

	handler := cboxidjwksauth.Middleware(v,
		cboxidjwksauth.WithRequiredScope("id.usage.write"),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("downstream handler must not run")
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), `"insufficient_scope"`) {
		t.Errorf("body missing insufficient_scope: %s", body)
	}
}

func TestMiddlewarePassesWhenRequiredScopePresent(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	token := s.mintToken(t, func(tok jwt.Token) {
		_ = tok.Set("scopes", []any{"id.audit.write", "id.usage.write"})
	})

	called := false
	handler := cboxidjwksauth.Middleware(v,
		cboxidjwksauth.WithRequiredScope("id.usage.write"),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)

	if !called {
		t.Errorf("downstream handler did not run")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// slicesContains is a tiny helper to keep test reads obvious;
// avoids pulling slices import for one call.
func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// rotatingJwksServer serves a JWKS that the test can swap at
// runtime. Used to exercise the kid-miss force-refresh path.
type rotatingJwksServer struct {
	*httptest.Server
	mu  func(set jwk.Set) // setter (closes over a pointer)
	hit *int32
}

func newRotatingJwksServer(t *testing.T, initial ...*signer) (*httptest.Server, func(...*signer)) {
	t.Helper()
	current := jwk.NewSet()
	for _, s := range initial {
		_ = current.AddKey(s.public)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/.well-known/jwks.json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(current)
	}))
	t.Cleanup(srv.Close)
	swap := func(signers ...*signer) {
		ns := jwk.NewSet()
		for _, s := range signers {
			_ = ns.AddKey(s.public)
		}
		current = ns
	}
	return srv, swap
}

func TestKidMissRefreshPicksUpRotatedKey(t *testing.T) {
	old := newSigner(t, "old-kid")
	srv, swap := newRotatingJwksServer(t, old)

	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	// Warm cache with the original keyset.
	if _, err := v.Validate(t.Context(), old.mintToken(t)); err != nil {
		t.Fatalf("warm validate: %v", err)
	}

	// id rotates: old key out, new key in. The cache hasn't refreshed
	// (its interval is hours), but the validator's kid-miss path
	// should force a refresh and re-validate the freshly-issued
	// token transparently.
	rotated := newSigner(t, "rotated-kid")
	swap(rotated)

	token := rotated.mintToken(t)
	claims, err := v.Validate(t.Context(), token)
	if err != nil {
		t.Fatalf("post-rotation Validate: %v", err)
	}
	if claims.Subject != "vault-prod" {
		t.Errorf("Subject = %q", claims.Subject)
	}
}

func TestKidMissRefreshDoesNotLoopOnGenuineUnknownKid(t *testing.T) {
	publishedSigner := newSigner(t, "published-kid")
	srv, _ := newRotatingJwksServer(t, publishedSigner)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	// Mint a token with a kid that's NEVER in the JWKS. The retry
	// path will refresh once, see the same keyset, and surface
	// reason=unknown_kid (or bad_signature/malformed) — never
	// retries indefinitely. We assert the call returns within a
	// short timeout, not that it spins.
	otherSigner := newSigner(t, "drift-kid")
	token := otherSigner.mintToken(t)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := v.Validate(ctx, token)
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) {
		t.Fatalf("expected *InvalidTokenError, got %T (%v)", err, err)
	}
}

func TestStaleFallbackPathBootsValidatorWhenIDIsDownAtStartup(t *testing.T) {
	s := newSigner(t, "kid-1")

	// Phase 1: id is up. A first validator persists the JWKS to disk.
	upSrv, _ := newRotatingJwksServer(t, s)
	jwksURI := upSrv.URL + "/.well-known/jwks.json"

	staleFile := t.TempDir() + "/jwks.json"

	v1 := newValidator(t, jwksURI, cboxidjwksauth.WithStaleFallbackPath(staleFile))
	if _, err := v1.Validate(t.Context(), s.mintToken(t)); err != nil {
		t.Fatalf("phase 1 Validate: %v", err)
	}
	v1.Close()
	upSrv.Close()

	// Phase 2: id is down. A fresh validator pointing at a dead URL
	// + the same fallback path bootstraps from the stale file and
	// validates a freshly-minted token signed with the original key.
	deadURL := "http://127.0.0.1:1/.well-known/jwks.json"

	v2, err := cboxidjwksauth.New(t.Context(),
		cboxidjwksauth.WithIssuer(testIssuer),
		cboxidjwksauth.WithAudience(testAudience),
		cboxidjwksauth.WithJWKSURI(deadURL),
		cboxidjwksauth.WithStaleFallbackPath(staleFile),
	)
	if err != nil {
		t.Fatalf("phase 2 New: %v", err)
	}
	defer v2.Close()

	if _, err := v2.Validate(t.Context(), s.mintToken(t)); err != nil {
		t.Fatalf("phase 2 Validate (stale fallback): %v", err)
	}
}

func TestValidatorCloseIsIdempotent(t *testing.T) {
	s := newSigner(t, "kid-1")
	srv := jwksServer(t, s)
	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	v.Close()
	v.Close() // must not panic / double-cancel
}

func TestValidatorRejectsWeakRSAKeysInJWKS(t *testing.T) {
	// Generate a 1024-bit key, hand-publish via JWKS doc.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = pub.Set(jwk.KeyIDKey, "weak-kid")
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)

	set := jwk.NewSet()
	_ = set.AddKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)

	v := newValidator(t, srv.URL+"/.well-known/jwks.json")

	// Mint a token signed with the weak key. The validator should
	// reject because the JWKS doc contained no acceptable keys.
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, testIssuer)
	_ = tok.Set(jwt.AudienceKey, []string{testAudience})
	_ = tok.Set(jwt.SubjectKey, "attacker")
	_ = tok.Set(jwt.IssuedAtKey, time.Now())
	_ = tok.Set(jwt.NotBeforeKey, time.Now())
	_ = tok.Set(jwt.ExpirationKey, time.Now().Add(10*time.Minute))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, priv, jws.WithProtectedHeaders(headerWithKid("weak-kid"))))
	if err != nil {
		t.Fatalf("jwt.Sign: %v", err)
	}

	_, err = v.Validate(t.Context(), string(signed))
	var ite *cboxidjwksauth.InvalidTokenError
	if !errors.As(err, &ite) {
		t.Fatalf("expected *InvalidTokenError, got %T (%v)", err, err)
	}
	if ite.Reason != "jwks_unavailable" {
		t.Errorf("Reason = %q, want jwks_unavailable (weak-only JWKS should fail loud)", ite.Reason)
	}
}

// silence unused-import warning if we ever drop the helper.
var _ = context.Background
var _ = fmt.Sprintf
