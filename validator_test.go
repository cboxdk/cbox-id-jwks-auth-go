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

// silence unused-import warning if we ever drop the helper.
var _ = context.Background
var _ = fmt.Sprintf
