# cbox-id-jwks-auth-go

Go counterpart of the PHP [`cboxdk/cbox-id-jwks-auth`](https://github.com/cboxdk/cbox-id-jwks-auth)
package. JWKS-only validator + `http.Handler` middleware for resource servers
consuming Cbox id-issued JWTs. Implements the validation half of
[`cbox-infra/docs/SERVICE_AUTH.md`](https://github.com/cboxdk/cbox-infra/blob/main/docs/SERVICE_AUTH.md).

Pair with [`cboxdk/cbox-id-tokens-go`](https://github.com/cboxdk/cbox-id-tokens-go)
when a service needs to both MINT id-issued tokens AND VALIDATE them.

## Why

High-volume gateways (vault, OTel-gw, future managed services) can't afford a
roundtrip to id on every request. This validator caches id's JWKS aggressively
via `lestrrat-go/jwx`'s `jwk.Cache`, validates JWTs locally, and tolerates
id-down because the cache holds last-good keys for the configured refresh
interval.

Revocation is **not** honoured by JWKS-only validation — the 10-minute access-
token TTL is the v1 mitigation; a distributed revocation feed is on the roadmap.

## Install

```bash
go get github.com/cboxdk/cbox-id-jwks-auth-go
```

## Use — middleware

```go
import (
    "context"
    "net/http"

    cboxidjwksauth "github.com/cboxdk/cbox-id-jwks-auth-go"
)

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

validator, err := cboxidjwksauth.New(ctx,
    cboxidjwksauth.WithIssuer("https://id.cbox.systems"),
    cboxidjwksauth.WithAudience("vault.cbox.systems"),
    cboxidjwksauth.WithJWKSURI("https://id.cbox.systems/.well-known/jwks.json"),
)
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()

// Base validation only.
mux.Handle("/api/v1/audit",
    cboxidjwksauth.Middleware(validator)(auditHandler))

// Per-route required scope:
mux.Handle("/api/v1/audit/events",
    cboxidjwksauth.Middleware(validator,
        cboxidjwksauth.WithRequiredScope("id.audit.write"),
    )(auditEventsHandler))
```

The middleware stashes validated claims on `r.Context()`:

```go
func auditHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := cboxidjwksauth.ClaimsFromContext(r.Context())
    if !ok {
        http.Error(w, "no claims", http.StatusInternalServerError)
        return
    }
    log.Printf("authed sub=%s scopes=%v", claims.Subject, claims.Scopes)
}
```

Failure modes follow the OAuth 2.0 RFC:

- **401 invalid_token** — missing token, malformed, bad signature, expired,
  wrong issuer, wrong audience, unknown kid
- **403 insufficient_scope** — token valid but missing the required scope

WWW-Authenticate challenges are populated per RFC 6750.

## Use — Validator directly

For non-HTTP contexts (WebSocket handshake, gRPC interceptors, queue jobs):

```go
claims, err := validator.Validate(ctx, tokenString)
if err != nil {
    var ite *cboxidjwksauth.InvalidTokenError
    if errors.As(err, &ite) {
        log.Printf("invalid token: reason=%s msg=%s", ite.Reason, ite.Message)
    }
    return err
}
if !claims.HasScope("id.audit.write") {
    return errors.New("insufficient scope")
}
```

## Errors

- `*InvalidTokenError` — wraps validation failures with a stable `Reason`
  code (`malformed`, `missing_kid`, `unknown_kid`, `bad_signature`,
  `wrong_issuer`, `wrong_audience`, `expired`, `not_yet_valid`,
  `jwks_unavailable`)
- `*InsufficientScopeError` — only used by callers that need explicit scope
  checking outside the middleware

Use `errors.As(err, &ite)` to inspect.

## License

MIT
