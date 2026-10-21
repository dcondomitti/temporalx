// Package codecserver serves the Temporal codec-server HTTP contract so the
// Cloud UI and CLI can show a namespace's payloads decoded.
//
// The namespace stores ciphertext. The UI, running at
// https://cloud.temporal.io in a browser, POSTs each payload here with the
// user's Temporal Cloud access token and expects plaintext back. So this is
// the one handler that both holds a keyring and faces a browser, and it is
// gated accordingly: CORS pinned to one origin, a signed JWT from the issuer
// on every request, the email inside it on an allowlist, and X-Namespace
// limited to the namespaces the keyring is for. Serve it over HTTPS only.
package codecserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.temporal.io/sdk/converter"
)

// TemporalCloudIssuer is where the Cloud UI's access tokens come from.
const TemporalCloudIssuer = "https://login.tmprl.cloud/"

// TemporalCloudUIOrigin is the browser origin the Cloud UI calls from.
const TemporalCloudUIOrigin = "https://cloud.temporal.io"

// TokenVerifier checks a raw bearer token and returns its claims.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*oidc.IDToken, error)
}

// NewVerifier discovers the issuer's keys and returns a verifier for its
// access tokens. The audience is not pinned: Temporal does not document it,
// and the email allowlist is the authorisation decision anyway.
func NewVerifier(ctx context.Context, issuer string) (TokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("codecserver: oidc discovery for %s: %w", issuer, err)
	}
	return provider.Verifier(&oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.PS256},
	}), nil
}

// Config is the handler's policy. Build it through Handler's options.
type Config struct {
	// Namespaces this handler decodes for. Required, at least one.
	Namespaces []string
	// AllowedEmails may decode. Required, at least one. The namespace's own
	// RBAC in Cloud is not consulted; this list is the decision.
	AllowedEmails []string
	// CORSOrigin is the single browser origin allowed. Defaults to the
	// Cloud UI.
	CORSOrigin string
	// Logger for refusals. Values that could identify a token are never
	// logged; claim names are, so an unexpected token shape can be diagnosed.
	Logger *slog.Logger
}

// Option adjusts a Config.
type Option func(*Config)

// WithNamespaces sets the namespaces served.
func WithNamespaces(ns ...string) Option {
	return func(c *Config) { c.Namespaces = append(c.Namespaces, ns...) }
}

// WithAllowedEmails sets who may decode.
func WithAllowedEmails(emails ...string) Option {
	return func(c *Config) { c.AllowedEmails = append(c.AllowedEmails, emails...) }
}

// WithCORSOrigin replaces the allowed browser origin.
func WithCORSOrigin(origin string) Option { return func(c *Config) { c.CORSOrigin = origin } }

// WithLogger sets the refusal logger.
func WithLogger(l *slog.Logger) Option { return func(c *Config) { c.Logger = l } }

// Handler returns the HTTP handler. Routes, relative to wherever it is
// mounted (use http.StripPrefix for a prefix):
//
//	POST /decode, POST /encode  -- the codec contract, authenticated
//	GET  /health                -- liveness, open
func Handler(codec converter.PayloadCodec, verifier TokenVerifier, opts ...Option) (http.Handler, error) {
	if codec == nil || verifier == nil {
		return nil, errors.New("codecserver: codec and verifier are required")
	}
	cfg := Config{CORSOrigin: TemporalCloudUIOrigin, Logger: slog.Default()}
	for _, o := range opts {
		o(&cfg)
	}
	namespaces := set(cfg.Namespaces)
	emails := set(cfg.AllowedEmails)
	if len(namespaces) == 0 || len(emails) == 0 {
		return nil, errors.New("codecserver: at least one namespace and one allowed email are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	contract := converter.NewPayloadCodecHTTPHandler(codec)

	authed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		ns := r.Header.Get("X-Namespace")
		if _, ok := namespaces[strings.ToLower(ns)]; !ok {
			cfg.Logger.Warn("codec: refused namespace", "namespace", ns, "path", r.URL.Path)
			http.Error(w, "namespace not served here", http.StatusForbidden)
			return
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			http.Error(w, "bearer token required", http.StatusUnauthorized)
			return
		}
		tok, err := verifier.Verify(r.Context(), raw)
		if err != nil {
			cfg.Logger.Warn("codec: token rejected", "error", err.Error())
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		email, claimNames := emailOf(tok)
		if _, ok := emails[strings.ToLower(email)]; !ok {
			cfg.Logger.Warn("codec: email not allowed", "email", email, "claims", claimNames, "namespace", ns)
			http.Error(w, "not allowed", http.StatusForbidden)
			return
		}
		contract.ServeHTTP(w, r)
	})

	mux := http.NewServeMux()
	mux.Handle("/decode", authed)
	mux.Handle("/encode", authed)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return cors(cfg.CORSOrigin, mux), nil
}

// cors answers the browser's preflight and marks responses for the one
// allowed origin. Credentials are not allowed: the token travels in the
// Authorization header, so cookies have no part in this.
func cors(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Namespace")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// emailOf finds the email claim. Temporal's token carries it as "email"; the
// fallback accepts a namespaced claim ending in "/email", which is how Auth0
// tenants that customise claims tend to spell it. The claim names are
// returned for the refusal log, never the values.
func emailOf(tok *oidc.IDToken) (string, []string) {
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return "", nil
	}
	names := make([]string, 0, len(claims))
	for k := range claims {
		names = append(names, k)
	}
	if v, ok := claims["email"].(string); ok && v != "" {
		return v, names
	}
	for k, v := range claims {
		if s, ok := v.(string); ok && strings.HasSuffix(k, "/email") && s != "" {
			return s, names
		}
	}
	return "", names
}

func set(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			m[strings.ToLower(x)] = struct{}{}
		}
	}
	return m
}
