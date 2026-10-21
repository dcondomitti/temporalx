package codecserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"

	"github.com/dcondomitti/temporalx"
)

// issuer is a throwaway OIDC provider: discovery document, JWKS, and a way to
// mint tokens signed by its key. Stands in for login.tmprl.cloud.
type issuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                is.srv.URL,
			"jwks_uri":                              is.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: is.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]any{
		"iss": is.srv.URL, "sub": "user", "aud": "whatever",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		all[k] = v
	}
	payload, _ := json.Marshal(all)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newServer(t *testing.T, is *issuer) (*httptest.Server, converter.PayloadCodec) {
	t.Helper()
	keyBytes := make([]byte, temporalx.KeySize)
	_, _ = rand.Read(keyBytes)
	keys, err := temporalx.ParseKeyring("t="+base64.StdEncoding.EncodeToString(keyBytes), "")
	if err != nil {
		t.Fatal(err)
	}
	codec := temporalx.NewCodec(keys)
	verifier, err := NewVerifier(context.Background(), is.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Handler(codec, verifier,
		WithNamespaces("example.test"),
		WithAllowedEmails("Pilot@Example.com"),
		WithLogger(slog.New(slog.NewTextHandler(testWriter{t}, nil))),
	)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, codec
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// decodeRequest builds what the Cloud UI sends: the sealed payloads, JSON,
// with the namespace header and the user's token.
func decodeRequest(t *testing.T, url string, codec converter.PayloadCodec, token, namespace string) *http.Request {
	t.Helper()
	sealed, err := codec.Encode([]*commonpb.Payload{{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     []byte(`"n12345"`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(&commonpb.Payloads{Payloads: sealed})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, url+"/decode", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if namespace != "" {
		req.Header.Set("X-Namespace", namespace)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestDecodeForAnAllowedUser(t *testing.T) {
	is := newIssuer(t)
	srv, codec := newServer(t, is)

	resp := do(t, decodeRequest(t, srv.URL, codec, is.token(t, map[string]any{"email": "pilot@example.com"}), "example.test"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out commonpb.Payloads
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Payloads) != 1 || string(out.Payloads[0].Data) != `"n12345"` {
		t.Errorf("decoded %v", out.Payloads)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != TemporalCloudUIOrigin {
		t.Errorf("CORS origin %q", got)
	}
}

func TestRefusals(t *testing.T) {
	is := newIssuer(t)
	srv, codec := newServer(t, is)
	other := newIssuer(t) // same shape, different key: a forged token
	ok := map[string]any{"email": "pilot@example.com"}

	cases := []struct {
		name      string
		token     string
		namespace string
		want      int
	}{
		{"no token", "", "example.test", http.StatusUnauthorized},
		{"token from another issuer", other.token(t, ok), "example.test", http.StatusUnauthorized},
		{"expired", is.token(t, map[string]any{"email": "pilot@example.com", "exp": time.Now().Add(-time.Minute).Unix()}), "example.test", http.StatusUnauthorized},
		{"email not allowed", is.token(t, map[string]any{"email": "stranger@example.com"}), "example.test", http.StatusForbidden},
		{"no email claim", is.token(t, nil), "example.test", http.StatusForbidden},
		{"wrong namespace", is.token(t, ok), "someone-else.test", http.StatusForbidden},
		{"no namespace", is.token(t, ok), "", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if resp := do(t, decodeRequest(t, srv.URL, codec, c.token, c.namespace)); resp.StatusCode != c.want {
				t.Errorf("status %d, want %d", resp.StatusCode, c.want)
			}
		})
	}
}

func TestNamespacedEmailClaimIsAccepted(t *testing.T) {
	is := newIssuer(t)
	srv, codec := newServer(t, is)
	tok := is.token(t, map[string]any{"https://example.com/email": "pilot@example.com"})
	if resp := do(t, decodeRequest(t, srv.URL, codec, tok, "example.test")); resp.StatusCode != http.StatusOK {
		t.Errorf("status %d", resp.StatusCode)
	}
}

func TestPreflightAndHealthNeedNoToken(t *testing.T) {
	is := newIssuer(t)
	srv, _ := newServer(t, is)

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/decode", nil)
	req.Header.Set("Origin", TemporalCloudUIOrigin)
	req.Header.Set("Access-Control-Request-Headers", "authorization,x-namespace,content-type")
	resp := do(t, req)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status %d", resp.StatusCode)
	}
	for _, h := range []string{"Authorization", "X-Namespace", "Content-Type"} {
		if !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), h) {
			t.Errorf("preflight does not allow %s: %q", h, resp.Header.Get("Access-Control-Allow-Headers"))
		}
	}
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	if resp := do(t, req); resp.StatusCode != http.StatusOK {
		t.Errorf("health status %d", resp.StatusCode)
	}
}

func TestHandlerRequiresPolicy(t *testing.T) {
	is := newIssuer(t)
	verifier, _ := NewVerifier(context.Background(), is.srv.URL)
	keyBytes := make([]byte, temporalx.KeySize)
	keys, _ := temporalx.NewKeyring("k", map[string][]byte{"k": keyBytes})
	if _, err := Handler(temporalx.NewCodec(keys), verifier, WithNamespaces("x")); err == nil {
		t.Error("accepted a handler with no allowed emails")
	}
	if _, err := Handler(temporalx.NewCodec(keys), verifier, WithAllowedEmails("a@b")); err == nil {
		t.Error("accepted a handler with no namespaces")
	}
	if _, err := Handler(nil, verifier, WithNamespaces("x"), WithAllowedEmails("a@b")); err == nil {
		t.Error("accepted a nil codec")
	}
}
