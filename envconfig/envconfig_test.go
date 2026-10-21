package envconfig

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"testing"
)

func env(m map[string]string) Option { return WithLookup(func(k string) string { return m[k] }) }

func key() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestLoad(t *testing.T) {
	if _, configured, err := Load(env(nil)); configured || err != nil {
		t.Errorf("no hostname should read as not configured: %v %v", configured, err)
	}
	if _, _, err := Load(env(map[string]string{HostPort: "h:7233"})); err == nil {
		t.Error("hostname without namespace accepted")
	}
	if _, _, err := Load(env(map[string]string{HostPort: "h:7233", Namespace: "ns"})); err == nil {
		t.Error("missing keyring accepted")
	}
	base := map[string]string{HostPort: "h:7233", Namespace: "ns.acct", EncryptionKeys: "2026-10=" + key()}
	s, configured, err := Load(env(base))
	if err != nil || !configured || s.Keyring.ActiveKeyID() != "2026-10" || s.Auth() != "none (plaintext)" {
		t.Fatalf("plain: %+v %v %v", s, configured, err)
	}
	withKey := map[string]string{APIKey: "k"}
	for k, v := range base {
		withKey[k] = v
	}
	if s, _, err := Load(env(withKey)); err != nil || s.Auth() != "api-key" {
		t.Errorf("api key: %v %v", s.Auth(), err)
	}
	if _, err := s.Config(slog.Default()); err != nil {
		t.Errorf("config: %v", err)
	}
	withCert := map[string]string{ClientCert: "/tls/tls.crt"}
	for k, v := range base {
		withCert[k] = v
	}
	if _, _, err := Load(env(withCert)); err == nil {
		t.Error("certificate without key accepted")
	}
	withCert[ClientKey] = "/tls/tls.key"
	if s, _, err := Load(env(withCert)); err != nil || s.Auth() != "mtls" {
		t.Errorf("mtls: %v %v", s.Auth(), err)
	}
	withCert[APIKey] = "k"
	if _, _, err := Load(env(withCert)); err == nil {
		t.Error("both credentials accepted")
	}
}
