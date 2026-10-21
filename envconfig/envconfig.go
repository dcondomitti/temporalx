// Package envconfig reads Temporal connection settings from the environment
// under one set of variable names, so every service's manifest and every
// binary agree on them. It is the only place in this module that looks at
// the environment, and nothing calls it but you.
//
//	TEMPORAL_HOSTNAME           host:port of the namespace's gRPC endpoint
//	TEMPORAL_NAMESPACE          namespace, e.g. my-ns.acct
//	TEMPORAL_API_KEY            API key (TLS on); or
//	TEMPORAL_CLIENT_CERT        path to a client certificate PEM (mTLS), with
//	TEMPORAL_CLIENT_KEY         path to its key
//	TEMPORAL_ENCRYPTION_KEYS    "id=base64key[;id=base64key...]"
//	TEMPORAL_ENCRYPTION_KEY_ID  id of the key that seals new payloads
package envconfig

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/dcondomitti/temporalx"
)

// Variable names.
const (
	HostPort       = "TEMPORAL_HOSTNAME"
	Namespace      = "TEMPORAL_NAMESPACE"
	APIKey         = "TEMPORAL_API_KEY"
	ClientCert     = "TEMPORAL_CLIENT_CERT"
	ClientKey      = "TEMPORAL_CLIENT_KEY"
	EncryptionKeys = "TEMPORAL_ENCRYPTION_KEYS"
	ActiveKeyID    = "TEMPORAL_ENCRYPTION_KEY_ID"
)

// Settings is what the environment said.
type Settings struct {
	HostPort       string
	Namespace      string
	APIKey         string
	ClientCertFile string
	ClientKeyFile  string
	Keyring        *temporalx.Keyring
}

// Lookup is how values are read; os.Getenv unless an Option says otherwise.
type Lookup func(string) string

// Option adjusts how Load reads.
type Option func(*loader)

type loader struct {
	get Lookup
}

// WithLookup reads from somewhere other than the process environment, e.g.
// a map in tests.
func WithLookup(get Lookup) Option { return func(l *loader) { l.get = get } }

// Keyring reads only the encryption keyring, for binaries that decode but
// never connect (a codec server).
func Keyring(opts ...Option) (*temporalx.Keyring, error) {
	l := newLoader(opts)
	spec := l.get(EncryptionKeys)
	if spec == "" {
		return nil, fmt.Errorf("%s is required: Temporal Cloud namespaces here hold only encrypted payloads, so there is no plaintext mode", EncryptionKeys)
	}
	keys, err := temporalx.ParseKeyring(spec, l.get(ActiveKeyID))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EncryptionKeys, err)
	}
	return keys, nil
}

// Load reads everything a client needs. configured reports whether
// TEMPORAL_HOSTNAME is set at all, so a binary that treats Temporal as
// optional can tell "not configured" from "misconfigured".
func Load(opts ...Option) (s Settings, configured bool, err error) {
	l := newLoader(opts)
	s.HostPort = l.get(HostPort)
	if s.HostPort == "" {
		return s, false, nil
	}
	s.Namespace = l.get(Namespace)
	if s.Namespace == "" {
		return s, true, errors.New(Namespace + " is required when " + HostPort + " is set")
	}
	s.APIKey = l.get(APIKey)
	s.ClientCertFile, s.ClientKeyFile = l.get(ClientCert), l.get(ClientKey)
	if (s.ClientCertFile == "") != (s.ClientKeyFile == "") {
		return s, true, errors.New(ClientCert + " and " + ClientKey + " must be set together")
	}
	if s.APIKey != "" && s.ClientCertFile != "" {
		return s, true, errors.New("set " + APIKey + " or " + ClientCert + ", not both")
	}
	s.Keyring, err = Keyring(opts...)
	return s, true, err
}

// Config turns the settings into a temporalx.Config, with the given logger
// and any further options.
func (s Settings) Config(logger *slog.Logger, opts ...temporalx.Option) (temporalx.Config, error) {
	all := []temporalx.Option{temporalx.WithLogger(logger)}
	switch {
	case s.APIKey != "":
		all = append(all, temporalx.WithAPIKey(s.APIKey))
	case s.ClientCertFile != "":
		all = append(all, temporalx.WithClientCertificate(s.ClientCertFile, s.ClientKeyFile))
	}
	all = append(all, opts...)
	return temporalx.NewConfig(s.HostPort, s.Namespace, s.Keyring, all...)
}

// Auth names the credential in use, for a startup log line.
func (s Settings) Auth() string {
	switch {
	case s.APIKey != "":
		return "api-key"
	case s.ClientCertFile != "":
		return "mtls"
	}
	return "none (plaintext)"
}

// LogAttrs describes the connection without its secrets.
func (s Settings) LogAttrs() []any {
	attrs := []any{"host", s.HostPort, "namespace", s.Namespace, "auth", s.Auth()}
	if s.Keyring != nil {
		attrs = append(attrs, "encryption_key_id", s.Keyring.ActiveKeyID())
	}
	return attrs
}

func newLoader(opts []Option) *loader {
	l := &loader{get: os.Getenv}
	for _, o := range opts {
		o(l)
	}
	return l
}
