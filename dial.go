package temporalx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/contrib/opentelemetry"
	"go.temporal.io/sdk/interceptor"
	"go.temporal.io/sdk/log"
)

// Config is everything Dial needs. Build it with NewConfig and Options; the
// zero value is not usable.
type Config struct {
	// HostPort of the namespace's gRPC endpoint, e.g.
	// "my-ns.acct.tmprl.cloud:7233".
	HostPort string
	// Namespace as the service knows it, e.g. "my-ns.acct" on Cloud.
	Namespace string
	// Keyring seals every payload. Required.
	Keyring *Keyring

	// APIKey authenticates to Temporal Cloud and turns on TLS. Empty, with no
	// client certificate either, means a plaintext frontend, which only a
	// local dev server accepts.
	APIKey string
	// ClientCertFile and ClientKeyFile authenticate with mTLS. The files are
	// re-read on every TLS handshake, so a certificate rotated in place (as
	// cert-manager does) is picked up without a restart.
	ClientCertFile string
	ClientKeyFile  string
	// Logger receives the SDK's own logging. Defaults to slog.Default().
	Logger log.Logger
	// Tracing installs the SDK's OpenTelemetry interceptor, which emits
	// workflow and activity spans through the global tracer provider.
	// Default true.
	Tracing bool
	// Interceptors are added after the tracing interceptor.
	Interceptors []interceptor.ClientInterceptor
	// Customize runs last, on the fully built client.Options, for anything
	// this package does not model. It cannot remove the codec: the data and
	// failure converters are re-applied after it returns.
	Customize func(*client.Options)
}

// Option adjusts a Config.
type Option func(*Config)

// WithAPIKey authenticates with a Temporal Cloud API key over TLS.
func WithAPIKey(key string) Option { return func(c *Config) { c.APIKey = key } }

// WithClientCertificate authenticates with an mTLS client certificate, read
// from PEM files at each handshake so rotation needs no restart.
func WithClientCertificate(certFile, keyFile string) Option {
	return func(c *Config) { c.ClientCertFile, c.ClientKeyFile = certFile, keyFile }
}

// WithLogger routes the SDK's logging through l.
func WithLogger(l *slog.Logger) Option { return func(c *Config) { c.Logger = slogLogger{l} } }

// WithSDKLogger routes the SDK's logging through a logger that already
// speaks the SDK's interface.
func WithSDKLogger(l log.Logger) Option { return func(c *Config) { c.Logger = l } }

// WithoutTracing leaves the OpenTelemetry interceptor out.
func WithoutTracing() Option { return func(c *Config) { c.Tracing = false } }

// WithInterceptors adds client interceptors after the tracing one.
func WithInterceptors(is ...interceptor.ClientInterceptor) Option {
	return func(c *Config) { c.Interceptors = append(c.Interceptors, is...) }
}

// WithClientOptions registers a last-word hook on the SDK options.
func WithClientOptions(f func(*client.Options)) Option { return func(c *Config) { c.Customize = f } }

// NewConfig builds a Config. The three positional arguments are the ones no
// client can do without.
func NewConfig(hostPort, namespace string, keys *Keyring, opts ...Option) (Config, error) {
	c := Config{
		HostPort:  hostPort,
		Namespace: namespace,
		Keyring:   keys,
		Logger:    slogLogger{slog.Default()},
		Tracing:   true,
	}
	for _, o := range opts {
		o(&c)
	}
	return c, c.validate()
}

func (c Config) validate() error {
	switch {
	case c.HostPort == "":
		return errors.New("temporalx: HostPort is required")
	case c.Namespace == "":
		return errors.New("temporalx: Namespace is required")
	case c.Keyring == nil:
		return errors.New("temporalx: Keyring is required; there is no plaintext mode")
	case (c.ClientCertFile == "") != (c.ClientKeyFile == ""):
		return errors.New("temporalx: client certificate and key must be given together")
	case c.APIKey != "" && c.ClientCertFile != "":
		return errors.New("temporalx: choose an API key or a client certificate, not both")
	}
	return nil
}

// ClientOptions renders the SDK options Dial uses, for callers that need to
// construct the client themselves (a lazy client, a test). The codec and
// failure converter are always present in the result.
func (c Config) ClientOptions() (client.Options, error) {
	if err := c.validate(); err != nil {
		return client.Options{}, err
	}
	dc := NewDataConverter(c.Keyring)
	opts := client.Options{
		HostPort:         c.HostPort,
		Namespace:        c.Namespace,
		Logger:           c.Logger,
		DataConverter:    dc,
		FailureConverter: NewFailureConverter(dc),
	}
	if c.Tracing {
		tracing, err := opentelemetry.NewTracingInterceptor(opentelemetry.TracerOptions{})
		if err != nil {
			return client.Options{}, fmt.Errorf("temporalx: tracing interceptor: %w", err)
		}
		opts.Interceptors = append(opts.Interceptors, tracing)
	}
	opts.Interceptors = append(opts.Interceptors, c.Interceptors...)
	switch {
	case c.APIKey != "":
		opts.Credentials = client.NewAPIKeyStaticCredentials(c.APIKey)
		opts.ConnectionOptions = client.ConnectionOptions{TLS: &tls.Config{MinVersion: tls.VersionTLS12}}
	case c.ClientCertFile != "":
		// Load once now so a bad path or key fails Dial, not the first
		// handshake; then reload per handshake for rotation.
		if _, err := tls.LoadX509KeyPair(c.ClientCertFile, c.ClientKeyFile); err != nil {
			return client.Options{}, fmt.Errorf("temporalx: client certificate: %w", err)
		}
		certFile, keyFile := c.ClientCertFile, c.ClientKeyFile
		opts.ConnectionOptions = client.ConnectionOptions{TLS: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					return nil, fmt.Errorf("temporalx: reload client certificate: %w", err)
				}
				return &cert, nil
			},
		}}
	}
	if c.Customize != nil {
		c.Customize(&opts)
		opts.DataConverter = dc
		opts.FailureConverter = NewFailureConverter(dc)
	}
	return opts, nil
}

// Dial connects to the namespace with the codec, failure converter, tracing
// and credentials from cfg.
func Dial(ctx context.Context, cfg Config) (client.Client, error) {
	opts, err := cfg.ClientOptions()
	if err != nil {
		return nil, err
	}
	return client.DialContext(ctx, opts)
}

// slogLogger adapts *slog.Logger to the SDK's logger interface.
type slogLogger struct{ l *slog.Logger }

func (s slogLogger) Debug(msg string, kv ...any) { s.l.Debug(msg, kv...) }
func (s slogLogger) Info(msg string, kv ...any)  { s.l.Info(msg, kv...) }
func (s slogLogger) Warn(msg string, kv ...any)  { s.l.Warn(msg, kv...) }
func (s slogLogger) Error(msg string, kv ...any) { s.l.Error(msg, kv...) }
