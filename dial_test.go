package temporalx

import (
	"log/slog"
	"testing"

	"go.temporal.io/sdk/client"
)

func TestConfigRequiresTheEssentials(t *testing.T) {
	keys, _ := ParseKeyring("k="+randomKey(t), "")
	if _, err := NewConfig("", "ns", keys); err == nil {
		t.Error("accepted an empty host")
	}
	if _, err := NewConfig("h:7233", "", keys); err == nil {
		t.Error("accepted an empty namespace")
	}
	if _, err := NewConfig("h:7233", "ns", nil); err == nil {
		t.Error("accepted a nil keyring: that would be a plaintext client")
	}
}

func TestClientOptionsCarryTheCodecAndCredentials(t *testing.T) {
	keys, _ := ParseKeyring("k="+randomKey(t), "")
	var customized bool
	cfg, err := NewConfig("ns.acct.tmprl.cloud:7233", "ns.acct", keys,
		WithAPIKey("secret"),
		WithLogger(slog.Default()),
		WithClientOptions(func(o *client.Options) {
			customized = true
			o.DataConverter = nil // must not survive
			o.Identity = "custom"
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := cfg.ClientOptions()
	if err != nil {
		t.Fatal(err)
	}
	if !customized || opts.Identity != "custom" {
		t.Error("Customize did not run")
	}
	if opts.DataConverter == nil || opts.FailureConverter == nil {
		t.Error("codec or failure converter missing after Customize")
	}
	if opts.Credentials == nil || opts.ConnectionOptions.TLS == nil {
		t.Error("API key should set credentials and TLS")
	}
	if len(opts.Interceptors) != 1 {
		t.Errorf("want the tracing interceptor, got %d interceptors", len(opts.Interceptors))
	}

	plain, _ := NewConfig("localhost:7233", "default", keys, WithoutTracing())
	popts, _ := plain.ClientOptions()
	if popts.Credentials != nil || popts.ConnectionOptions.TLS != nil || len(popts.Interceptors) != 0 {
		t.Error("no API key should mean plaintext and no tracing when asked")
	}
}
