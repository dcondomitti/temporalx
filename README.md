# temporalx

How a service connects to Temporal Cloud, in one place:

- **Every payload sealed before it leaves the process.** AES-256-GCM over the
  whole payload, tagged with the id of the key that sealed it; an additive
  keyring makes rotation a config change. Failure messages and stack traces
  are encoded too.
- **API-key authentication over TLS**, the SDK's OpenTelemetry interceptor,
  and a logger of your choosing, all through `Dial`.
- **A codec server handler** (`codecserver`) so the Cloud UI shows plaintext:
  CORS pinned to the UI, JWT verified against Temporal's issuer, an email
  allowlist, and a namespace check.
- **Tracer provider setup** (`otelx`) for binaries that export OTLP/HTTP.
- **Idempotent, always-bounded schedules** (`schedule`) declared from a
  worker's startup.
- **One set of environment variable names** (`envconfig`), for services that
  want them. Nothing else in the module reads the environment, and nothing
  calls `envconfig` but you.

The core packages take their configuration through constructors and
functional options; the caller decides where host, credential and keyring
come from.

Authentication is an API key or an mTLS client certificate
(`WithClientCertificate`, re-read at each handshake so cert-manager can
rotate it in place).

```go
keys, err := temporalx.ParseKeyring(os.Getenv("TEMPORAL_ENCRYPTION_KEYS"), os.Getenv("TEMPORAL_ENCRYPTION_KEY_ID"))
cfg, err := temporalx.NewConfig(hostPort, namespace, keys,
    temporalx.WithAPIKey(apiKey),            // or temporalx.WithClientCertificate(certFile, keyFile)
    temporalx.WithLogger(slog.Default()),
)
c, err := temporalx.Dial(ctx, cfg)
```

```go
verifier, err := codecserver.NewVerifier(ctx, codecserver.TemporalCloudIssuer)
h, err := codecserver.Handler(temporalx.NewCodec(keys), verifier,
    codecserver.WithNamespaces("my-ns.acct"),
    codecserver.WithAllowedEmails("me@example.com"),
)
mux.Handle("/codec/", http.StripPrefix("/codec", h))
```

Register the endpoint on the namespace with pass-access-token on:

```
temporal cloud namespace codec set --namespace my-ns.acct \
  --endpoint https://my-host/codec --pass-access-token
```

What Cloud still sees with the codec in place: workflow ids, workflow and
activity type names, task queue names, search attributes, timestamps, and
the trace context header (the Go SDK writes headers outside the codec).

## Private module

Consumers need `GOPRIVATE=github.com/dcondomitti/temporalx` and git access
to this repo. In CI, a read-only deploy key and
`git config url."git@github.com:".insteadOf "https://github.com/"` does it.
