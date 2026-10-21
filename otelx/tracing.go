// Package otelx installs an OpenTelemetry tracer provider that exports over
// OTLP/HTTP. It is the few lines every binary otherwise copies, with one
// decision made for them: no endpoint means tracing is off, not an exporter
// failing against localhost on every flush.
package otelx

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Config is what Init needs. Build it through options.
type Config struct {
	// EndpointURL is the OTLP/HTTP collector, e.g. "http://10.0.0.5:4318".
	// Empty disables tracing.
	EndpointURL string
	// Headers are sent with every export, e.g. an ingest key.
	Headers map[string]string
	// Logger announces whether tracing is on. Defaults to slog.Default().
	Logger *slog.Logger
}

// Option adjusts a Config.
type Option func(*Config)

// WithEndpointURL sets the collector. Empty leaves tracing off.
func WithEndpointURL(u string) Option { return func(c *Config) { c.EndpointURL = u } }

// WithHeaders adds request headers to every export.
func WithHeaders(h map[string]string) Option { return func(c *Config) { c.Headers = h } }

// WithLogger sets where Init reports.
func WithLogger(l *slog.Logger) Option { return func(c *Config) { c.Logger = l } }

// Init installs the global tracer provider and a W3C trace-context plus
// baggage propagator. The returned function flushes and stops the exporter;
// call it on the way out. With no endpoint it installs nothing and returns a
// no-op.
func Init(ctx context.Context, serviceName string, opts ...Option) (func(context.Context) error, error) {
	cfg := Config{Logger: slog.Default()}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.EndpointURL == "" {
		cfg.Logger.Info("tracing disabled: no OTLP endpoint", "service", serviceName)
		return func(context.Context) error { return nil }, nil
	}

	exporterOpts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(cfg.EndpointURL)}
	if len(cfg.Headers) > 0 {
		exporterOpts = append(exporterOpts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	exporter, err := otlptracehttp.New(ctx, exporterOpts...)
	if err != nil {
		return nil, err
	}
	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(serviceName)))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	cfg.Logger.Info("tracing enabled", "service", serviceName, "endpoint", cfg.EndpointURL)
	return tp.Shutdown, nil
}
