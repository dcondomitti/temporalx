package otelx

import "testing"

func TestTracesURL(t *testing.T) {
	cases := map[string]string{
		"http://10.0.0.5:4318":           "http://10.0.0.5:4318/v1/traces",
		"http://10.0.0.5:4318/":          "http://10.0.0.5:4318/v1/traces",
		"https://api.honeycomb.io:443":   "https://api.honeycomb.io:443/v1/traces",
		"https://collector.example/otlp": "https://collector.example/otlp",
		"http://host:4318/v1/traces":     "http://host:4318/v1/traces",
	}
	for in, want := range cases {
		got, err := tracesURL(in)
		if err != nil || got != want {
			t.Errorf("tracesURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "host:4318", "/v1/traces"} {
		if _, err := tracesURL(bad); err == nil {
			t.Errorf("tracesURL(%q) accepted", bad)
		}
	}
}
