package temporalx

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
)

func randomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestCodecSealsEveryPayload(t *testing.T) {
	keys, err := ParseKeyring("2026-10="+randomKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	dc := NewDataConverter(keys)

	type in struct {
		Hex   string
		Count int
	}
	payloads, err := dc.ToPayloads(in{Hex: "a1b2c3", Count: 3}, nil, "", 42)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range payloads.Payloads {
		if got := string(p.Metadata[converter.MetadataEncoding]); got != MetadataEncodingEncrypted {
			t.Errorf("payload %d encoding = %q: every payload must be sealed", i, got)
		}
		if got := string(p.Metadata[MetadataEncryptionKeyID]); got != "2026-10" {
			t.Errorf("payload %d key id = %q", i, got)
		}
		if strings.Contains(string(p.Data), "a1b2c3") {
			t.Errorf("payload %d carries plaintext", i)
		}
	}
	var got in
	var gotNil *in
	var gotStr string
	var gotInt int
	if err := dc.FromPayloads(payloads, &got, &gotNil, &gotStr, &gotInt); err != nil {
		t.Fatal(err)
	}
	if got.Hex != "a1b2c3" || got.Count != 3 || gotNil != nil || gotStr != "" || gotInt != 42 {
		t.Errorf("round trip changed the values: %+v %v %q %d", got, gotNil, gotStr, gotInt)
	}
}

func TestFailureConverterEncodesMessages(t *testing.T) {
	keys, err := ParseKeyring("k="+randomKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	dc := NewDataConverter(keys)
	fc := NewFailureConverter(dc)
	f := fc.ErrorToFailure(errTest("card 4111 declined"))
	if strings.Contains(f.GetMessage(), "4111") || strings.Contains(f.GetStackTrace(), "4111") {
		t.Fatalf("failure message stored in the clear: %q", f.GetMessage())
	}
	if f.GetEncodedAttributes() == nil || string(f.GetEncodedAttributes().Metadata[converter.MetadataEncoding]) != MetadataEncodingEncrypted {
		t.Fatal("encoded attributes missing or not sealed")
	}
	if back := fc.FailureToError(f); back == nil || !strings.Contains(back.Error(), "card 4111 declined") {
		t.Errorf("round trip lost the message: %v", back)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

func TestCodecOpensPayloadsSealedUnderARetiredKey(t *testing.T) {
	old, current := randomKey(t), randomKey(t)
	before, err := ParseKeyring("2026-09="+old, "")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := NewCodec(before).Encode([]*commonpb.Payload{{Data: []byte("hello")}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseKeyring("2026-09="+old+";2026-10="+current, "2026-10")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := NewCodec(after).Decode(sealed)
	if err != nil {
		t.Fatalf("rotation must keep old payloads readable: %v", err)
	}
	if string(opened[0].Data) != "hello" {
		t.Errorf("got %q", opened[0].Data)
	}
	fresh, err := NewCodec(after).Encode([]*commonpb.Payload{{Data: []byte("hello")}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(fresh[0].Metadata[MetadataEncryptionKeyID]); got != "2026-10" {
		t.Errorf("new payloads sealed under %q, want the active key", got)
	}
	if _, err := NewCodec(before).Decode(fresh); err == nil || !strings.Contains(err.Error(), "2026-10") {
		t.Errorf("decode with a missing key should name it: %v", err)
	}
}

func TestCodecRejectsTamperedCiphertext(t *testing.T) {
	keys, err := ParseKeyring("k="+randomKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	c := NewCodec(keys)
	sealed, err := c.Encode([]*commonpb.Payload{{Data: []byte("hello")}})
	if err != nil {
		t.Fatal(err)
	}
	sealed[0].Data[len(sealed[0].Data)-1] ^= 0xff
	if _, err := c.Decode(sealed); err == nil {
		t.Error("tampered ciphertext decoded without error")
	}
}

func TestCodecPassesUnsealedPayloadsThrough(t *testing.T) {
	keys, err := ParseKeyring("k="+randomKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	plain := &commonpb.Payload{Metadata: map[string][]byte{"encoding": []byte("json/plain")}, Data: []byte(`"x"`)}
	out, err := NewCodec(keys).Decode([]*commonpb.Payload{plain})
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != plain {
		t.Error("an unsealed payload should pass through untouched")
	}
}

func TestKeyringValidation(t *testing.T) {
	good := randomKey(t)
	bad := map[string]struct{ spec, active string }{
		"empty":               {"", ""},
		"not id=key":          {good, ""},
		"short key":           {"k=" + base64.StdEncoding.EncodeToString([]byte("short")), ""},
		"not base64":          {"k=***", ""},
		"duplicate id":        {"k=" + good + ";k=" + good, "k"},
		"two keys, no active": {"a=" + good + ";b=" + good, ""},
		"active not present":  {"a=" + good, "b"},
	}
	for name, c := range bad {
		if _, err := ParseKeyring(c.spec, c.active); err == nil {
			t.Errorf("%s: accepted %q / %q", name, c.spec, c.active)
		}
	}
	k, err := ParseKeyring(" a = "+good+" ; ", "")
	if err != nil || k.ActiveKeyID() != "a" {
		t.Errorf("whitespace and a trailing separator should be tolerated: %v %v", k, err)
	}
	raw := make([]byte, KeySize)
	if _, err := NewKeyring("", map[string][]byte{"x": raw, "y": raw}); err == nil {
		t.Error("NewKeyring accepted two keys without an active id")
	}
	if k, err := NewKeyring("y", map[string][]byte{"x": raw, "y": raw}); err != nil || k.ActiveKeyID() != "y" || strings.Join(k.IDs(), ",") != "x,y" {
		t.Errorf("NewKeyring: %v %v", k, err)
	}
}
