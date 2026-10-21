// Package temporalx is how a service connects to Temporal Cloud: every
// payload sealed before it leaves the process, API-key authentication over
// TLS, failure messages encoded, and OpenTelemetry spans for workflows and
// activities -- all set in one place, Dial, so no two clients of the same
// namespace can disagree about how a payload is written.
//
// Nothing here reads the environment. The caller decides where host, key
// and keyring come from and passes them in.
package temporalx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
)

// Payload metadata written by the codec. A namespace configured to reject
// unencrypted payloads matches on exactly these.
const (
	// MetadataEncodingEncrypted marks a payload as sealed by this codec.
	MetadataEncodingEncrypted = "binary/encrypted"
	// MetadataEncryptionKeyID names the keyring entry that sealed a payload.
	MetadataEncryptionKeyID = "encryption-key-id"
)

// Codec implements converter.PayloadCodec with AES-256-GCM.
//
// Each payload is sealed whole -- metadata and data -- under the ring's
// active key and tagged with that key's id, so an old payload can still be
// opened after a rotation.
type Codec struct {
	keys *Keyring
}

// NewCodec returns a codec sealing under the keyring's active key.
func NewCodec(keys *Keyring) *Codec { return &Codec{keys: keys} }

// NewDataConverter wraps the SDK's default converter with the codec. This is
// what Dial installs; it is exported for codec servers and tests.
func NewDataConverter(keys *Keyring) converter.DataConverter {
	return NewDataConverterOver(converter.GetDefaultDataConverter(), keys)
}

// NewDataConverterOver wraps base with the codec, for services that need
// their own payload converters underneath the encryption.
func NewDataConverterOver(base converter.DataConverter, keys *Keyring) converter.DataConverter {
	return converter.NewCodecDataConverter(base, NewCodec(keys))
}

// NewFailureConverter encodes failure messages and stack traces with the
// given data converter. Without it Temporal stores those fields in the clear
// even when every payload is sealed.
func NewFailureConverter(dc converter.DataConverter) converter.FailureConverter {
	return temporal.NewDefaultFailureConverter(temporal.DefaultFailureConverterOptions{
		DataConverter:          dc,
		EncodeCommonAttributes: true,
	})
}

// Encode seals every payload, including empty ones. Nothing is passed
// through: a namespace that rejects unencrypted payloads would refuse the
// request, so "skip the small ones" is a way to break a worker, not an
// optimisation.
func (c *Codec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	out := make([]*commonpb.Payload, len(payloads))
	key, _ := c.keys.key(c.keys.active)
	for i, p := range payloads {
		plain, err := p.Marshal()
		if err != nil {
			return payloads, err
		}
		sealed, err := seal(plain, key)
		if err != nil {
			return payloads, err
		}
		out[i] = &commonpb.Payload{
			Metadata: map[string][]byte{
				converter.MetadataEncoding: []byte(MetadataEncodingEncrypted),
				MetadataEncryptionKeyID:    []byte(c.keys.active),
			},
			Data: sealed,
		}
	}
	return out, nil
}

// Decode opens payloads sealed by Encode. A payload without the marker is
// returned as-is: a codec that refuses what the server legitimately hands
// back (the SDK's own internal payloads, system search attributes) would be
// worse than one that passes it through.
func (c *Codec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	out := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		if string(p.GetMetadata()[converter.MetadataEncoding]) != MetadataEncodingEncrypted {
			out[i] = p
			continue
		}
		id := string(p.GetMetadata()[MetadataEncryptionKeyID])
		key, ok := c.keys.key(id)
		if !ok {
			return payloads, fmt.Errorf("payload sealed under key %q, which is not in the keyring", id)
		}
		plain, err := open(p.GetData(), key)
		if err != nil {
			return payloads, fmt.Errorf("payload sealed under key %q: %w", id, err)
		}
		out[i] = &commonpb.Payload{}
		if err := out[i].Unmarshal(plain); err != nil {
			return payloads, err
		}
	}
	return out, nil
}

func seal(plain, key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Nonce first, then ciphertext and tag. Seal appends to its first
	// argument, so this is one allocation.
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func open(sealed, key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("ciphertext shorter than a nonce")
	}
	return gcm.Open(nil, sealed[:n], sealed[n:], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
