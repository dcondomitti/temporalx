package temporalx

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Keyring holds every key that may be needed to open a payload, and names
// the one that seals new ones.
//
// Rotation is additive: add the new key, make it active, keep the old one
// until retention has aged everything it sealed out of history. A payload
// sealed under a key the ring no longer holds fails to decode with that key's
// id in the error.
type Keyring struct {
	active string
	keys   map[string][]byte
}

// KeySize is the only accepted key length: 32 bytes, AES-256.
const KeySize = 32

// NewKeyring builds a ring from raw keys. active names the sealing key and
// must be present; with exactly one key it may be empty.
func NewKeyring(active string, keys map[string][]byte) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("keyring: no keys")
	}
	ring := &Keyring{keys: make(map[string][]byte, len(keys))}
	for id, key := range keys {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, errors.New("keyring: empty key id")
		}
		if len(key) != KeySize {
			return nil, fmt.Errorf("keyring: key %q is %d bytes, want %d", id, len(key), KeySize)
		}
		ring.keys[id] = append([]byte(nil), key...)
	}
	active = strings.TrimSpace(active)
	if active == "" {
		if len(ring.keys) > 1 {
			return nil, fmt.Errorf("keyring: %d keys (%s) but no active key id", len(ring.keys), strings.Join(ring.IDs(), ", "))
		}
		for id := range ring.keys {
			active = id
		}
	}
	if _, ok := ring.keys[active]; !ok {
		return nil, fmt.Errorf("keyring: active key id %q is not in the ring", active)
	}
	ring.active = active
	return ring, nil
}

// ParseKeyring reads "id=base64key;id2=base64key" and the id of the active
// key -- the shape a Secret or env var naturally holds.
//
// Keys are base64 in either alphabet, padded or not. Ids are opaque labels;
// the convention is the month the key was minted, e.g. "2026-10", so a
// payload's metadata says how old its key is.
func ParseKeyring(spec, active string) (*Keyring, error) {
	keys := map[string][]byte{}
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, enc, ok := strings.Cut(entry, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			return nil, fmt.Errorf("keyring: entry %q is not id=base64key", entry)
		}
		key, err := decodeKey(strings.TrimSpace(enc))
		if err != nil {
			return nil, fmt.Errorf("keyring: key %q: %w", id, err)
		}
		if _, dup := keys[id]; dup {
			return nil, fmt.Errorf("keyring: key id %q appears twice", id)
		}
		keys[id] = key
	}
	return NewKeyring(active, keys)
}

// ActiveKeyID is the id new payloads are sealed under.
func (k *Keyring) ActiveKeyID() string { return k.active }

// IDs lists every key id in the ring, sorted.
func (k *Keyring) IDs() []string {
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (k *Keyring) key(id string) ([]byte, bool) {
	key, ok := k.keys[id]
	return key, ok
}

func decodeKey(enc string) ([]byte, error) {
	var key []byte
	var err error
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err = e.DecodeString(enc); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("not base64: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("%d bytes, want %d (AES-256)", len(key), KeySize)
	}
	return key, nil
}
