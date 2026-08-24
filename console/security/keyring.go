package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Envelope is an AES-GCM encrypted value. AAD is supplied by the caller and
// intentionally not persisted inside the envelope.
type Envelope struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

// Keyring encrypts new values with ActiveID and decrypts older values by ID.
type Keyring struct {
	ActiveID string
	Keys     map[string][]byte
}

func (k Keyring) Validate() error {
	if k.ActiveID == "" {
		return errors.New("active key id is required")
	}
	for id, key := range k.Keys {
		if id == "" || len(key) != 32 {
			return fmt.Errorf("keyring entry %q must be a 32-byte AES-256 key", id)
		}
	}
	if len(k.Keys[k.ActiveID]) != 32 {
		return errors.New("active key is missing")
	}
	return nil
}

func (k Keyring) Encrypt(plaintext, aad []byte) (Envelope, error) {
	if err := k.Validate(); err != nil {
		return Envelope{}, err
	}
	gcm, err := newGCM(k.Keys[k.ActiveID])
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate encryption nonce: %w", err)
	}
	return Envelope{
		KeyID:      k.ActiveID,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, aad),
	}, nil
}

func (k Keyring) Decrypt(envelope Envelope, aad []byte) ([]byte, error) {
	key, ok := k.Keys[envelope.KeyID]
	if !ok {
		return nil, fmt.Errorf("unknown encryption key id %q", envelope.KeyID)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(envelope.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid encryption nonce")
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("decrypt protected value: authentication failed")
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
