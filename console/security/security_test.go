package security

import (
	"bytes"
	"strings"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword(strings.Repeat("correct horse battery staple ", 2))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(strings.Repeat("correct horse battery staple ", 2), encoded)
	if err != nil || !ok {
		t.Fatalf("expected password match, ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword("wrong", encoded)
	if err != nil || ok {
		t.Fatalf("expected mismatch, ok=%v err=%v", ok, err)
	}
}

func TestKeyringAuthenticatedEncryption(t *testing.T) {
	ring := Keyring{ActiveID: "v1", Keys: map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)}}
	envelope, err := ring.Encrypt([]byte("private key"), []byte("ca:123"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ring.Decrypt(envelope, []byte("ca:123"))
	if err != nil || string(got) != "private key" {
		t.Fatalf("unexpected decryption result %q: %v", got, err)
	}
	if _, err := ring.Decrypt(envelope, []byte("ca:456")); err == nil {
		t.Fatal("expected AAD mismatch to fail")
	}
}
