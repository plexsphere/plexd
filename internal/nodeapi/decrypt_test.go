package nodeapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

// testEncrypt seals plaintext with AES-256-GCM under key using a random 12-byte
// nonce and returns the raw envelope nonce || ciphertext+tag.
func testEncrypt(t *testing.T, key []byte, plaintext string) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil)
}

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDecryptSecret_Success(t *testing.T) {
	key := testKey(t)
	want := "my-secret-value"
	envelope := testEncrypt(t, key, want)

	got, err := DecryptSecret(key, envelope)
	if err != nil {
		t.Fatalf("DecryptSecret() error = %v, want nil", err)
	}
	if got != want {
		t.Errorf("DecryptSecret() = %q, want %q", got, want)
	}
}

func TestDecryptSecret_CorruptCiphertext(t *testing.T) {
	key := testKey(t)
	envelope := testEncrypt(t, key, "plaintext")

	// Corrupt one byte of the ciphertext (past the 12-byte nonce prefix).
	envelope[12] ^= 0xff

	if _, err := DecryptSecret(key, envelope); err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for corrupt ciphertext")
	}
}

func TestDecryptSecret_InvalidNonce(t *testing.T) {
	key := testKey(t)
	envelope := testEncrypt(t, key, "plaintext")

	// Corrupt a byte of the nonce prefix so GCM authentication fails.
	envelope[0] ^= 0xff

	if _, err := DecryptSecret(key, envelope); err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for tampered nonce")
	}
}

func TestDecryptSecret_WrongKey(t *testing.T) {
	key := testKey(t)
	envelope := testEncrypt(t, key, "plaintext")

	if _, err := DecryptSecret(testKey(t), envelope); err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for wrong key")
	}
}

func TestDecryptSecret_ShortKey(t *testing.T) {
	shortKey := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, shortKey); err != nil {
		t.Fatal(err)
	}

	if _, err := DecryptSecret(shortKey, make([]byte, 28)); err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for short key")
	}
}

func TestDecryptSecret_ErrorMessageGeneric(t *testing.T) {
	// Verify error messages don't leak crypto details and stay identical across
	// every failure path.
	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "nil envelope",
			fn: func() error {
				_, err := DecryptSecret(testKey(t), nil)
				return err
			},
		},
		{
			name: "empty envelope",
			fn: func() error {
				_, err := DecryptSecret(testKey(t), []byte{})
				return err
			},
		},
		{
			name: "27-byte envelope",
			fn: func() error {
				_, err := DecryptSecret(testKey(t), make([]byte, 27))
				return err
			},
		},
		{
			name: "tampered ciphertext",
			fn: func() error {
				key := testKey(t)
				envelope := testEncrypt(t, key, "test")
				envelope[12] ^= 0xff
				_, err := DecryptSecret(key, envelope)
				return err
			},
		},
		{
			name: "wrong key",
			fn: func() error {
				key := testKey(t)
				envelope := testEncrypt(t, key, "test")
				_, err := DecryptSecret(testKey(t), envelope)
				return err
			},
		},
		{
			name: "non-32-byte key",
			fn: func() error {
				_, err := DecryptSecret(make([]byte, 16), make([]byte, 28))
				return err
			},
		},
	}

	const wantMsg = "nodeapi: decryption failed"
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != wantMsg {
				t.Errorf("error = %q, want %q", err.Error(), wantMsg)
			}
			// Ensure no crypto-specific terms leak.
			lower := strings.ToLower(err.Error())
			for _, forbidden := range []string{"aes", "gcm", "cipher", "nonce", "key size", "authentication"} {
				if strings.Contains(lower, forbidden) {
					t.Errorf("error message contains forbidden term %q: %s", forbidden, err.Error())
				}
			}
		})
	}
}
