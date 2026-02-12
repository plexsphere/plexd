package nodeapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func testEncrypt(t *testing.T, key []byte, plaintext string) (ciphertext, nonce string) {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		t.Fatal(err)
	}
	ciphertextBytes := gcm.Seal(nil, nonceBytes, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertextBytes), base64.StdEncoding.EncodeToString(nonceBytes)
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
	ct, nonce := testEncrypt(t, key, want)

	got, err := DecryptSecret(key, ct, nonce)
	if err != nil {
		t.Fatalf("DecryptSecret() error = %v, want nil", err)
	}
	if got != want {
		t.Errorf("DecryptSecret() = %q, want %q", got, want)
	}
}

func TestDecryptSecret_CorruptCiphertext(t *testing.T) {
	key := testKey(t)
	ct, nonce := testEncrypt(t, key, "plaintext")

	// Corrupt one byte in the ciphertext.
	raw, _ := base64.StdEncoding.DecodeString(ct)
	raw[0] ^= 0xff
	ct = base64.StdEncoding.EncodeToString(raw)

	_, err := DecryptSecret(key, ct, nonce)
	if err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for corrupt ciphertext")
	}
}

func TestDecryptSecret_InvalidNonce(t *testing.T) {
	key := testKey(t)
	ct, _ := testEncrypt(t, key, "plaintext")

	// Use a different valid-length nonce.
	wrongNonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, wrongNonce); err != nil {
		t.Fatal(err)
	}
	nonce := base64.StdEncoding.EncodeToString(wrongNonce)

	_, err := DecryptSecret(key, ct, nonce)
	if err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for wrong nonce")
	}
}

func TestDecryptSecret_WrongKey(t *testing.T) {
	key := testKey(t)
	ct, nonce := testEncrypt(t, key, "plaintext")

	wrongKey := testKey(t)
	_, err := DecryptSecret(wrongKey, ct, nonce)
	if err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for wrong key")
	}
}

func TestDecryptSecret_InvalidBase64(t *testing.T) {
	key := testKey(t)

	_, err := DecryptSecret(key, "not-valid-base64!!!", "AAAAAAAAAAAAAAAA")
	if err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for invalid base64")
	}
}

func TestDecryptSecret_ShortKey(t *testing.T) {
	shortKey := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, shortKey); err != nil {
		t.Fatal(err)
	}

	_, err := DecryptSecret(shortKey, "AAAA", "AAAA")
	if err == nil {
		t.Fatal("DecryptSecret() error = nil, want error for short key")
	}
}

func TestDecryptSecret_ErrorMessageGeneric(t *testing.T) {
	// Verify error messages don't leak crypto details.
	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "short key",
			fn: func() error {
				_, err := DecryptSecret(make([]byte, 16), "AAAA", "AAAA")
				return err
			},
		},
		{
			name: "corrupt ciphertext",
			fn: func() error {
				key := testKey(t)
				ct, nonce := testEncrypt(t, key, "test")
				raw, _ := base64.StdEncoding.DecodeString(ct)
				raw[0] ^= 0xff
				ct = base64.StdEncoding.EncodeToString(raw)
				_, err := DecryptSecret(key, ct, nonce)
				return err
			},
		},
		{
			name: "wrong key",
			fn: func() error {
				key := testKey(t)
				ct, nonce := testEncrypt(t, key, "test")
				_, err := DecryptSecret(testKey(t), ct, nonce)
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
