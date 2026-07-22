package nodeapi

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// DecryptSecret opens the raw AES-256-GCM envelope
// <12-byte nonce> || <ciphertext + 16-byte GCM tag> under the NSK.
// The NSK (node secret key) must be exactly 32 bytes.
// Returns a generic error on every failure to avoid leaking cryptographic
// details.
func DecryptSecret(nsk []byte, envelope []byte) (string, error) {
	if len(nsk) != 32 {
		return "", errors.New("nodeapi: decryption failed")
	}

	block, err := aes.NewCipher(nsk)
	if err != nil {
		return "", errors.New("nodeapi: decryption failed")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("nodeapi: decryption failed")
	}

	if len(envelope) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("nodeapi: decryption failed")
	}

	plaintext, err := gcm.Open(nil, envelope[:gcm.NonceSize()], envelope[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("nodeapi: decryption failed")
	}

	return string(plaintext), nil
}
