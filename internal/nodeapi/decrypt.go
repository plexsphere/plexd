package nodeapi

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// DecryptSecret decrypts an AES-256-GCM encrypted secret.
// The ciphertext and nonce are base64-encoded (standard encoding).
// The NSK (node secret key) must be exactly 32 bytes.
// Returns a generic error on failure to avoid leaking cryptographic details.
func DecryptSecret(nsk []byte, ciphertext string, nonce string) (string, error) {
	if len(nsk) != 32 {
		return "", errors.New("nodeapi: decryption failed")
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.New("nodeapi: decryption failed")
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
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

	if len(nonceBytes) != gcm.NonceSize() {
		return "", errors.New("nodeapi: decryption failed")
	}

	plaintext, err := gcm.Open(nil, nonceBytes, ciphertextBytes, nil)
	if err != nil {
		return "", errors.New("nodeapi: decryption failed")
	}

	return string(plaintext), nil
}
