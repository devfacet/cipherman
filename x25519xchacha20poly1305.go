// Cipherman
// For the full copyright and license information, please view the LICENSE.txt file.

package cipherman

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// X25519HKDFInfoSK represents the derived key info for the shared key.
	X25519HKDFInfoSK = "X25519"
)

// NewX25519XChaCha20Poly1305 creates a new X25519XChaCha20Poly1305 instance.
// By design (similar to ephemeral-static Diffie-Hellman) this cipher:
//  1. Generates an ephemeral private key (instead of using the given private key) during encryption.
//  2. Extracts public key from the ciphertext (instead of using the given public key).
//
// Because the encryption always uses the given public key and the decryption always uses the given private key
// it doesn't require both keys to be present at the same time.
func NewX25519XChaCha20Poly1305(privateKey, publicKey []byte) (*X25519XChaCha20Poly1305, error) {
	// Init the instance
	x25519cc20p1305 := X25519XChaCha20Poly1305{
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	// Check the keys
	if x25519cc20p1305.privateKey == nil && x25519cc20p1305.publicKey == nil {
		return nil, errors.New("missing key")
	}
	if x25519cc20p1305.privateKey != nil {
		if l := len(x25519cc20p1305.privateKey); l != curve25519.PointSize {
			return nil, fmt.Errorf("invalid private key size (%d)", l)
		}
		x25519cc20p1305.canDecrypt = true
	}
	if x25519cc20p1305.publicKey != nil {
		if l := len(x25519cc20p1305.publicKey); l != curve25519.PointSize {
			return nil, fmt.Errorf("invalid public key size (%d)", l)
		}
		x25519cc20p1305.canEncrypt = true
	}

	return &x25519cc20p1305, nil
}

// X25519XChaCha20Poly1305 represents an X25519XChaCha20Poly1305 cipher.
type X25519XChaCha20Poly1305 struct {
	privateKey []byte
	publicKey  []byte
	canEncrypt bool
	canDecrypt bool
}

// Encrypt encrypts plaintext by the given arguments and returns ciphertext.
func (x25519cc20p1305 *X25519XChaCha20Poly1305) Encrypt(plaintext, additionalData, nonce []byte) ([]byte, error) {
	// Check the instance
	if !x25519cc20p1305.canEncrypt {
		return nil, errors.New("invalid cipher instance")
	}

	// Generate an ephemeral asymmetric key
	ephemeral := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(ephemeral); err != nil {
		return nil, fmt.Errorf("couldn't generate the ephemeral private key: %s", err)
	}
	ephemeralPubKey, err := curve25519.X25519(ephemeral, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate the ephemeral public key: %s", err)
	}

	// Generate the shared secret between peers
	sharedKey, err := curve25519.X25519(ephemeral, x25519cc20p1305.publicKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate the shared secret: %s", err)
	}

	// Derive a key from the shared secret for better security
	salt := make([]byte, 0, len(ephemeralPubKey)+len(x25519cc20p1305.publicKey))
	salt = append(salt, ephemeralPubKey...)
	salt = append(salt, x25519cc20p1305.publicKey...)
	h := hkdf.New(sha256.New, sharedKey, salt, []byte(X25519HKDFInfoSK))
	cipherKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, cipherKey); err != nil {
		return nil, fmt.Errorf("couldn't generate the cipher key: %s", err)
	}

	// Init the underlying cipher instance
	c, err := NewXChaCha20Poly1305(cipherKey)
	if err != nil {
		return nil, err
	}

	// Encrypt
	// chacha20poly1305 cipher generates a random nonce (recommended) when nonce is not set.
	ciphertext, err := c.Encrypt(plaintext, additionalData, nonce)
	if err != nil {
		return nil, err
	}

	// Add the ephemeral public key to the ciphertext for decryption
	ret := make([]byte, 0, len(ephemeralPubKey)+len(ciphertext))
	ret = append(ret, ephemeralPubKey...)
	ret = append(ret, ciphertext...)

	return ret, nil
}

// Decrypt decrypts ciphertext by the given arguments and returns plaintext.
func (x25519cc20p1305 *X25519XChaCha20Poly1305) Decrypt(ciphertext, additionalData, nonce []byte) ([]byte, error) {
	// Check the instance
	if !x25519cc20p1305.canDecrypt {
		return nil, errors.New("invalid cipher instance")
	}

	// Determine the public key
	publicKey, err := curve25519.X25519(x25519cc20p1305.privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't determine the public key: %s", err)
	}

	// Extract the ephemeral public key from the ciphertext
	ephemeralPubKey := ciphertext[:curve25519.PointSize]

	// Generate the shared secret between peers
	sharedKey, err := curve25519.X25519(x25519cc20p1305.privateKey, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't determine the shared secret: %s", err)
	}

	// Determine the derived key
	salt := make([]byte, 0, len(ephemeralPubKey)+len(publicKey))
	salt = append(salt, ephemeralPubKey...)
	salt = append(salt, publicKey...)
	h := hkdf.New(sha256.New, sharedKey, salt, []byte(X25519HKDFInfoSK))
	cipherKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, cipherKey); err != nil {
		return nil, fmt.Errorf("couldn't generate the cipher key: %s", err)
	}

	// Remove the ephemeral public key from the ciphertext
	ciphertext = ciphertext[curve25519.PointSize:]

	// Init the underlying cipher instance
	c, err := NewXChaCha20Poly1305(cipherKey)
	if err != nil {
		return nil, err
	}

	// Decrypt
	// chacha20poly1305 cipher extracts the nonce from the ciphertext
	plaintext, err := c.Decrypt(ciphertext, additionalData, nonce)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
