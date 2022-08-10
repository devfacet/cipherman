// Cipherman
// For the full copyright and license information, please view the LICENSE.txt file.

package cipherman

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// NewChaCha20Poly1305 creates a new ChaCha20Poly1305 cipher instance.
func NewChaCha20Poly1305(key []byte) (*ChaCha20Poly1305, error) {
	return newChaCha20Poly1305(key, false)
}

// NewXChaCha20Poly1305 creates a new ChaCha20Poly1305 cipher instance which uses XChaCha20-Poly1305 variant.
func NewXChaCha20Poly1305(key []byte) (*ChaCha20Poly1305, error) {
	return newChaCha20Poly1305(key, true)
}

// new creates a new ChaCha20Poly1305 cipher instance by the given key and variant.
func newChaCha20Poly1305(key []byte, variantX bool) (*ChaCha20Poly1305, error) {
	// Init the instance
	cc20p1305 := ChaCha20Poly1305{
		key:      key,
		variantX: variantX,
	}

	// Init the underlying cipher instance
	var err error
	if cc20p1305.variantX {
		cc20p1305.cipher, err = chacha20poly1305.NewX(cc20p1305.key)
	} else {
		cc20p1305.cipher, err = chacha20poly1305.New(cc20p1305.key)
	}
	if err != nil {
		return nil, fmt.Errorf("couldn't initialized the underlying cipher instance: %s", err)
	}
	return &cc20p1305, nil
}

// ChaCha20Poly1305 represents a ChaCha20Poly1305 cipher.
type ChaCha20Poly1305 struct {
	key      []byte
	variantX bool
	cipher   cipher.AEAD
}

// Encrypt encrypts plaintext by the given arguments and returns ciphertext.
func (cc20p1305 *ChaCha20Poly1305) Encrypt(plaintext, additionalData, nonce []byte) ([]byte, error) {
	// Check the instance
	if cc20p1305.cipher == nil {
		return nil, errors.New("invalid cipher instance")
	}

	// Check the nonce
	var newNonce []byte
	if l := len(nonce); l > 0 {
		// Copy the given nonce for safety
		newNonce = make([]byte, l)
		copy(newNonce, nonce)
	} else {
		// Generate a new nonce
		newNonce = make([]byte, cc20p1305.cipher.NonceSize())
		if _, err := io.ReadFull(rand.Reader, newNonce); err != nil {
			return nil, fmt.Errorf("couldn't encrypt: %s", err)
		}
	}

	// Encrypt
	// Note that nonce is prepended to the ciphertext for decryption
	ciphertext := cc20p1305.cipher.Seal(newNonce, newNonce, plaintext, additionalData)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext by the given arguments and returns plaintext.
func (cc20p1305 *ChaCha20Poly1305) Decrypt(ciphertext, additionalData, nonce []byte) ([]byte, error) {
	// Check the instance
	if cc20p1305.cipher == nil {
		return nil, errors.New("invalid cipher instance")
	}

	// Check the nonce
	var newNonce []byte
	var ns = len(nonce)
	if ns > 0 {
		// Copy the given nonce for safety
		newNonce = make([]byte, ns)
		copy(newNonce, nonce)
	} else {
		// Extract the nonce from the ciphertext
		ns = cc20p1305.cipher.NonceSize()
		newNonce = ciphertext[:ns]
	}
	// Skip nonce which is prepended during the encryption
	ciphertext = ciphertext[ns:]

	// Decrypt
	plaintext, err := cc20p1305.cipher.Open(nil, newNonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("couldn't decrypt: %s", err)
	}

	return plaintext, nil
}
