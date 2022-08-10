// Cipherman
// For the full copyright and license information, please view the LICENSE.txt file.

// Package cipherman provides various cipher implementations.
package cipherman

// Block is the interface that must be implemented by block ciphers.
type Block interface {
	// Encrypt encrypts plaintext by the given arguments and returns ciphertext.
	Encrypt(plaintext []byte, additionalData []byte, nonce []byte) ([]byte, error)
	// Decrypt decrypts ciphertext by the given arguments and returns plaintext.
	Decrypt(ciphertext []byte, additionalData []byte, nonce []byte) ([]byte, error)
}
