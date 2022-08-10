// Cipherman
// For the full copyright and license information, please view the LICENSE.txt file.

package cipherman

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// ECDHHKDFInfoSK represents the derived key info for the shared key.
	ECDHHKDFInfoSK = "ECDH"
)

// NewECDHP256XChaCha20Poly1305 creates a new ECDHP256XChaCha20Poly1305 instance.
// By design (similar to ephemeral-static Diffie-Hellman) this cipher:
//  1. Generates an ephemeral private key (instead of using the given private key) during encryption.
//  2. Extracts public key from the ciphertext (instead of using the given public key).
//
// Because the encryption always uses the given public key and the decryption always uses the given private key
// it doesn't require both keys to be present at the same time.
//
// Optional sharedKeyHandler argument allows encryption and decryption without providing private and public keys.
// This is useful where the keys are not accessible to pass (i.e. hardware security key).
func NewECDHP256XChaCha20Poly1305(privateKey, publicKey []byte, sharedKeyHandler func(peerKey []byte) (sharedKey, publicKey []byte, err error)) (*ECDHP256XChaCha20Poly1305, error) {
	// Init the instance
	ecdhcc20p1305 := ECDHP256XChaCha20Poly1305{
		privateKey:       privateKey,
		publicKey:        publicKey,
		sharedKeyHandler: sharedKeyHandler,
		curve:            elliptic.P256(),
	}

	// Check the keys
	if ecdhcc20p1305.privateKey == nil && ecdhcc20p1305.publicKey == nil && ecdhcc20p1305.sharedKeyHandler == nil {
		return nil, errors.New("missing key or handler")
	}
	if ecdhcc20p1305.privateKey != nil {
		if l := len(ecdhcc20p1305.privateKey); l != ecdhcc20p1305.curve.Params().P.BitLen()/8 {
			return nil, fmt.Errorf("invalid private key size (%d)", l)
		}
		ecdhcc20p1305.canDecrypt = true
	} else if ecdhcc20p1305.sharedKeyHandler != nil {
		ecdhcc20p1305.canDecrypt = true
	}
	if ecdhcc20p1305.publicKey != nil {
		if l := len(ecdhcc20p1305.publicKey); l != ecdhcc20p1305.publicKeySize(true) {
			return nil, fmt.Errorf("invalid compressed public key size (%d)", l)
		}
		ecdhcc20p1305.canEncrypt = true
	} else if ecdhcc20p1305.sharedKeyHandler != nil {
		ecdhcc20p1305.canEncrypt = true
	}

	return &ecdhcc20p1305, nil
}

// ECDHP256XChaCha20Poly1305 represents an ECDHP256XChaCha20Poly1305 cipher.
type ECDHP256XChaCha20Poly1305 struct {
	privateKey       []byte
	publicKey        []byte // compressed key
	sharedKeyHandler func(peerKey []byte) (sharedKey, publicKey []byte, err error)
	curve            elliptic.Curve
	canEncrypt       bool
	canDecrypt       bool
}

// publicKeySize returns the public key size in bytes.
func (ecdhcc20p1305 ECDHP256XChaCha20Poly1305) publicKeySize(compress bool) int {
	byteLen := (ecdhcc20p1305.curve.Params().BitSize + 7) / 8
	if compress {
		return byteLen + 1
	}
	return byteLen
}

// Encrypt encrypts plaintext by the given arguments and returns ciphertext.
func (ecdhcc20p1305 *ECDHP256XChaCha20Poly1305) Encrypt(plaintext, additionalData, nonce []byte) ([]byte, error) {
	// Check the instance
	if !ecdhcc20p1305.canEncrypt {
		return nil, errors.New("invalid cipher instance")
	}

	// Init vars
	var publicKeyC []byte
	var sharedKey []byte
	var ephemeralPubKeyC []byte

	// Check the given keys
	if ecdhcc20p1305.sharedKeyHandler != nil {
		// Do not use the given public key, instead create an ephemeral key.

		// Generate an ephemeral asymmetric key
		ephemeral, err := ecdsa.GenerateKey(ecdhcc20p1305.curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("couldn't generate the ephemeral private key: %s", err)
		}
		ephemeralPubKeyC = elliptic.MarshalCompressed(ephemeral.Curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

		// Retrieve the shared and public keys
		sharedKey, publicKeyC, err = ecdhcc20p1305.sharedKeyHandler(ephemeralPubKeyC)
		if err != nil {
			return nil, fmt.Errorf("shared key error: %s", err)
		}
	} else if len(ecdhcc20p1305.publicKey) > 0 {
		publicKeyC = ecdhcc20p1305.publicKey

		// Generate an ephemeral asymmetric key
		ephemeral, err := ecdsa.GenerateKey(ecdhcc20p1305.curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("couldn't generate the ephemeral private key: %s", err)
		}
		ephemeralPubKeyC = elliptic.MarshalCompressed(ephemeral.Curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

		// Unmarshal the given public key and generate the ECDSA public key instance
		x, y := elliptic.UnmarshalCompressed(ecdhcc20p1305.curve, publicKeyC)
		if x == nil {
			return nil, errors.New("couldn't encrypt due to invalid public key size")
		}
		ecdsaPublicKey := ecdsa.PublicKey{Curve: ecdhcc20p1305.curve, X: x, Y: y}

		// Generate the shared secret between peers
		sx, _ := ecdsaPublicKey.ScalarMult(ecdsaPublicKey.X, ecdsaPublicKey.Y, ephemeral.D.Bytes())
		sharedKey = sx.Bytes()
	} else {
		return nil, errors.New("missing key or handler")
	}

	// Derive a key from the shared secret for better security
	salt := make([]byte, 0, len(ephemeralPubKeyC)+len(publicKeyC))
	salt = append(salt, ephemeralPubKeyC...)
	salt = append(salt, publicKeyC...)
	h := hkdf.New(sha256.New, sharedKey, salt, []byte(ECDHHKDFInfoSK))
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
	ret := make([]byte, 0, len(ephemeralPubKeyC)+len(ciphertext))
	ret = append(ret, ephemeralPubKeyC...)
	ret = append(ret, ciphertext...)

	return ret, nil
}

// Decrypt decrypts ciphertext by the given arguments and returns plaintext.
func (ecdhcc20p1305 *ECDHP256XChaCha20Poly1305) Decrypt(ciphertext, additionalData, nonce []byte) ([]byte, error) {
	// Check the instance
	if !ecdhcc20p1305.canDecrypt {
		return nil, errors.New("invalid cipher instance")
	}

	// Init vars
	var publicKeyC []byte
	var sharedKey []byte
	var ephemeralPubKeyC = ciphertext[:ecdhcc20p1305.publicKeySize(true)] // Extract the ephemeral public key.

	// Check the given keys
	if ecdhcc20p1305.sharedKeyHandler != nil {
		// Retrieve the shared and public keys
		var err error
		sharedKey, publicKeyC, err = ecdhcc20p1305.sharedKeyHandler(ephemeralPubKeyC)
		if err != nil {
			return nil, fmt.Errorf("shared key error: %s", err)
		}
	} else if len(ecdhcc20p1305.privateKey) > 0 {
		// Determine the public key
		x, y := ecdhcc20p1305.curve.ScalarBaseMult(ecdhcc20p1305.privateKey)
		publicKeyC = elliptic.MarshalCompressed(ecdhcc20p1305.curve, x, y)

		// Unmarshal the ephemeral public key and generate the ECDSA public key instance
		x, y = elliptic.UnmarshalCompressed(ecdhcc20p1305.curve, ephemeralPubKeyC)
		if x == nil {
			return nil, errors.New("couldn't decrypt due to invalid public key size")
		}
		ephemeralPubKey := ecdsa.PublicKey{Curve: ecdhcc20p1305.curve, X: x, Y: y}

		// Generate the shared secret between peers
		sx, _ := ephemeralPubKey.ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, ecdhcc20p1305.privateKey)
		sharedKey = sx.Bytes()
	} else {
		return nil, errors.New("missing keys")
	}

	// Determine the derived key
	salt := make([]byte, 0, len(ephemeralPubKeyC)+len(publicKeyC))
	salt = append(salt, ephemeralPubKeyC...)
	salt = append(salt, publicKeyC...)
	h := hkdf.New(sha256.New, sharedKey, salt, []byte(ECDHHKDFInfoSK))
	cipherKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, cipherKey); err != nil {
		return nil, fmt.Errorf("couldn't generate the cipher key: %s", err)
	}

	// Remove the ephemeral public key from the ciphertext
	ciphertext = ciphertext[ecdhcc20p1305.publicKeySize(true):]

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
