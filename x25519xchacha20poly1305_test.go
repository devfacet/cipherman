// Cipherman
// For the full copyright and license information, please view the LICENSE.txt file.

package cipherman_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/devfacet/cipherman"
	"golang.org/x/crypto/curve25519"
)

func TestNewX25519XChaCha20Poly1305(t *testing.T) {
	table := []struct {
		privateKey []byte
		publicKey  []byte
	}{
		{privateKey: genX25519PrivateKey(), publicKey: nil},
		{privateKey: nil, publicKey: genX25519PublicKey()},
		{privateKey: genX25519PrivateKey(), publicKey: genX25519PublicKey()},
	}
	for _, v := range table {
		c, err := cipherman.NewX25519XChaCha20Poly1305(v.privateKey, v.publicKey)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if c == nil {
			t.Error("got nil, want not nil")
		}
	}
}

func TestNewX25519XChaCha20Poly1305_Error(t *testing.T) {
	table := []struct {
		privateKey []byte
		publicKey  []byte
	}{
		{privateKey: nil, publicKey: nil},
	}
	for _, v := range table {
		c, err := cipherman.NewX25519XChaCha20Poly1305(v.privateKey, v.publicKey)
		if err == nil {
			t.Errorf("got nil, want %v", err)
		} else if c != nil {
			t.Error("got not nil, want nil")
		}
	}
}

func TestNewX25519XChaCha20Poly1305_Encrypt(t *testing.T) {
	table := []struct {
		publicKey      []byte
		plaintext      []byte
		additionalData []byte
		nonce          []byte
	}{
		{
			publicKey: genX25519PublicKey(),
			plaintext: []byte("foo"),
		},
		{
			publicKey:      genX25519PublicKey(),
			plaintext:      []byte("bar"),
			additionalData: []byte("foo"),
		},
		{
			publicKey:      genX25519PublicKey(),
			plaintext:      []byte("baz"),
			additionalData: []byte("bar"),
			nonce:          genChacha20Poly1305NonceX(),
		},
		{
			publicKey:      []byte{218, 178, 196, 247, 87, 178, 232, 226, 247, 21, 100, 50, 163, 172, 19, 146, 49, 217, 226, 87, 180, 30, 0, 81, 56, 235, 21, 205, 41, 90, 101, 2},
			plaintext:      []byte("qux"),
			additionalData: []byte("baz"),
			nonce:          []byte{0, 216, 247, 156, 16, 102, 188, 122, 236, 91, 156, 124, 9, 221, 153, 102, 84, 235, 90, 69, 176, 6, 164, 123},
		},
	}
	for _, v := range table {
		c, err := cipherman.NewX25519XChaCha20Poly1305(nil, v.publicKey)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if c == nil {
			t.Error("got nil, want not nil")
		}
		ct, err := c.Encrypt(v.plaintext, v.additionalData, v.nonce)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if ct == nil {
			t.Error("got nil, want not nil")
		}
	}
}

func BenchmarkX25519XChaCha20Poly1305_Encrypt(b *testing.B) {
	c, err := cipherman.NewX25519XChaCha20Poly1305(nil, genX25519PublicKey())
	if err != nil {
		b.Errorf("got %v, want nil", err)
	} else if c == nil {
		b.Error("got nil, want not nil")
	}
	pt := []byte("foo")
	ad := []byte("bar")
	for i := 0; i < b.N; i++ {
		_, err := c.Encrypt(pt, ad, nil)
		if err != nil {
			b.Errorf("got %v, want nil", err)
		}
	}
}

func TestNewX25519XChaCha20Poly1305_Decrypt(t *testing.T) {
	table := []struct {
		privateKey     []byte
		ciphertext     []byte
		additionalData []byte
		nonce          []byte
		plaintext      []byte
	}{
		{
			privateKey: []byte{39, 235, 7, 195, 97, 95, 105, 38, 189, 81, 123, 188, 91, 11, 202, 230, 197, 165, 116, 181, 182, 164, 57, 95, 133, 61, 57, 145, 35, 193, 54, 186},
			ciphertext: []byte{45, 91, 49, 85, 191, 113, 2, 133, 244, 200, 212, 140, 9, 101, 32, 32, 249, 105, 84, 4, 242, 67, 7, 3, 63, 132, 14, 149, 2, 233, 237, 75, 39, 184, 234, 21, 62, 24, 250, 123, 127, 230, 9, 79, 164, 0, 68, 103, 26, 176, 163, 215, 209, 207, 156, 71, 251, 195, 168, 150, 15, 169, 227, 57, 224, 248, 212, 31, 191, 161, 77, 120, 74, 247, 206},
			plaintext:  []byte("foo"),
		},
		{
			privateKey:     []byte{45, 136, 147, 84, 213, 119, 251, 89, 15, 206, 136, 172, 148, 188, 211, 202, 141, 142, 23, 191, 94, 169, 132, 252, 197, 160, 93, 165, 52, 204, 16, 211},
			ciphertext:     []byte{184, 133, 3, 227, 56, 208, 62, 53, 206, 120, 38, 144, 79, 49, 208, 11, 66, 54, 240, 21, 183, 194, 86, 219, 8, 26, 70, 228, 59, 101, 227, 107, 104, 130, 226, 227, 225, 216, 93, 33, 210, 183, 91, 250, 121, 244, 228, 243, 248, 179, 123, 194, 153, 250, 174, 43, 79, 135, 61, 222, 110, 243, 158, 99, 32, 15, 159, 216, 23, 153, 124, 123, 0, 54, 63},
			plaintext:      []byte("bar"),
			additionalData: []byte("foo"),
		},
		{
			privateKey:     []byte{214, 152, 65, 61, 169, 157, 196, 196, 182, 3, 171, 238, 48, 164, 229, 211, 135, 41, 197, 122, 90, 207, 131, 201, 116, 248, 148, 195, 15, 72, 131, 232},
			ciphertext:     []byte{241, 17, 219, 236, 233, 194, 61, 166, 22, 144, 30, 124, 146, 164, 56, 166, 8, 233, 155, 138, 250, 100, 156, 203, 119, 191, 20, 238, 90, 240, 244, 15, 14, 85, 12, 41, 44, 170, 57, 221, 17, 221, 197, 135, 8, 222, 40, 214, 69, 25, 44, 67, 54, 17, 22, 33, 1, 243, 74, 32, 186, 129, 239, 119, 186, 212, 251, 57, 125, 96, 134, 22, 175, 227, 45},
			plaintext:      []byte("baz"),
			additionalData: []byte("bar"),
			nonce:          []byte{14, 85, 12, 41, 44, 170, 57, 221, 17, 221, 197, 135, 8, 222, 40, 214, 69, 25, 44, 67, 54, 17, 22, 33},
		},
		{
			privateKey:     []byte{89, 154, 119, 217, 161, 227, 120, 114, 12, 218, 105, 202, 32, 89, 19, 100, 47, 61, 178, 50, 194, 43, 67, 137, 58, 2, 13, 58, 118, 110, 249, 247},
			ciphertext:     []byte{34, 22, 31, 104, 215, 208, 234, 5, 21, 238, 127, 16, 255, 147, 172, 80, 57, 244, 39, 196, 220, 88, 119, 173, 13, 8, 229, 200, 195, 255, 72, 68, 0, 216, 247, 156, 16, 102, 188, 122, 236, 91, 156, 124, 9, 221, 153, 102, 84, 235, 90, 69, 176, 6, 164, 123, 149, 140, 54, 0, 81, 81, 171, 136, 115, 134, 230, 24, 210, 137, 101, 161, 174, 253, 15},
			plaintext:      []byte("qux"),
			additionalData: []byte("baz"),
			nonce:          []byte{0, 216, 247, 156, 16, 102, 188, 122, 236, 91, 156, 124, 9, 221, 153, 102, 84, 235, 90, 69, 176, 6, 164, 123},
		},
	}
	for _, v := range table {
		c, err := cipherman.NewX25519XChaCha20Poly1305(v.privateKey, nil)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if c == nil {
			t.Error("got nil, want not nil")
		}
		pt, err := c.Decrypt(v.ciphertext, v.additionalData, v.nonce)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if pt == nil {
			t.Error("got nil, want not nil")
		}
		if !bytes.Equal(pt, v.plaintext) {
			t.Errorf("got %v, want %v", pt, v.plaintext)
		}
	}
}

func BenchmarkX25519XChaCha20Poly1305_Decrypt(b *testing.B) {
	c, err := cipherman.NewX25519XChaCha20Poly1305([]byte{114, 124, 139, 180, 26, 255, 180, 125, 59, 247, 69, 204, 63, 19, 65, 12, 193, 47, 149, 101, 91, 186, 124, 23, 145, 23, 129, 186, 59, 70, 180, 176}, nil)
	if err != nil {
		b.Errorf("got %v, want nil", err)
	} else if c == nil {
		b.Error("got nil, want not nil")
	}
	ct := []byte{107, 149, 197, 77, 97, 232, 197, 206, 157, 125, 67, 57, 179, 197, 231, 239, 89, 177, 184, 148, 254, 0, 142, 187, 163, 203, 8, 7, 104, 55, 213, 124, 43, 133, 3, 91, 220, 28, 5, 33, 227, 187, 140, 118, 132, 109, 29, 57, 40, 136, 218, 120, 56, 48, 250, 0, 123, 230, 59, 99, 36, 55, 89, 155, 21, 31, 74, 74, 122, 157, 7, 176, 144, 89, 216}
	ad := []byte("foo")
	for i := 0; i < b.N; i++ {
		_, err := c.Decrypt(ct, ad, nil)
		if err != nil {
			b.Errorf("got %v, want nil", err)
		}
	}
}

func genX25519PrivateKey() []byte {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil
	}
	return privateKey
}

func genX25519PublicKey() []byte {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil
	}
	return publicKey
}
