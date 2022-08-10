// Cipherman
// For the full copyright and license information, please view the LICENSE.txt file.

package cipherman_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/devfacet/cipherman"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestNewChaCha20Poly1305(t *testing.T) {
	table := []struct {
		key []byte
	}{
		{key: genChacha20Poly1305Key()},
	}
	for _, v := range table {
		c, err := cipherman.NewChaCha20Poly1305(v.key)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if c == nil {
			t.Error("got nil, want not nil")
		}
	}
}

func TestNewChaCha20Poly1305_Error(t *testing.T) {
	table := []struct {
		key []byte
	}{
		{key: nil},
	}
	for _, v := range table {
		c, err := cipherman.NewChaCha20Poly1305(v.key)
		if err == nil {
			t.Errorf("got nil, want %v", err)
		} else if c != nil {
			t.Error("got not nil, want nil")
		}
	}
}

func TestNewXChaCha20Poly1305(t *testing.T) {
	table := []struct {
		key []byte
	}{
		{key: genChacha20Poly1305Key()},
	}
	for _, v := range table {
		c, err := cipherman.NewXChaCha20Poly1305(v.key)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if c == nil {
			t.Error("got nil, want not nil")
		}
	}
}

func TestNewXChaCha20Poly1305_Error(t *testing.T) {
	table := []struct {
		key []byte
	}{
		{key: nil},
		{key: []byte{}},
	}
	for _, v := range table {
		c, err := cipherman.NewXChaCha20Poly1305(v.key)
		if err == nil {
			t.Errorf("got nil, want %v", err)
		} else if c != nil {
			t.Error("got not nil, want nil")
		}
	}
}

func TestChaCha20Poly1305_Encrypt(t *testing.T) {
	table := []struct {
		variantX       bool
		key            []byte
		plaintext      []byte
		additionalData []byte
		nonce          []byte
		ciphertext     []byte
	}{
		{
			key:       genChacha20Poly1305Key(),
			plaintext: []byte("foo"),
		},
		{
			key:            genChacha20Poly1305Key(),
			plaintext:      []byte("bar"),
			additionalData: []byte("foo"),
		},
		{
			key:            genChacha20Poly1305Key(),
			plaintext:      []byte("baz"),
			additionalData: []byte("bar"),
			nonce:          genChacha20Poly1305Nonce(),
		},
		{
			key:            []byte{159, 43, 40, 124, 233, 90, 177, 224, 30, 100, 176, 249, 198, 243, 84, 221, 156, 36, 229, 119, 45, 200, 97, 132, 128, 196, 219, 173, 250, 73, 56, 54},
			plaintext:      []byte("qux"),
			additionalData: []byte("baz"),
			nonce:          []byte{42, 194, 67, 185, 151, 54, 124, 0, 243, 113, 194, 157},
			ciphertext:     []byte{42, 194, 67, 185, 151, 54, 124, 0, 243, 113, 194, 157, 90, 217, 30, 64, 241, 150, 80, 91, 77, 78, 14, 58, 19, 5, 205, 77, 23, 203, 197},
		},
		{
			variantX:  true,
			key:       genChacha20Poly1305Key(),
			plaintext: []byte("foo"),
		},
		{
			variantX:       true,
			key:            genChacha20Poly1305Key(),
			plaintext:      []byte("bar"),
			additionalData: []byte("foo"),
		},
		{
			variantX:       true,
			key:            genChacha20Poly1305Key(),
			plaintext:      []byte("baz"),
			additionalData: []byte("bar"),
			nonce:          genChacha20Poly1305NonceX(),
		},
		{
			variantX:       true,
			key:            []byte{109, 214, 107, 232, 251, 172, 155, 107, 143, 36, 100, 94, 48, 96, 74, 228, 126, 212, 169, 167, 59, 187, 66, 102, 57, 11, 188, 237, 2, 161, 112, 59},
			plaintext:      []byte("qux"),
			additionalData: []byte("baz"),
			nonce:          []byte{94, 33, 238, 49, 22, 125, 92, 28, 237, 217, 33, 126, 99, 244, 241, 97, 189, 168, 111, 177, 4, 247, 209, 83},
			ciphertext:     []byte{94, 33, 238, 49, 22, 125, 92, 28, 237, 217, 33, 126, 99, 244, 241, 97, 189, 168, 111, 177, 4, 247, 209, 83, 193, 46, 55, 119, 33, 94, 200, 192, 130, 235, 150, 193, 221, 254, 8, 13, 56, 113, 23},
		},
	}
	for _, v := range table {
		var c *cipherman.ChaCha20Poly1305
		var err error
		if v.variantX {
			c, err = cipherman.NewXChaCha20Poly1305(v.key)
		} else {
			c, err = cipherman.NewChaCha20Poly1305(v.key)
		}
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
		if v.ciphertext != nil {
			if !bytes.Equal(ct, v.ciphertext) {
				t.Errorf("got %v, want %v", ct, v.ciphertext)
			}
		}
	}
}

func BenchmarkChaCha20Poly1305_Encrypt(b *testing.B) {
	c, err := cipherman.NewChaCha20Poly1305(genChacha20Poly1305Key())
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

func BenchmarkXChaCha20Poly1305_Encrypt(b *testing.B) {
	c, err := cipherman.NewXChaCha20Poly1305(genChacha20Poly1305Key())
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

func TestChaCha20Poly1305_Decrypt(t *testing.T) {
	table := []struct {
		variantX       bool
		key            []byte
		ciphertext     []byte
		additionalData []byte
		nonce          []byte
		plaintext      []byte
	}{
		{
			key:        []byte{42, 103, 72, 30, 211, 82, 217, 231, 71, 214, 193, 99, 194, 100, 75, 223, 248, 125, 24, 227, 8, 27, 106, 231, 89, 174, 222, 138, 121, 5, 92, 3},
			ciphertext: []byte{126, 173, 179, 90, 163, 216, 226, 128, 211, 162, 226, 247, 205, 171, 0, 227, 248, 19, 29, 238, 98, 145, 53, 193, 137, 67, 228, 219, 220, 55, 148},
			plaintext:  []byte("foo"),
		},
		{
			key:            []byte{24, 202, 234, 56, 216, 85, 136, 112, 230, 77, 58, 117, 57, 36, 19, 122, 179, 178, 193, 249, 101, 31, 180, 124, 43, 55, 255, 90, 97, 158, 216, 183},
			ciphertext:     []byte{236, 201, 162, 172, 91, 230, 155, 11, 118, 90, 185, 148, 47, 180, 138, 236, 90, 231, 235, 18, 179, 158, 61, 62, 49, 177, 220, 96, 166, 43, 26},
			additionalData: []byte("foo"),
			plaintext:      []byte("bar"),
		},
		{
			key:            []byte{159, 43, 40, 124, 233, 90, 177, 224, 30, 100, 176, 249, 198, 243, 84, 221, 156, 36, 229, 119, 45, 200, 97, 132, 128, 196, 219, 173, 250, 73, 56, 54},
			ciphertext:     []byte{42, 194, 67, 185, 151, 54, 124, 0, 243, 113, 194, 157, 90, 217, 30, 64, 241, 150, 80, 91, 77, 78, 14, 58, 19, 5, 205, 77, 23, 203, 197},
			additionalData: []byte("baz"),
			nonce:          []byte{42, 194, 67, 185, 151, 54, 124, 0, 243, 113, 194, 157},
			plaintext:      []byte("qux"),
		},
		{
			variantX:   true,
			key:        []byte{34, 210, 70, 9, 119, 219, 77, 129, 253, 183, 254, 182, 96, 245, 56, 77, 104, 174, 160, 151, 58, 235, 157, 159, 32, 28, 76, 85, 16, 100, 125, 36},
			ciphertext: []byte{78, 154, 165, 186, 248, 196, 61, 8, 186, 33, 69, 96, 214, 175, 186, 210, 82, 60, 190, 36, 202, 59, 31, 68, 26, 70, 21, 86, 14, 16, 32, 97, 132, 26, 50, 190, 37, 47, 41, 214, 232, 137, 38},
			plaintext:  []byte("foo"),
		},
		{
			variantX:       true,
			key:            []byte{29, 88, 60, 122, 132, 169, 46, 216, 198, 173, 23, 113, 110, 168, 8, 212, 151, 144, 4, 44, 118, 255, 71, 171, 118, 129, 131, 170, 130, 166, 178, 3},
			ciphertext:     []byte{104, 230, 41, 110, 223, 226, 92, 94, 25, 113, 53, 207, 148, 27, 143, 12, 249, 2, 194, 55, 70, 62, 128, 99, 59, 25, 148, 81, 15, 43, 211, 75, 204, 36, 86, 188, 149, 248, 170, 195, 113, 63, 6},
			plaintext:      []byte("bar"),
			additionalData: []byte("foo"),
		},
		{
			variantX:       true,
			key:            []byte{109, 214, 107, 232, 251, 172, 155, 107, 143, 36, 100, 94, 48, 96, 74, 228, 126, 212, 169, 167, 59, 187, 66, 102, 57, 11, 188, 237, 2, 161, 112, 59},
			ciphertext:     []byte{94, 33, 238, 49, 22, 125, 92, 28, 237, 217, 33, 126, 99, 244, 241, 97, 189, 168, 111, 177, 4, 247, 209, 83, 193, 46, 55, 119, 33, 94, 200, 192, 130, 235, 150, 193, 221, 254, 8, 13, 56, 113, 23},
			additionalData: []byte("baz"),
			nonce:          []byte{94, 33, 238, 49, 22, 125, 92, 28, 237, 217, 33, 126, 99, 244, 241, 97, 189, 168, 111, 177, 4, 247, 209, 83},
			plaintext:      []byte("qux"),
		},
	}
	for _, v := range table {
		var c *cipherman.ChaCha20Poly1305
		var err error
		if v.variantX {
			c, err = cipherman.NewXChaCha20Poly1305(v.key)
		} else {
			c, err = cipherman.NewChaCha20Poly1305(v.key)
		}
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

func BenchmarkChaCha20Poly1305_Decrypt(b *testing.B) {
	c, err := cipherman.NewChaCha20Poly1305([]byte{33, 11, 142, 90, 184, 165, 144, 36, 107, 40, 101, 133, 200, 223, 203, 123, 134, 98, 129, 237, 223, 147, 6, 125, 98, 60, 193, 167, 78, 231, 119, 100})
	if err != nil {
		b.Errorf("got %v, want nil", err)
	} else if c == nil {
		b.Error("got nil, want not nil")
	}
	ct := []byte{63, 228, 7, 83, 255, 17, 234, 187, 254, 221, 45, 82, 116, 33, 207, 87, 189, 196, 20, 173, 93, 250, 47, 123, 57, 80, 31, 47, 183, 124, 200}
	ad := []byte("foo")
	for i := 0; i < b.N; i++ {
		_, err := c.Decrypt(ct, ad, nil)
		if err != nil {
			b.Errorf("got %v, want nil", err)
		}
	}
}

func BenchmarkXChaCha20Poly1305_Decrypt(b *testing.B) {
	c, err := cipherman.NewXChaCha20Poly1305([]byte{190, 53, 200, 194, 234, 122, 220, 12, 133, 91, 113, 85, 227, 171, 4, 32, 249, 7, 0, 222, 157, 1, 9, 165, 169, 96, 250, 73, 125, 77, 33, 28})
	if err != nil {
		b.Errorf("got %v, want nil", err)
	} else if c == nil {
		b.Error("got nil, want not nil")
	}
	ct := []byte{251, 206, 246, 30, 68, 62, 204, 253, 131, 135, 202, 218, 47, 15, 163, 74, 222, 127, 252, 193, 193, 170, 247, 207, 85, 244, 203, 105, 205, 183, 236, 75, 184, 45, 18, 128, 228, 62, 129, 57, 120, 100, 24}
	ad := []byte("foo")
	for i := 0; i < b.N; i++ {
		_, err := c.Decrypt(ct, ad, nil)
		if err != nil {
			b.Errorf("got %v, want nil", err)
		}
	}
}

func genChacha20Poly1305Key() []byte {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil
	}
	return key
}

func genChacha20Poly1305Nonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return nonce
}

func genChacha20Poly1305NonceX() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return nonce
}
