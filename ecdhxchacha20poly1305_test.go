// Cipherman
// For the full copyright and license information, please view the LICENSE.txt file.

package cipherman_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/devfacet/cipherman"
)

func TestNewECDHP256XChaCha20Poly1305(t *testing.T) {
	table := []struct {
		privateKey       []byte
		publicKey        []byte
		sharedKeyHandler func(peerKey []byte) (sharedKey, publicKey []byte, err error)
	}{
		{privateKey: genECDHP256PrivateKey(), publicKey: nil, sharedKeyHandler: nil},
		{privateKey: nil, publicKey: genECDHP256PublicKey(), sharedKeyHandler: nil},
		{privateKey: genECDHP256PrivateKey(), publicKey: genECDHP256PublicKey(), sharedKeyHandler: nil},
		{
			privateKey: nil,
			publicKey:  nil,
			sharedKeyHandler: func(peerKey []byte) (sharedKey, publicKey []byte, err error) {
				return genECDHP256SharedKey()
			},
		},
	}
	for _, v := range table {
		c, err := cipherman.NewECDHP256XChaCha20Poly1305(v.privateKey, v.publicKey, v.sharedKeyHandler)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if c == nil {
			t.Error("got nil, want not nil")
		}
	}
}

func TestNewECDHP256XChaCha20Poly1305_Error(t *testing.T) {
	table := []struct {
		privateKey       []byte
		publicKey        []byte
		sharedKeyHandler func(peerKey []byte) (sharedKey, publicKey []byte, err error)
	}{
		{privateKey: nil, publicKey: nil, sharedKeyHandler: nil},
	}
	for _, v := range table {
		c, err := cipherman.NewECDHP256XChaCha20Poly1305(v.privateKey, v.publicKey, v.sharedKeyHandler)
		if err == nil {
			t.Errorf("got nil, want %v", err)
		} else if c != nil {
			t.Error("got not nil, want nil")
		}
	}
}

func TestNewECDHP256XChaCha20Poly1305_Encrypt(t *testing.T) {
	table := []struct {
		publicKey      []byte
		plaintext      []byte
		additionalData []byte
		nonce          []byte
	}{
		{
			publicKey: genECDHP256PublicKey(),
			plaintext: []byte("foo"),
		},
		{
			publicKey:      genECDHP256PublicKey(),
			plaintext:      []byte("bar"),
			additionalData: []byte("foo"),
		},
		{
			publicKey:      genECDHP256PublicKey(),
			plaintext:      []byte("baz"),
			additionalData: []byte("bar"),
			nonce:          genChacha20Poly1305NonceX(),
		},
		{
			publicKey:      []byte{3, 88, 33, 212, 83, 92, 131, 224, 160, 214, 8, 122, 221, 162, 225, 224, 180, 103, 124, 230, 104, 220, 42, 53, 251, 221, 254, 219, 102, 144, 27, 223, 165},
			plaintext:      []byte("qux"),
			additionalData: []byte("baz"),
			nonce:          []byte{245, 41, 13, 198, 138, 46, 164, 126, 157, 4, 28, 16, 74, 78, 56, 187, 65, 142, 133, 117, 84, 111, 248, 194},
		},
	}
	for _, v := range table {
		c, err := cipherman.NewECDHP256XChaCha20Poly1305(nil, v.publicKey, nil)
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

func BenchmarkECDHP256XChaCha20Poly1305_Encrypt(b *testing.B) {
	c, err := cipherman.NewECDHP256XChaCha20Poly1305(nil, genECDHP256PublicKey(), nil)
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

func TestNewECDHP256XChaCha20Poly1305_Decrypt(t *testing.T) {
	table := []struct {
		privateKey     []byte
		ciphertext     []byte
		additionalData []byte
		nonce          []byte
		plaintext      []byte
	}{
		{
			privateKey: []byte{238, 153, 159, 254, 42, 59, 179, 252, 172, 181, 236, 10, 49, 144, 209, 67, 215, 35, 161, 206, 3, 79, 178, 86, 212, 124, 18, 238, 68, 168, 43, 200},
			ciphertext: []byte{2, 52, 26, 248, 115, 182, 106, 25, 70, 223, 222, 226, 245, 173, 251, 14, 69, 83, 155, 167, 114, 37, 231, 180, 142, 147, 141, 32, 33, 175, 106, 238, 207, 209, 171, 60, 57, 4, 115, 58, 6, 116, 187, 118, 157, 231, 49, 147, 226, 163, 157, 128, 113, 221, 215, 73, 184, 230, 246, 0, 54, 189, 206, 94, 18, 42, 28, 29, 169, 140, 213, 116, 37, 62, 143, 170},
			plaintext:  []byte("foo"),
		},
		{
			privateKey:     []byte{222, 1, 195, 227, 21, 86, 71, 147, 111, 122, 139, 16, 124, 112, 129, 222, 2, 8, 114, 242, 243, 193, 17, 242, 188, 98, 51, 81, 27, 156, 188, 104},
			ciphertext:     []byte{3, 3, 250, 73, 101, 199, 99, 108, 251, 108, 24, 122, 82, 63, 95, 94, 52, 73, 192, 207, 83, 232, 38, 77, 92, 93, 125, 236, 142, 145, 2, 191, 186, 230, 139, 32, 20, 161, 20, 97, 15, 142, 70, 213, 190, 41, 115, 42, 151, 164, 7, 49, 202, 11, 111, 188, 43, 131, 224, 53, 10, 129, 125, 133, 240, 239, 52, 119, 64, 135, 32, 184, 171, 101, 133, 127},
			plaintext:      []byte("bar"),
			additionalData: []byte("foo"),
		},
		{
			privateKey:     []byte{211, 106, 30, 130, 102, 194, 250, 233, 240, 140, 74, 72, 176, 250, 216, 85, 173, 82, 31, 94, 245, 187, 135, 194, 43, 73, 211, 90, 245, 203, 207, 219},
			ciphertext:     []byte{3, 67, 255, 210, 179, 158, 118, 61, 197, 6, 54, 184, 225, 5, 104, 36, 105, 120, 31, 130, 68, 33, 171, 9, 204, 134, 81, 107, 187, 133, 27, 51, 146, 94, 21, 109, 152, 231, 140, 28, 228, 217, 210, 2, 231, 140, 105, 33, 61, 84, 56, 172, 109, 39, 52, 129, 74, 173, 168, 78, 151, 84, 66, 121, 251, 221, 114, 51, 183, 245, 134, 213, 136, 238, 171, 28},
			plaintext:      []byte("baz"),
			additionalData: []byte("bar"),
			nonce:          []byte{94, 21, 109, 152, 231, 140, 28, 228, 217, 210, 2, 231, 140, 105, 33, 61, 84, 56, 172, 109, 39, 52, 129, 74},
		},
		{
			privateKey:     []byte{88, 214, 161, 228, 80, 128, 46, 200, 135, 141, 9, 175, 179, 66, 116, 111, 202, 193, 208, 102, 39, 199, 144, 145, 253, 205, 140, 110, 170, 64, 28, 88},
			ciphertext:     []byte{3, 17, 14, 255, 202, 68, 99, 222, 163, 12, 122, 94, 129, 110, 59, 29, 74, 2, 152, 246, 211, 38, 48, 112, 47, 77, 87, 95, 176, 83, 51, 245, 214, 245, 41, 13, 198, 138, 46, 164, 126, 157, 4, 28, 16, 74, 78, 56, 187, 65, 142, 133, 117, 84, 111, 248, 194, 144, 166, 236, 170, 123, 3, 188, 31, 205, 165, 85, 226, 232, 47, 204, 159, 0, 43, 99},
			plaintext:      []byte("qux"),
			additionalData: []byte("baz"),
			nonce:          []byte{245, 41, 13, 198, 138, 46, 164, 126, 157, 4, 28, 16, 74, 78, 56, 187, 65, 142, 133, 117, 84, 111, 248, 194},
		},
	}
	for _, v := range table {
		c, err := cipherman.NewECDHP256XChaCha20Poly1305(v.privateKey, nil, nil)
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

func BenchmarkECDHP256XChaCha20Poly1305_Decrypt(b *testing.B) {
	c, err := cipherman.NewECDHP256XChaCha20Poly1305([]byte{87, 251, 0, 92, 224, 127, 140, 44, 95, 54, 70, 142, 94, 71, 76, 89, 69, 196, 218, 212, 105, 112, 220, 126, 120, 149, 177, 0, 53, 103, 124, 143}, nil, nil)
	if err != nil {
		b.Errorf("got %v, want nil", err)
	} else if c == nil {
		b.Error("got nil, want not nil")
	}
	ct := []byte{3, 195, 131, 147, 148, 8, 47, 140, 185, 144, 116, 80, 210, 191, 52, 169, 232, 100, 124, 158, 4, 121, 40, 106, 184, 251, 199, 198, 237, 233, 30, 43, 145, 217, 179, 41, 85, 184, 95, 110, 163, 69, 167, 47, 128, 64, 188, 172, 197, 83, 73, 194, 18, 88, 140, 162, 43, 78, 57, 144, 138, 227, 124, 16, 168, 47, 201, 134, 119, 109, 24, 75, 141, 59, 84, 66}
	ad := []byte("foo")
	for i := 0; i < b.N; i++ {
		_, err := c.Decrypt(ct, ad, nil)
		if err != nil {
			b.Errorf("got %v, want nil", err)
		}
	}
}

func genECDHP256PrivateKey() []byte {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	return privateKey.D.Bytes()
}

func genECDHP256PublicKey() []byte {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	publicKeyC := elliptic.MarshalCompressed(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	return publicKeyC
}

func genECDHP256SharedKey() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil
	}
	publicKeyC := elliptic.MarshalCompressed(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	x, _ := privateKey.PublicKey.Curve.ScalarMult(privateKey.PublicKey.X, privateKey.PublicKey.Y, privateKey.D.Bytes())
	return x.Bytes(), publicKeyC, nil
}
