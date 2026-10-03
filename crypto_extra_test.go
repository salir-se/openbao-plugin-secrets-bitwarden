// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// craftCipherString builds a type-2 CipherString with a valid MAC over
// arbitrary IV and ciphertext bytes. It lets tests reach the checks that sit
// behind MAC verification.
func craftCipherString(iv, ct, macKey []byte) string {
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("2.%s|%s|%s", b64(iv), b64(ct), b64(computeMAC(iv, ct, macKey)))
}

// cbcEncryptRaw encrypts exactly the given blocks, without adding padding.
func cbcEncryptRaw(t *testing.T, key, iv, blocks []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	out := make([]byte, len(blocks))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, blocks)
	return out
}

func TestDeriveKeysValidation(t *testing.T) {
	if _, _, _, err := DeriveKeys("", "pw", 100); err == nil || !strings.Contains(err.Error(), "email is required") {
		t.Errorf("empty email: got %v", err)
	}
	if _, _, _, err := DeriveKeys("a@example.com", "", 100); err == nil || !strings.Contains(err.Error(), "master password is required") {
		t.Errorf("empty password: got %v", err)
	}

	t.Run("non-positive iterations fall back to the default", func(t *testing.T) {
		if testing.Short() {
			t.Skip("600k PBKDF2 iterations")
		}
		wantMaster, wantEnc, wantMac, err := DeriveKeys("a@example.com", "pw", defaultKDFIterations)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, n := range []int{0, -5} {
			master, enc, mac, err := DeriveKeys("a@example.com", "pw", n)
			if err != nil {
				t.Fatalf("iterations=%d: %v", n, err)
			}
			if !bytes.Equal(master, wantMaster) || !bytes.Equal(enc, wantEnc) || !bytes.Equal(mac, wantMac) {
				t.Errorf("iterations=%d did not produce the default-iteration keys", n)
			}
		}
	})

	t.Run("email is case-insensitive, enc and mac keys differ", func(t *testing.T) {
		m1, e1, k1, _ := DeriveKeys("User@Example.COM", "pw", 100)
		m2, _, _, _ := DeriveKeys("user@example.com", "pw", 100)
		if !bytes.Equal(m1, m2) {
			t.Error("master key must not depend on email case")
		}
		if bytes.Equal(e1, k1) {
			t.Error("enc and mac keys must differ")
		}
	})
}

func TestDecryptSymmetricKeyVariants(t *testing.T) {
	encKey, macKey := randomBytes(t, 32), randomBytes(t, 32)

	t.Run("text variant splits a 64-byte key", func(t *testing.T) {
		// DecryptSymmetricKey goes through a string, so use ASCII key material.
		raw := []byte(strings.Repeat("E", 32) + strings.Repeat("M", 32))
		enc, mac, err := DecryptSymmetricKey(mustEncrypt(t, string(raw), encKey, macKey), encKey, macKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(enc, raw[:32]) || !bytes.Equal(mac, raw[32:]) {
			t.Error("key halves are wrong")
		}
	})

	t.Run("text variant rejects wrong length", func(t *testing.T) {
		_, _, err := DecryptSymmetricKey(mustEncrypt(t, "too short", encKey, macKey), encKey, macKey)
		wantErr(t, err, "expected 64-byte symmetric key, got 9 bytes")
	})

	t.Run("text variant rejects wrong key", func(t *testing.T) {
		_, _, err := DecryptSymmetricKey(mustEncrypt(t, strings.Repeat("k", 64), encKey, macKey), encKey, randomBytes(t, 32))
		wantErr(t, err, "decrypting symmetric key")
	})

	t.Run("raw variant rejects wrong length", func(t *testing.T) {
		_, _, err := DecryptSymmetricKeyRaw(mustEncrypt(t, string(randomBytes(t, 48)), encKey, macKey), encKey, macKey)
		wantErr(t, err, "expected 64-byte symmetric key, got 48 bytes")
	})

	t.Run("raw variant handles non-UTF-8 key bytes", func(t *testing.T) {
		raw := bytes.Repeat([]byte{0xff, 0x00, 0xfe, 0x80}, 16)
		enc, mac, err := DecryptSymmetricKeyRaw(mustEncrypt(t, string(raw), encKey, macKey), encKey, macKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(append(append([]byte{}, enc...), mac...), raw) {
			t.Error("raw key bytes were altered")
		}
	})
}

func TestCipherStringKeyLengthValidation(t *testing.T) {
	good := randomBytes(t, 32)
	for _, n := range []int{0, 16, 31, 33} {
		bad := make([]byte, n)
		if _, err := EncryptCipherString("x", bad, good); err == nil || !strings.Contains(err.Error(), "enc key must be 32 bytes") {
			t.Errorf("encrypt with %d-byte enc key: got %v", n, err)
		}
		if _, err := EncryptCipherString("x", good, bad); err == nil || !strings.Contains(err.Error(), "mac key must be 32 bytes") {
			t.Errorf("encrypt with %d-byte mac key: got %v", n, err)
		}
		cs := mustEncrypt(t, "x", good, good)
		if _, err := DecryptCipherString(cs, bad, good); err == nil || !strings.Contains(err.Error(), "enc key must be 32 bytes") {
			t.Errorf("decrypt with %d-byte enc key: got %v", n, err)
		}
		if _, err := DecryptCipherString(cs, good, bad); err == nil || !strings.Contains(err.Error(), "mac key must be 32 bytes") {
			t.Errorf("decrypt with %d-byte mac key: got %v", n, err)
		}
	}
}

func TestCipherStringTamperDetection(t *testing.T) {
	encKey, macKey := randomBytes(t, 32), randomBytes(t, 32)
	cs := mustEncrypt(t, "the quick brown fox jumps over the lazy dog", encKey, macKey)

	_, iv, ct, mac, err := parseCipherString(cs)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString
	flip := func(b []byte, i int) []byte {
		out := append([]byte{}, b...)
		out[i] ^= 0x01
		return out
	}

	tampered := map[string]string{
		"IV bit flipped":         fmt.Sprintf("2.%s|%s|%s", b64(flip(iv, 0)), b64(ct), b64(mac)),
		"ciphertext bit flipped": fmt.Sprintf("2.%s|%s|%s", b64(iv), b64(flip(ct, len(ct)-1)), b64(mac)),
		"MAC bit flipped":        fmt.Sprintf("2.%s|%s|%s", b64(iv), b64(ct), b64(flip(mac, 5))),
		"MAC truncated":          fmt.Sprintf("2.%s|%s|%s", b64(iv), b64(ct), b64(mac[:16])),
		"ciphertext truncated":   fmt.Sprintf("2.%s|%s|%s", b64(iv), b64(ct[:16]), b64(mac)),
		"blocks swapped":         fmt.Sprintf("2.%s|%s|%s", b64(iv), b64(append(append([]byte{}, ct[16:32]...), ct[:16]...)), b64(mac)),
	}
	for name, bad := range tampered {
		t.Run(name, func(t *testing.T) {
			_, err := DecryptCipherString(bad, encKey, macKey)
			wantErr(t, err, "HMAC verification failed")
		})
	}

	t.Run("wrong MAC key", func(t *testing.T) {
		_, err := DecryptCipherString(cs, encKey, randomBytes(t, 32))
		wantErr(t, err, "HMAC verification failed")
	})

	t.Run("wrong encryption key with right MAC key never returns the plaintext", func(t *testing.T) {
		got, err := DecryptCipherString(cs, randomBytes(t, 32), macKey)
		if err == nil && got == "the quick brown fox jumps over the lazy dog" {
			t.Fatal("decrypted with the wrong key")
		}
	})

	t.Run("two encryptions of the same plaintext differ", func(t *testing.T) {
		if other := mustEncrypt(t, "the quick brown fox jumps over the lazy dog", encKey, macKey); other == cs {
			t.Error("IV reuse: identical CipherStrings")
		}
	})
}

func TestDecryptRejectsMalformedAuthenticatedInput(t *testing.T) {
	encKey, macKey := randomBytes(t, 32), randomBytes(t, 32)
	iv := randomBytes(t, 16)

	t.Run("RSA-type string is not accepted by the symmetric decrypter", func(t *testing.T) {
		_, err := DecryptCipherString("4."+base64.StdEncoding.EncodeToString([]byte("blob")), encKey, macKey)
		wantErr(t, err, "unsupported encryption type: 4")
	})

	t.Run("ciphertext not a multiple of the block size", func(t *testing.T) {
		_, err := DecryptCipherString(craftCipherString(iv, randomBytes(t, 20), macKey), encKey, macKey)
		wantErr(t, err, "ciphertext length 20 is not a multiple of block size 16")
	})

	t.Run("empty ciphertext", func(t *testing.T) {
		_, err := DecryptCipherString(craftCipherString(iv, nil, macKey), encKey, macKey)
		wantErr(t, err, "removing padding: empty data")
	})

	t.Run("zero padding byte", func(t *testing.T) {
		ct := cbcEncryptRaw(t, encKey, iv, make([]byte, 16))
		_, err := DecryptCipherString(craftCipherString(iv, ct, macKey), encKey, macKey)
		wantErr(t, err, "invalid padding value: 0")
	})

	t.Run("padding byte larger than a block", func(t *testing.T) {
		ct := cbcEncryptRaw(t, encKey, iv, bytes.Repeat([]byte{17}, 16))
		_, err := DecryptCipherString(craftCipherString(iv, ct, macKey), encKey, macKey)
		wantErr(t, err, "invalid padding value: 17")
	})

	t.Run("inconsistent padding bytes", func(t *testing.T) {
		block := append(bytes.Repeat([]byte{'a'}, 13), 9, 3, 3)
		ct := cbcEncryptRaw(t, encKey, iv, block)
		_, err := DecryptCipherString(craftCipherString(iv, ct, macKey), encKey, macKey)
		wantErr(t, err, "invalid PKCS7 padding")
	})

	// KNOWN BUG (pinned, not fixed): the IV length is never validated, so a
	// CipherString with a correct MAC but an IV that is not 16 bytes makes
	// crypto/cipher panic instead of returning an error. Producing such a
	// string requires the MAC key, so only the key holder (or the server
	// when it chooses the key material) can trigger it.
	t.Run("short IV with valid MAC panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected a panic for an 8-byte IV; if this now returns an error the bug was fixed — update this test")
			}
		}()
		short := randomBytes(t, 8)
		ct := randomBytes(t, 16)
		_, _ = DecryptCipherString(craftCipherString(short, ct, macKey), encKey, macKey)
	})
}

func TestParseCipherStringErrors(t *testing.T) {
	ok := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", "empty cipher string"},
		{"no dot", "justtext", "no dot separator"},
		{"non-numeric type", "x." + ok, "parsing encryption type"},
		{"empty type", "." + ok, "parsing encryption type"},
		{"unsupported type 0", "0." + ok, "unsupported encryption type: 0"},
		{"unsupported type 7", "7." + ok + "|" + ok, "unsupported encryption type: 7"},
		{"AES with two parts", "2." + ok + "|" + ok, "expected 3 parts, got 2"},
		{"AES with four parts", "2." + ok + "|" + ok + "|" + ok + "|" + ok, "expected 3 parts, got 4"},
		{"AES bad IV base64", "2.!!!|" + ok + "|" + ok, "decoding IV"},
		{"AES bad ciphertext base64", "2." + ok + "|!!!|" + ok, "decoding ciphertext"},
		{"AES bad MAC base64", "2." + ok + "|" + ok + "|!!!", "decoding MAC"},
		{"RSA with extra parts", "4." + ok + "|" + ok, "expected 1 part, got 2"},
		{"RSA bad base64", "4.!!!", "decoding RSA ciphertext"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := parseCipherString(tc.in)
			wantErr(t, err, tc.want)
		})
	}

	t.Run("RSA string yields only ciphertext", func(t *testing.T) {
		encType, iv, ct, mac, err := parseCipherString("4." + ok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if encType != encTypeRsa2048OaepSha1 || iv != nil || mac != nil || string(ct) != "0123456789abcdef" {
			t.Errorf("got type=%d iv=%v ct=%q mac=%v", encType, iv, ct, mac)
		}
	})
}

func TestDecryptPrivateKey(t *testing.T) {
	encKey, macKey := randomBytes(t, 32), randomBytes(t, 32)
	key := sharedRSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	t.Run("round trip", func(t *testing.T) {
		got, err := DecryptPrivateKey(mustEncrypt(t, string(der), encKey, macKey), encKey, macKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.Equal(key) {
			t.Error("decrypted key differs from the original")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		_, err := DecryptPrivateKey(mustEncrypt(t, string(der), encKey, macKey), encKey, randomBytes(t, 32))
		wantErr(t, err, "decrypting private key")
	})

	t.Run("not PKCS8", func(t *testing.T) {
		_, err := DecryptPrivateKey(mustEncrypt(t, "garbage", encKey, macKey), encKey, macKey)
		wantErr(t, err, "parsing PKCS8 private key")
	})

	t.Run("PKCS1 encoding is rejected", func(t *testing.T) {
		pkcs1 := x509.MarshalPKCS1PrivateKey(key)
		_, err := DecryptPrivateKey(mustEncrypt(t, string(pkcs1), encKey, macKey), encKey, macKey)
		wantErr(t, err, "parsing PKCS8 private key")
	})

	t.Run("non-RSA key", func(t *testing.T) {
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa: %v", err)
		}
		ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		_, err = DecryptPrivateKey(mustEncrypt(t, string(ecDER), encKey, macKey), encKey, macKey)
		wantErr(t, err, "expected RSA private key, got *ecdsa.PrivateKey")
	})
}

func TestDecryptRSACipherString(t *testing.T) {
	f := newFakeBW(t)
	secret := randomBytes(t, 64)

	t.Run("round trip", func(t *testing.T) {
		got, err := DecryptRSACipherString(f.rsaWrap(secret), f.rsaKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(got, secret) {
			t.Error("plaintext mismatch")
		}
	})

	t.Run("malformed string", func(t *testing.T) {
		_, err := DecryptRSACipherString("4.!!!", f.rsaKey)
		wantErr(t, err, "decoding RSA ciphertext")
	})

	t.Run("AES-type string is rejected", func(t *testing.T) {
		_, err := DecryptRSACipherString(mustEncrypt(t, "x", randomBytes(t, 32), randomBytes(t, 32)), f.rsaKey)
		wantErr(t, err, "expected RSA cipher type 4, got 2")
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		wrapped := f.rsaWrap(secret)
		raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(wrapped, "4."))
		raw[len(raw)/2] ^= 0xff
		_, err := DecryptRSACipherString("4."+base64.StdEncoding.EncodeToString(raw), f.rsaKey)
		wantErr(t, err, "RSA-OAEP decryption failed")
	})
}

func TestPKCS7UnpadRejectsBadLengths(t *testing.T) {
	if _, err := pkcs7Unpad(nil, 16); err == nil || !strings.Contains(err.Error(), "empty data") {
		t.Errorf("empty input: got %v", err)
	}
	if _, err := pkcs7Unpad(make([]byte, 15), 16); err == nil || !strings.Contains(err.Error(), "not a multiple of block size") {
		t.Errorf("15-byte input: got %v", err)
	}
	// A full block of padding decodes to the empty message.
	got, err := pkcs7Unpad(bytes.Repeat([]byte{16}, 16), 16)
	if err != nil || len(got) != 0 {
		t.Errorf("full padding block: got (%v, %v), want empty", got, err)
	}
}
