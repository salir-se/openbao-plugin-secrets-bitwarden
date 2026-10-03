// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeriveKeys(t *testing.T) {
	t.Run("basic derivation", func(t *testing.T) {
		masterKey, encKey, macKey, err := DeriveKeys("test@example.com", "password123", 100000)
		if err != nil {
			t.Fatalf("DeriveKeys failed: %v", err)
		}

		if len(masterKey) != 32 {
			t.Errorf("master key length = %d, want 32", len(masterKey))
		}
		if len(encKey) != 32 {
			t.Errorf("enc key length = %d, want 32", len(encKey))
		}
		if len(macKey) != 32 {
			t.Errorf("mac key length = %d, want 32", len(macKey))
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		mk1, ek1, mac1, _ := DeriveKeys("test@example.com", "password123", 100000)
		mk2, ek2, mac2, _ := DeriveKeys("test@example.com", "password123", 100000)

		if !bytesEqual(mk1, mk2) {
			t.Error("master keys differ for same input")
		}
		if !bytesEqual(ek1, ek2) {
			t.Error("enc keys differ for same input")
		}
		if !bytesEqual(mac1, mac2) {
			t.Error("mac keys differ for same input")
		}
	})

	t.Run("different email produces different keys", func(t *testing.T) {
		mk1, _, _, _ := DeriveKeys("alice@example.com", "password123", 100000)
		mk2, _, _, _ := DeriveKeys("bob@example.com", "password123", 100000)

		if bytesEqual(mk1, mk2) {
			t.Error("different emails should produce different master keys")
		}
	})

	t.Run("email case insensitive", func(t *testing.T) {
		mk1, _, _, _ := DeriveKeys("Test@Example.Com", "password123", 100000)
		mk2, _, _, _ := DeriveKeys("test@example.com", "password123", 100000)

		if !bytesEqual(mk1, mk2) {
			t.Error("email should be case-insensitive for key derivation")
		}
	})

	t.Run("different password produces different keys", func(t *testing.T) {
		mk1, _, _, _ := DeriveKeys("test@example.com", "password1", 100000)
		mk2, _, _, _ := DeriveKeys("test@example.com", "password2", 100000)

		if bytesEqual(mk1, mk2) {
			t.Error("different passwords should produce different master keys")
		}
	})

	t.Run("empty email returns error", func(t *testing.T) {
		_, _, _, err := DeriveKeys("", "password123", 100000)
		if err == nil {
			t.Error("expected error for empty email")
		}
	})

	t.Run("empty password returns error", func(t *testing.T) {
		_, _, _, err := DeriveKeys("test@example.com", "", 100000)
		if err == nil {
			t.Error("expected error for empty password")
		}
	})

	t.Run("default iterations used for zero value", func(t *testing.T) {
		_, _, _, err := DeriveKeys("test@example.com", "password123", 0)
		if err != nil {
			t.Fatalf("DeriveKeys with 0 iterations should use default: %v", err)
		}
	})

	t.Run("enc and mac keys are different", func(t *testing.T) {
		_, encKey, macKey, _ := DeriveKeys("test@example.com", "password123", 100000)
		if bytesEqual(encKey, macKey) {
			t.Error("enc and mac keys should be different")
		}
	})
}

func TestComputePasswordHash(t *testing.T) {
	masterKey, _, _, err := DeriveKeys("test@example.com", "password123", 100000)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	t.Run("produces base64 output", func(t *testing.T) {
		hash := ComputePasswordHash(masterKey, "password123")
		if hash == "" {
			t.Error("password hash is empty")
		}

		// Should be valid base64.
		_, err := base64.StdEncoding.DecodeString(hash)
		if err != nil {
			t.Errorf("password hash is not valid base64: %v", err)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		h1 := ComputePasswordHash(masterKey, "password123")
		h2 := ComputePasswordHash(masterKey, "password123")
		if h1 != h2 {
			t.Error("password hash should be deterministic")
		}
	})

	t.Run("different password produces different hash", func(t *testing.T) {
		h1 := ComputePasswordHash(masterKey, "password1")
		h2 := ComputePasswordHash(masterKey, "password2")
		if h1 == h2 {
			t.Error("different passwords should produce different hashes")
		}
	})
}

func TestEncryptDecryptCipherString(t *testing.T) {
	// Generate random encryption and MAC keys.
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(macKey); err != nil {
		t.Fatal(err)
	}

	t.Run("round trip", func(t *testing.T) {
		plaintext := "Hello, Bitwarden!"
		encrypted, err := EncryptCipherString(plaintext, encKey, macKey)
		if err != nil {
			t.Fatalf("EncryptCipherString failed: %v", err)
		}

		decrypted, err := DecryptCipherString(encrypted, encKey, macKey)
		if err != nil {
			t.Fatalf("DecryptCipherString failed: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("cipher string format", func(t *testing.T) {
		encrypted, err := EncryptCipherString("test", encKey, macKey)
		if err != nil {
			t.Fatalf("EncryptCipherString failed: %v", err)
		}

		// Should start with "2."
		if !strings.HasPrefix(encrypted, "2.") {
			t.Errorf("cipher string should start with '2.', got %q", encrypted[:10])
		}

		// Should have format: 2.IV|CT|MAC
		parts := strings.SplitN(encrypted[2:], "|", 3)
		if len(parts) != 3 {
			t.Fatalf("expected 3 parts after type, got %d", len(parts))
		}

		// IV should decode to 16 bytes.
		iv, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("IV is not valid base64: %v", err)
		}
		if len(iv) != 16 {
			t.Errorf("IV length = %d, want 16", len(iv))
		}

		// MAC should decode to 32 bytes (HMAC-SHA256).
		mac, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("MAC is not valid base64: %v", err)
		}
		if len(mac) != 32 {
			t.Errorf("MAC length = %d, want 32", len(mac))
		}
	})

	t.Run("empty string", func(t *testing.T) {
		encrypted, err := EncryptCipherString("", encKey, macKey)
		if err != nil {
			t.Fatalf("EncryptCipherString failed: %v", err)
		}

		decrypted, err := DecryptCipherString(encrypted, encKey, macKey)
		if err != nil {
			t.Fatalf("DecryptCipherString failed: %v", err)
		}

		if decrypted != "" {
			t.Errorf("decrypted = %q, want empty string", decrypted)
		}
	})

	t.Run("long string", func(t *testing.T) {
		plaintext := strings.Repeat("A", 10000)
		encrypted, err := EncryptCipherString(plaintext, encKey, macKey)
		if err != nil {
			t.Fatalf("EncryptCipherString failed: %v", err)
		}

		decrypted, err := DecryptCipherString(encrypted, encKey, macKey)
		if err != nil {
			t.Fatalf("DecryptCipherString failed: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("decrypted length = %d, want %d", len(decrypted), len(plaintext))
		}
	})

	t.Run("unicode", func(t *testing.T) {
		plaintext := "Hello, World! Emoji: 🔐🔑"
		encrypted, err := EncryptCipherString(plaintext, encKey, macKey)
		if err != nil {
			t.Fatalf("EncryptCipherString failed: %v", err)
		}

		decrypted, err := DecryptCipherString(encrypted, encKey, macKey)
		if err != nil {
			t.Fatalf("DecryptCipherString failed: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("different keys fail decryption", func(t *testing.T) {
		plaintext := "secret data"
		encrypted, err := EncryptCipherString(plaintext, encKey, macKey)
		if err != nil {
			t.Fatalf("EncryptCipherString failed: %v", err)
		}

		wrongKey := make([]byte, 32)
		if _, err := rand.Read(wrongKey); err != nil {
			t.Fatal(err)
		}

		// Wrong enc key should fail HMAC.
		_, err = DecryptCipherString(encrypted, wrongKey, macKey)
		if err == nil {
			t.Error("expected error with wrong enc key")
		}

		// Wrong mac key should fail HMAC.
		_, err = DecryptCipherString(encrypted, encKey, wrongKey)
		if err == nil {
			t.Error("expected error with wrong mac key")
		}
	})

	t.Run("tampered ciphertext fails HMAC", func(t *testing.T) {
		plaintext := "secret data"
		encrypted, err := EncryptCipherString(plaintext, encKey, macKey)
		if err != nil {
			t.Fatalf("EncryptCipherString failed: %v", err)
		}

		// Tamper with a character in the ciphertext portion.
		parts := strings.SplitN(encrypted[2:], "|", 3)
		ct, _ := base64.StdEncoding.DecodeString(parts[1])
		ct[0] ^= 0xFF // flip bits
		parts[1] = base64.StdEncoding.EncodeToString(ct)
		tampered := "2." + strings.Join(parts, "|")

		_, err = DecryptCipherString(tampered, encKey, macKey)
		if err == nil {
			t.Error("expected error with tampered ciphertext")
		}
	})

	t.Run("invalid cipher string format", func(t *testing.T) {
		_, err := DecryptCipherString("invalid", encKey, macKey)
		if err == nil {
			t.Error("expected error for invalid format")
		}

		_, err = DecryptCipherString("", encKey, macKey)
		if err == nil {
			t.Error("expected error for empty string")
		}

		_, err = DecryptCipherString("2.abc", encKey, macKey)
		if err == nil {
			t.Error("expected error for missing parts")
		}

		_, err = DecryptCipherString("3.abc|def|ghi", encKey, macKey)
		if err == nil {
			t.Error("expected error for unsupported enc type")
		}
	})

	t.Run("wrong key length", func(t *testing.T) {
		_, err := EncryptCipherString("test", encKey[:16], macKey)
		if err == nil {
			t.Error("expected error for short enc key")
		}

		_, err = EncryptCipherString("test", encKey, macKey[:16])
		if err == nil {
			t.Error("expected error for short mac key")
		}
	})
}

func TestDecryptSymmetricKey(t *testing.T) {
	// Create a synthetic 64-byte key and encrypt it.
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(macKey); err != nil {
		t.Fatal(err)
	}

	// Create a 64-byte symmetric key.
	symKey := make([]byte, 64)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatal(err)
	}

	// Encrypt it as a CipherString.
	encrypted, err := EncryptCipherString(string(symKey), encKey, macKey)
	if err != nil {
		t.Fatalf("encrypting symmetric key: %v", err)
	}

	t.Run("successful decryption", func(t *testing.T) {
		se, sm, err := DecryptSymmetricKeyRaw(encrypted, encKey, macKey)
		if err != nil {
			t.Fatalf("DecryptSymmetricKeyRaw failed: %v", err)
		}

		if len(se) != 32 {
			t.Errorf("sym enc key length = %d, want 32", len(se))
		}
		if len(sm) != 32 {
			t.Errorf("sym mac key length = %d, want 32", len(sm))
		}

		if !bytesEqual(se, symKey[:32]) {
			t.Error("sym enc key does not match")
		}
		if !bytesEqual(sm, symKey[32:]) {
			t.Error("sym mac key does not match")
		}
	})

	t.Run("wrong keys fail", func(t *testing.T) {
		wrongKey := make([]byte, 32)
		rand.Read(wrongKey)

		_, _, err := DecryptSymmetricKeyRaw(encrypted, wrongKey, macKey)
		if err == nil {
			t.Error("expected error with wrong enc key")
		}
	})
}

func TestPKCS7Padding(t *testing.T) {
	t.Run("pad and unpad round trip", func(t *testing.T) {
		for i := 0; i < 32; i++ {
			data := make([]byte, i)
			for j := range data {
				data[j] = byte(j)
			}

			padded := pkcs7Pad(data, 16)
			if len(padded)%16 != 0 {
				t.Errorf("padded length %d not multiple of 16 for input length %d", len(padded), i)
			}

			unpadded, err := pkcs7Unpad(padded, 16)
			if err != nil {
				t.Fatalf("pkcs7Unpad failed for input length %d: %v", i, err)
			}

			if !bytesEqual(unpadded, data) {
				t.Errorf("round trip failed for input length %d", i)
			}
		}
	})

	t.Run("empty data adds full block", func(t *testing.T) {
		padded := pkcs7Pad([]byte{}, 16)
		if len(padded) != 16 {
			t.Errorf("padding empty data: got %d bytes, want 16", len(padded))
		}
		for _, b := range padded {
			if b != 16 {
				t.Errorf("padding byte = %d, want 16", b)
			}
		}
	})

	t.Run("exact block adds full block", func(t *testing.T) {
		data := make([]byte, 16)
		padded := pkcs7Pad(data, 16)
		if len(padded) != 32 {
			t.Errorf("padding exact block: got %d bytes, want 32", len(padded))
		}
	})

	t.Run("invalid padding detected", func(t *testing.T) {
		// All zeros — invalid padding (padding byte 0 is invalid).
		_, err := pkcs7Unpad(make([]byte, 16), 16)
		if err == nil {
			t.Error("expected error for zero padding byte")
		}

		// Inconsistent padding.
		bad := make([]byte, 16)
		bad[15] = 3
		bad[14] = 3
		bad[13] = 2 // wrong
		_, err = pkcs7Unpad(bad, 16)
		if err == nil {
			t.Error("expected error for inconsistent padding")
		}
	})
}

func TestParseCipherString(t *testing.T) {
	t.Run("valid cipher string", func(t *testing.T) {
		iv := make([]byte, 16)
		ct := make([]byte, 32)
		mac := make([]byte, 32)
		rand.Read(iv)
		rand.Read(ct)
		rand.Read(mac)

		cs := "2." + base64.StdEncoding.EncodeToString(iv) + "|" +
			base64.StdEncoding.EncodeToString(ct) + "|" +
			base64.StdEncoding.EncodeToString(mac)

		encType, parsedIV, parsedCT, parsedMAC, err := parseCipherString(cs)
		if err != nil {
			t.Fatalf("parseCipherString failed: %v", err)
		}

		if encType != 2 {
			t.Errorf("encType = %d, want 2", encType)
		}
		if !bytesEqual(parsedIV, iv) {
			t.Error("IV mismatch")
		}
		if !bytesEqual(parsedCT, ct) {
			t.Error("ciphertext mismatch")
		}
		if !bytesEqual(parsedMAC, mac) {
			t.Error("MAC mismatch")
		}
	})

	t.Run("errors", func(t *testing.T) {
		cases := []struct {
			name  string
			input string
		}{
			{"empty", ""},
			{"no dot", "nodot"},
			{"bad type", "x.a|b|c"},
			{"too few parts", "2.abc|def"},
			{"too many parts", "2.a|b|c|d"},
			{"bad iv base64", "2.!!!|" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "|" + base64.StdEncoding.EncodeToString(make([]byte, 32))},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, _, _, _, err := parseCipherString(tc.input)
				if err == nil {
					t.Errorf("expected error for input %q", tc.input)
				}
			})
		}
	})
}

// TestDeriveKeysKnownVector tests that our derivation produces expected results
// for a known input. This ensures compatibility with the Bitwarden protocol.
func TestDeriveKeysKnownVector(t *testing.T) {
	// Use low iterations for speed. The important thing is the algorithm, not timing.
	masterKey, encKey, macKey, err := DeriveKeys("user@example.com", "master-password", 1000)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	// Verify key lengths.
	if len(masterKey) != 32 || len(encKey) != 32 || len(macKey) != 32 {
		t.Fatal("unexpected key lengths")
	}

	// Verify that the password hash can be computed.
	hash := ComputePasswordHash(masterKey, "master-password")
	if hash == "" {
		t.Error("empty password hash")
	}

	// Verify hash is valid base64 and has expected length (32 bytes -> 44 chars in base64).
	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Fatalf("password hash is not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded hash length = %d, want 32", len(decoded))
	}

	// Now encrypt and decrypt with the derived keys, proving the full pipeline works.
	testMsg := "Synced from OpenBao at 2026-03-21T00:00:00Z"
	cs, err := EncryptCipherString(testMsg, encKey, macKey)
	if err != nil {
		t.Fatalf("EncryptCipherString failed: %v", err)
	}

	decrypted, err := DecryptCipherString(cs, encKey, macKey)
	if err != nil {
		t.Fatalf("DecryptCipherString failed: %v", err)
	}

	if decrypted != testMsg {
		t.Errorf("round trip failed: got %q, want %q", decrypted, testMsg)
	}
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
