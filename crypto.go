// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Bitwarden-compatible client-side encryption.
//
// Bitwarden uses a layered encryption scheme:
//  1. Master key derived from email + master password via PBKDF2-SHA256
//  2. Stretched keys (enc + mac) via HKDF-Expand-SHA256
//  3. Password hash for server authentication
//  4. User symmetric key (encrypted in vault, decrypted client-side)
//  5. All cipher data encrypted with user/org symmetric keys
//
// CipherString format: "2.<base64(IV)>|<base64(ciphertext)>|<base64(HMAC)>"
//   - Type 2 = AES-256-CBC + HMAC-SHA256
//   - IV: 16 random bytes
//   - Ciphertext: PKCS7-padded AES-256-CBC
//   - MAC: HMAC-SHA256(IV || ciphertext)

package vaultwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// encTypeAesCbc256HmacSha256 is Bitwarden's AES-256-CBC + HMAC-SHA256 cipher type.
	encTypeAesCbc256HmacSha256 = 2

	// encTypeRsa2048OaepSha1 is Bitwarden's RSA-2048-OAEP-SHA1 cipher type.
	// Used for org keys encrypted with the user's RSA public key.
	encTypeRsa2048OaepSha1 = 4

	// keyLen is the AES-256 key length in bytes.
	keyLen = 32

	// ivLen is the AES CBC initialization vector length.
	ivLen = 16

	// defaultKDFIterations is the default PBKDF2 iteration count.
	defaultKDFIterations = 600000
)

// DeriveKeys derives the master encryption key, stretched encryption key, and
// stretched MAC key from the user's email and master password.
//
// The process follows Bitwarden's key derivation:
//  1. masterKey = PBKDF2-SHA256(password, lowercase(email), iterations, 32)
//  2. encKey = HKDF-Expand-SHA256(masterKey, "enc", 32)
//  3. macKey = HKDF-Expand-SHA256(masterKey, "mac", 32)
func DeriveKeys(email, masterPassword string, kdfIterations int) (masterKey, encKey, macKey []byte, err error) {
	if email == "" {
		return nil, nil, nil, errors.New("email is required")
	}
	if masterPassword == "" {
		return nil, nil, nil, errors.New("master password is required")
	}
	if kdfIterations <= 0 {
		kdfIterations = defaultKDFIterations
	}

	// Step 1: Derive master key via PBKDF2-SHA256.
	salt := []byte(strings.ToLower(email))
	masterKey = pbkdf2.Key([]byte(masterPassword), salt, kdfIterations, keyLen, sha256.New)

	// Step 2: Stretch master key via HKDF-Expand-SHA256.
	encKey, err = hkdfExpand(masterKey, "enc", keyLen)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("deriving enc key: %w", err)
	}

	macKey, err = hkdfExpand(masterKey, "mac", keyLen)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("deriving mac key: %w", err)
	}

	return masterKey, encKey, macKey, nil
}

// hkdfExpand performs HKDF-Expand-SHA256 with the given PRK and info string.
func hkdfExpand(prk []byte, info string, length int) ([]byte, error) {
	r := hkdf.Expand(sha256.New, prk, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return out, nil
}

// ComputePasswordHash computes the hash sent to the Bitwarden server during login.
// It is PBKDF2-SHA256(masterKey, masterPassword, 1, 32) then base64-encoded.
func ComputePasswordHash(masterKey []byte, masterPassword string) string {
	hash := pbkdf2.Key(masterKey, []byte(masterPassword), 1, keyLen, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}

// DecryptSymmetricKey decrypts the user's symmetric key returned during login.
//
// The login response "Key" field is a CipherString encrypted with the derived
// encKey/macKey. The decrypted result is 64 bytes: the first 32 bytes are the
// user's symmetric encryption key and the last 32 bytes are the MAC key.
func DecryptSymmetricKey(encryptedKey string, encKey, macKey []byte) (symEncKey, symMacKey []byte, err error) {
	decrypted, err := DecryptCipherString(encryptedKey, encKey, macKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting symmetric key: %w", err)
	}

	rawKey := []byte(decrypted)
	if len(rawKey) != 64 {
		return nil, nil, fmt.Errorf("expected 64-byte symmetric key, got %d bytes", len(rawKey))
	}

	return rawKey[:32], rawKey[32:], nil
}

// DecryptSymmetricKeyRaw decrypts the user's symmetric key and returns the raw
// 64-byte key. This is useful when the encrypted key contains raw bytes (not
// UTF-8 text).
func DecryptSymmetricKeyRaw(encryptedKey string, encKey, macKey []byte) (symEncKey, symMacKey []byte, err error) {
	rawKey, err := decryptCipherStringRaw(encryptedKey, encKey, macKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting symmetric key: %w", err)
	}

	if len(rawKey) != 64 {
		return nil, nil, fmt.Errorf("expected 64-byte symmetric key, got %d bytes", len(rawKey))
	}

	return rawKey[:32], rawKey[32:], nil
}

// EncryptCipherString encrypts plaintext into a Bitwarden CipherString.
//
// The format is: "2.<base64(IV)>|<base64(ciphertext)>|<base64(HMAC)>"
//   - AES-256-CBC encryption with PKCS7 padding
//   - HMAC-SHA256 over (IV || ciphertext) for authentication
func EncryptCipherString(plaintext string, encKey, macKey []byte) (string, error) {
	if len(encKey) != keyLen {
		return "", fmt.Errorf("enc key must be %d bytes, got %d", keyLen, len(encKey))
	}
	if len(macKey) != keyLen {
		return "", fmt.Errorf("mac key must be %d bytes, got %d", keyLen, len(macKey))
	}

	// Generate random IV.
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("generating IV: %w", err)
	}

	// PKCS7 pad the plaintext.
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	// Encrypt with AES-256-CBC.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("creating AES cipher: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Compute HMAC-SHA256 over IV || ciphertext.
	mac := computeMAC(iv, ciphertext, macKey)

	// Build the CipherString.
	cs := fmt.Sprintf("%d.%s|%s|%s",
		encTypeAesCbc256HmacSha256,
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ciphertext),
		base64.StdEncoding.EncodeToString(mac),
	)

	return cs, nil
}

// DecryptCipherString decrypts a Bitwarden CipherString and returns the plaintext.
func DecryptCipherString(cipherString string, encKey, macKey []byte) (string, error) {
	raw, err := decryptCipherStringRaw(cipherString, encKey, macKey)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// decryptCipherStringRaw decrypts a CipherString and returns raw bytes.
func decryptCipherStringRaw(cipherString string, encKey, macKey []byte) ([]byte, error) {
	if len(encKey) != keyLen {
		return nil, fmt.Errorf("enc key must be %d bytes, got %d", keyLen, len(encKey))
	}
	if len(macKey) != keyLen {
		return nil, fmt.Errorf("mac key must be %d bytes, got %d", keyLen, len(macKey))
	}

	// Parse the CipherString.
	encType, iv, ct, macBytes, err := parseCipherString(cipherString)
	if err != nil {
		return nil, err
	}

	if encType != encTypeAesCbc256HmacSha256 {
		return nil, fmt.Errorf("unsupported encryption type: %d", encType)
	}

	// Verify HMAC.
	expectedMAC := computeMAC(iv, ct, macKey)
	if !hmac.Equal(macBytes, expectedMAC) {
		return nil, errors.New("HMAC verification failed")
	}

	// Decrypt AES-256-CBC.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of block size %d", len(ct), aes.BlockSize)
	}

	plaintext := make([]byte, len(ct))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ct)

	// Remove PKCS7 padding.
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("removing padding: %w", err)
	}

	return plaintext, nil
}

// parseCipherString parses a Bitwarden CipherString into its components.
// Supports:
//   - Type 2 (AES-256-CBC + HMAC): "2.<base64(IV)>|<base64(CT)>|<base64(MAC)>"
//   - Type 4 (RSA-2048-OAEP-SHA1): "4.<base64(ciphertext)>"
func parseCipherString(cs string) (encType int, iv, ciphertext, mac []byte, err error) {
	if cs == "" {
		return 0, nil, nil, nil, errors.New("empty cipher string")
	}

	// Split on the first dot to get encType.
	dotIdx := strings.IndexByte(cs, '.')
	if dotIdx < 0 {
		return 0, nil, nil, nil, fmt.Errorf("invalid cipher string format: no dot separator")
	}

	typeStr := cs[:dotIdx]
	rest := cs[dotIdx+1:]

	// Parse encryption type.
	if _, err := fmt.Sscanf(typeStr, "%d", &encType); err != nil {
		return 0, nil, nil, nil, fmt.Errorf("parsing encryption type: %w", err)
	}

	// Split the rest on pipe characters.
	parts := strings.Split(rest, "|")

	switch encType {
	case encTypeRsa2048OaepSha1:
		// RSA: single base64 blob, no IV or MAC.
		if len(parts) != 1 {
			return 0, nil, nil, nil, fmt.Errorf("RSA cipher string: expected 1 part, got %d", len(parts))
		}
		ciphertext, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return 0, nil, nil, nil, fmt.Errorf("decoding RSA ciphertext: %w", err)
		}
		return encType, nil, ciphertext, nil, nil

	case encTypeAesCbc256HmacSha256:
		if len(parts) != 3 {
			return 0, nil, nil, nil, fmt.Errorf("AES cipher string: expected 3 parts, got %d", len(parts))
		}
		iv, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return 0, nil, nil, nil, fmt.Errorf("decoding IV: %w", err)
		}
		ciphertext, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return 0, nil, nil, nil, fmt.Errorf("decoding ciphertext: %w", err)
		}
		mac, err = base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return 0, nil, nil, nil, fmt.Errorf("decoding MAC: %w", err)
		}
		return encType, iv, ciphertext, mac, nil

	default:
		return 0, nil, nil, nil, fmt.Errorf("unsupported encryption type: %d", encType)
	}
}

// DecryptPrivateKey decrypts the user's RSA private key from the login response.
// The PrivateKey field is a type-2 CipherString encrypted with the user's symmetric key.
// Returns the parsed RSA private key.
func DecryptPrivateKey(encryptedKey string, encKey, macKey []byte) (*rsa.PrivateKey, error) {
	der, err := decryptCipherStringRaw(encryptedKey, encKey, macKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting private key: %w", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA private key, got %T", key)
	}

	return rsaKey, nil
}

// DecryptRSACipherString decrypts a type-4 (RSA-2048-OAEP-SHA1) CipherString.
func DecryptRSACipherString(cipherString string, privateKey *rsa.PrivateKey) ([]byte, error) {
	encType, _, ciphertext, _, err := parseCipherString(cipherString)
	if err != nil {
		return nil, err
	}

	if encType != encTypeRsa2048OaepSha1 {
		return nil, fmt.Errorf("expected RSA cipher type %d, got %d", encTypeRsa2048OaepSha1, encType)
	}

	plaintext, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decryption failed: %w", err)
	}

	return plaintext, nil
}

// computeMAC computes HMAC-SHA256 over IV || ciphertext.
func computeMAC(iv, ciphertext, macKey []byte) []byte {
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	return h.Sum(nil)
}

// pkcs7Pad applies PKCS7 padding to data for the given block size.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

// pkcs7Unpad removes PKCS7 padding from data.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data length %d is not a multiple of block size %d", len(data), blockSize)
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("invalid padding value: %d", padding)
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}

	return data[:len(data)-padding], nil
}
