//go:build integration

package vaultwarden

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// registerTestAccount creates a Vaultwarden account using the Bitwarden registration API.
// This implements the client-side key generation that the Bitwarden protocol requires:
//  1. Derive master key + enc/mac keys from email + password (PBKDF2 + HKDF)
//  2. Generate a random 64-byte symmetric key
//  3. Encrypt the symmetric key with derived keys → "Key" field
//  4. Generate RSA-2048 keypair
//  5. Encrypt the private key with the symmetric key → "encryptedPrivateKey"
//  6. POST to /identity/accounts/register
func registerTestAccount(t *testing.T, baseURL, email, password string) {
	t.Helper()

	kdfIterations := 600000

	// Step 1: Derive keys from master password
	masterKey, encKey, macKey, err := DeriveKeys(email, password, kdfIterations)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	// Step 2: Compute password hash for server
	passwordHash := ComputePasswordHash(masterKey, password)

	// Step 3: Generate random symmetric key (64 bytes: 32 enc + 32 mac)
	symKey := make([]byte, 64)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatalf("failed to generate symmetric key: %v", err)
	}

	// Step 4: Encrypt the symmetric key with derived keys
	encryptedSymKey, err := EncryptCipherString(string(symKey), encKey, macKey)
	if err != nil {
		t.Fatalf("failed to encrypt symmetric key: %v", err)
	}

	// Step 5: Generate RSA keypair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Public key as PKCS1 DER → base64
	pubKeyDER := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyDER)

	// Private key as PKCS8 DER → encrypt with symmetric key
	privKeyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	// Encrypt private key with the user's symmetric key
	userEncKey := symKey[:32]
	userMacKey := symKey[32:]
	encryptedPrivKey, err := EncryptCipherString(string(privKeyDER), userEncKey, userMacKey)
	if err != nil {
		t.Fatalf("failed to encrypt private key: %v", err)
	}

	// Step 6: Register
	regBody := map[string]interface{}{
		"email":              email,
		"name":               "Test User",
		"masterPasswordHash": passwordHash,
		"masterPasswordHint": "",
		"key":                encryptedSymKey,
		"kdf":                0,
		"kdfIterations":      kdfIterations,
		"keys": map[string]string{
			"publicKey":           pubKeyB64,
			"encryptedPrivateKey": encryptedPrivKey,
		},
	}

	bodyBytes, _ := json.Marshal(regBody)
	resp, err := http.Post(baseURL+"/identity/accounts/register", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("registration request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var errBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errBody)
		// 400 with "already registered" is OK
		if msg, ok := errBody["message"].(string); ok && resp.StatusCode == 400 {
			t.Logf("Registration response: %s (may already exist)", msg)
			return
		}
		t.Fatalf("registration failed with status %d: %v", resp.StatusCode, errBody)
	}

	t.Logf("Registered test account: %s", email)
}

// ensureTestAccount registers the test account if needed, then verifies login works.
func ensureTestAccount(t *testing.T, baseURL, email, password string) {
	t.Helper()

	// Try to register (idempotent — will log if already exists)
	registerTestAccount(t, baseURL, email, password)

	// Verify login works
	config := &VaultwardenConfig{
		URL:      baseURL,
		Email:    email,
		Password: password,
	}
	client, err := NewClient(config, nil)
	if err != nil {
		t.Fatalf("login failed after registration: %v", err)
	}

	// Quick smoke test
	_, err = client.ListCiphers()
	if err != nil {
		t.Fatalf("list ciphers failed after login: %v", err)
	}

	fmt.Printf("  Test account verified: %s\n", email)
}
