//go:build integration

package vaultwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Integration test environment variables:
//
//	TEST_OPENBAO_ADDR       - OpenBao address (e.g. http://localhost:18200)
//	TEST_OPENBAO_TOKEN      - OpenBao root token
//	TEST_VAULTWARDEN_URL    - Vaultwarden URL (e.g. http://localhost:18080)
//	TEST_VAULTWARDEN_EMAIL  - Vaultwarden test account email
//	TEST_VAULTWARDEN_PASSWORD - Vaultwarden test account password

func getEnvOrSkip(t *testing.T, key string) string {
	t.Helper()
	val := os.Getenv(key)
	if val == "" {
		t.Skipf("skipping: %s not set", key)
	}
	return val
}

func setupIntegrationBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()

	config := &logical.BackendConfig{
		Logger: hclog.NewNullLogger(),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 24 * time.Hour,
			MaxLeaseTTLVal:     48 * time.Hour,
		},
		StorageView: &logical.InmemStorage{},
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestIntegrationOpenBaoConnectivity(t *testing.T) {
	addr := getEnvOrSkip(t, "TEST_OPENBAO_ADDR")
	token := getEnvOrSkip(t, "TEST_OPENBAO_TOKEN")

	// Verify OpenBao is reachable and unsealed
	req, _ := http.NewRequest("GET", addr+"/v1/sys/health", nil)
	req.Header.Set("X-Vault-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("cannot reach OpenBao at %s: %v", addr, err)
	}
	defer resp.Body.Close()

	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)

	if health["sealed"] == true {
		t.Fatal("OpenBao is sealed")
	}
	t.Logf("OpenBao healthy: initialized=%v sealed=%v", health["initialized"], health["sealed"])
}

func TestIntegrationVaultwardenConnectivity(t *testing.T) {
	url := getEnvOrSkip(t, "TEST_VAULTWARDEN_URL")

	resp, err := http.Get(url + "/alive")
	if err != nil {
		t.Fatalf("cannot reach Vaultwarden at %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Vaultwarden returned %d", resp.StatusCode)
	}
	t.Logf("Vaultwarden alive at %s", url)
}

func TestIntegrationReadSourceSecret(t *testing.T) {
	addr := getEnvOrSkip(t, "TEST_OPENBAO_ADDR")
	token := getEnvOrSkip(t, "TEST_OPENBAO_TOKEN")

	// Read the test secret we seeded
	req, _ := http.NewRequest("GET", addr+"/v1/secret/data/test-service", nil)
	req.Header.Set("X-Vault-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to read secret: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected response structure: %v", result)
	}
	innerData, ok := data["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data.data in response: %v", data)
	}

	if innerData["username"] != "testuser" {
		t.Errorf("expected username=testuser, got %v", innerData["username"])
	}
	if innerData["password"] != "testpass123" {
		t.Errorf("expected password=testpass123, got %v", innerData["password"])
	}
	t.Logf("Source secret verified: username=%s url=%s", innerData["username"], innerData["url"])
}

func TestIntegrationCryptoRoundTrip(t *testing.T) {
	// Test that our crypto implementation works end-to-end
	// with realistic parameters matching what Vaultwarden would use
	email := "test@example.com"
	password := "TestPassword123!"
	kdfIterations := 600000

	masterKey, encKey, macKey, err := DeriveKeys(email, password, kdfIterations)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}
	if len(masterKey) != 32 {
		t.Errorf("masterKey length = %d, want 32", len(masterKey))
	}

	// Compute password hash (what gets sent to server)
	hash := ComputePasswordHash(masterKey, password)
	if hash == "" {
		t.Fatal("ComputePasswordHash returned empty string")
	}
	t.Logf("Password hash (first 20 chars): %s...", hash[:20])

	// Encrypt and decrypt various field types
	testCases := []struct {
		name  string
		value string
	}{
		{"simple", "admin"},
		{"password", "s3cur3P@ssw0rd!"},
		{"url", "https://grafana.example.com/d/os-overview"},
		{"notes", "This is a multi-line\nnote with special chars: àéîõü © ™"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := EncryptCipherString(tc.value, encKey, macKey)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			decrypted, err := DecryptCipherString(encrypted, encKey, macKey)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if decrypted != tc.value {
				t.Errorf("round-trip failed: got %q, want %q", decrypted, tc.value)
			}
		})
	}
}

func TestIntegrationVaultwardenClient(t *testing.T) {
	url := getEnvOrSkip(t, "TEST_VAULTWARDEN_URL")
	email := getEnvOrSkip(t, "TEST_VAULTWARDEN_EMAIL")
	password := getEnvOrSkip(t, "TEST_VAULTWARDEN_PASSWORD")

	// Register the test account (idempotent)
	ensureTestAccount(t, url, email, password)

	config := &VaultwardenConfig{
		URL:      url,
		Email:    email,
		Password: password,
	}

	client, err := NewClient(config, hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	t.Run("create cipher", func(t *testing.T) {
		name, _ := client.Encrypt("Integration Test Service")
		username, _ := client.Encrypt("testuser")
		pass, _ := client.Encrypt("testpass123")
		uri, _ := client.Encrypt("https://test.example.com")
		notes, _ := client.Encrypt("Created by integration test at " + time.Now().Format(time.RFC3339))

		cipher := &CipherRequest{
			Type:  1, // Login
			Name:  name,
			Notes: notes,
			Login: &CipherLoginData{
				Username: username,
				Password: pass,
				URIs:     []CipherURI{{URI: uri}},
			},
		}

		resp, err := client.CreateCipher(cipher)
		if err != nil {
			t.Fatalf("CreateCipher failed: %v", err)
		}
		if resp.ID == "" {
			t.Fatal("cipher ID is empty")
		}
		t.Logf("Created cipher: %s", resp.ID)

		// Read it back
		t.Run("get cipher", func(t *testing.T) {
			got, err := client.GetCipher(resp.ID)
			if err != nil {
				t.Fatalf("GetCipher failed: %v", err)
			}
			if got.ID != resp.ID {
				t.Errorf("ID mismatch: got %s, want %s", got.ID, resp.ID)
			}
		})

		// Find by name
		t.Run("find by name", func(t *testing.T) {
			found, err := client.FindCipherByName("Integration Test Service", "")
			if err != nil {
				t.Fatalf("FindCipherByName failed: %v", err)
			}
			if found == nil {
				t.Fatal("cipher not found by name")
			}
			if found.ID != resp.ID {
				t.Errorf("found wrong cipher: got %s, want %s", found.ID, resp.ID)
			}
			t.Logf("Found cipher by name: %s", found.ID)
		})

		// Update
		t.Run("update cipher", func(t *testing.T) {
			newPass, _ := client.Encrypt("updatedpass789")
			cipher.Login.Password = newPass
			updated, err := client.UpdateCipher(resp.ID, cipher)
			if err != nil {
				t.Fatalf("UpdateCipher failed: %v", err)
			}
			if updated.ID != resp.ID {
				t.Errorf("updated cipher ID mismatch")
			}
			t.Logf("Updated cipher: %s", updated.ID)
		})

		// Delete
		t.Run("delete cipher", func(t *testing.T) {
			err := client.DeleteCipher(resp.ID)
			if err != nil {
				t.Fatalf("DeleteCipher failed: %v", err)
			}
			t.Logf("Deleted cipher: %s", resp.ID)

			// Verify it's gone
			_, err = client.GetCipher(resp.ID)
			if err == nil {
				t.Error("expected error getting deleted cipher")
			}
		})
	})
}

func TestIntegrationConfigAndRolesWorkflow(t *testing.T) {
	url := getEnvOrSkip(t, "TEST_VAULTWARDEN_URL")
	email := getEnvOrSkip(t, "TEST_VAULTWARDEN_EMAIL")
	password := getEnvOrSkip(t, "TEST_VAULTWARDEN_PASSWORD")

	b, storage := setupIntegrationBackend(t)
	ctx := context.Background()

	// Step 1: Write config
	t.Run("write config", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Data: map[string]interface{}{
				"url":      url,
				"email":    email,
				"password": password,
			},
			Storage: storage,
		})
		if err != nil {
			t.Fatalf("write config failed: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("write config error: %s", resp.Error())
		}
	})

	// Step 2: Read config (password should be hidden)
	t.Run("read config", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("read config failed: %v", err)
		}
		if resp.Data["url"] != url {
			t.Errorf("url = %v, want %v", resp.Data["url"], url)
		}
		if resp.Data["email"] != email {
			t.Errorf("email = %v, want %v", resp.Data["email"], email)
		}
		if _, ok := resp.Data["password"]; ok {
			t.Error("password should not be returned in read")
		}
	})

	// Step 3: Create a role
	t.Run("create role", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/test-service",
			Data: map[string]interface{}{
				"source_path": "secret/data/test-service",
				"cipher_name": "Test Service",
				"cipher_type": 1,
				"url_field":   "url",
				"user_field":  "username",
				"pass_field":  "password",
			},
			Storage: storage,
		})
		if err != nil {
			t.Fatalf("create role failed: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("create role error: %s", resp.Error())
		}
	})

	// Step 4: List roles
	t.Run("list roles", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ListOperation,
			Path:      "roles/",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("list roles failed: %v", err)
		}
		keys := resp.Data["keys"].([]string)
		if len(keys) != 1 || keys[0] != "test-service" {
			t.Errorf("expected [test-service], got %v", keys)
		}
	})

	// Step 5: Read role back
	t.Run("read role", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/test-service",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("read role failed: %v", err)
		}
		if resp.Data["cipher_name"] != "Test Service" {
			t.Errorf("cipher_name = %v, want Test Service", resp.Data["cipher_name"])
		}
		if resp.Data["source_path"] != "secret/data/test-service" {
			t.Errorf("source_path = %v", resp.Data["source_path"])
		}
	})

	t.Logf("Full config + roles workflow passed against live services")
}

func TestIntegrationFullSyncWorkflow(t *testing.T) {
	baoAddr := getEnvOrSkip(t, "TEST_OPENBAO_ADDR")
	baoToken := getEnvOrSkip(t, "TEST_OPENBAO_TOKEN")
	vwURL := getEnvOrSkip(t, "TEST_VAULTWARDEN_URL")
	vwEmail := getEnvOrSkip(t, "TEST_VAULTWARDEN_EMAIL")
	vwPassword := getEnvOrSkip(t, "TEST_VAULTWARDEN_PASSWORD")

	// Register the test account (idempotent)
	ensureTestAccount(t, vwURL, vwEmail, vwPassword)

	// Test the full pipeline: OpenBao secret → plugin sync → Vaultwarden cipher

	// Step 1: Verify source secret exists in OpenBao
	req, _ := http.NewRequest("GET", baoAddr+"/v1/secret/data/test-service", nil)
	req.Header.Set("X-Vault-Token", baoToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to read source secret: %v", err)
	}
	defer resp.Body.Close()

	var baoResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&baoResp)

	data := baoResp["data"].(map[string]interface{})["data"].(map[string]interface{})
	sourceUsername := data["username"].(string)
	sourcePassword := data["password"].(string)
	sourceURL := data["url"].(string)

	t.Logf("Source secret: username=%s url=%s", sourceUsername, sourceURL)

	// Step 2: Create Vaultwarden client
	client, err := NewClient(&VaultwardenConfig{
		URL:      vwURL,
		Email:    vwEmail,
		Password: vwPassword,
	}, hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("failed to create Vaultwarden client: %v", err)
	}

	// Step 3: Encrypt and create cipher (simulating what syncSingleRole does)
	encName, _ := client.Encrypt("Test Service (Synced)")
	encUser, _ := client.Encrypt(sourceUsername)
	encPass, _ := client.Encrypt(sourcePassword)
	encURI, _ := client.Encrypt(sourceURL)
	encNotes, _ := client.Encrypt(fmt.Sprintf("Synced from OpenBao at %s", time.Now().Format(time.RFC3339)))

	cipher := &CipherRequest{
		Type:  1,
		Name:  encName,
		Notes: encNotes,
		Login: &CipherLoginData{
			Username: encUser,
			Password: encPass,
			URIs:     []CipherURI{{URI: encURI}},
		},
	}

	created, err := client.CreateCipher(cipher)
	if err != nil {
		t.Fatalf("failed to create synced cipher: %v", err)
	}
	t.Logf("Created synced cipher: %s", created.ID)

	// Step 4: Verify cipher can be found by name
	found, err := client.FindCipherByName("Test Service (Synced)", "")
	if err != nil {
		t.Fatalf("FindCipherByName failed: %v", err)
	}
	if found == nil {
		t.Fatal("synced cipher not found by name")
	}
	if found.ID != created.ID {
		t.Errorf("found wrong cipher: got %s, want %s", found.ID, created.ID)
	}

	// Step 5: Update the cipher (simulating re-sync after rotation)
	newPass, _ := client.Encrypt("rotated-password-xyz")
	cipher.Login.Password = newPass
	updated, err := client.UpdateCipher(created.ID, cipher)
	if err != nil {
		t.Fatalf("failed to update synced cipher: %v", err)
	}
	t.Logf("Updated synced cipher: %s (revision: %s)", updated.ID, updated.RevisionDate)

	// Step 6: Clean up
	err = client.DeleteCipher(created.ID)
	if err != nil {
		t.Fatalf("failed to delete synced cipher: %v", err)
	}
	t.Logf("Cleaned up synced cipher: %s", created.ID)

	t.Log("Full sync workflow: OpenBao → encrypt → Vaultwarden → update → delete — PASSED")
}
